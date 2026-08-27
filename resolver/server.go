package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// policyReloadInterval is what bounds revocation latency. A tenant suspended by
// the billing system stops resolving within one tick, even on a DoT connection
// a phone has held open for hours.
const policyReloadInterval = time.Second

// blocklistReloadInterval controls how quickly an updated feed on disk reaches
// the serving path. Reloads swap an atomic pointer, so no query is delayed.
const blocklistReloadInterval = 15 * time.Minute

// usageFlushInterval batches counter writes. Short enough that a dashboard
// looks live, long enough that query rates do not become write rates.
const usageFlushInterval = 30 * time.Second

// Version is the build version, set by the command wrapper.
var Version = "dev"

// Server owns the resolver's long-lived state.
type Server struct {
	cfg     Config
	store   Store
	block   *Blocklist
	cache   *Cache
	m       *Metrics
	limiter *RateLimiter
	usage   *UsageCollector
	probes  *ProbeRecorder
	health  *Health
	log     *slog.Logger

	stop chan struct{}
}

// New assembles a Server from configuration, opening the policy store and
// loading blocklists. The caller owns shutdown via Close.
func New(cfg Config) (*Server, error) {
	log := NewLogger(cfg)
	slog.SetDefault(log)

	if dir := filepath.Dir(cfg.DBPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("policy store: %w", err)
	}

	if v, err := store.SchemaVersion(); err == nil {
		log.Info("policy store ready", "schema_version", v, "tenants", store.TenantCount())
	}

	block := NewBlocklist(cfg.BlocklistDir)
	n, err := block.Load()
	if err != nil {
		// An absent or unreadable blocklist directory must not stop the
		// resolver starting — filtering is a feature, resolution is the job.
		log.Warn("blocklist unavailable, continuing with an empty list", "err", err)
	} else {
		log.Info("blocklist loaded", "domains", n)
	}

	return &Server{
		cfg:     cfg,
		store:   store,
		block:   block,
		cache:   NewCache(),
		m:       &Metrics{},
		limiter: NewRateLimiter(cfg.RateLimitQPS, cfg.RateLimitBurst, cfg.MaxConnsPerTenant),
		usage:   NewUsageCollector(store),
		probes:  NewProbeRecorder(cfg.BaseDomain),
		health:  NewHealth(cfg, store, block, Version),
		log:     log,
		stop:    make(chan struct{}),
	}, nil
}

func (s *Server) Close() error { return s.store.Close() }

func (s *Server) Store() Store           { return s.store }
func (s *Server) Blocklist() *Blocklist  { return s.block }
func (s *Server) Metrics() *Metrics      { return s.m }
func (s *Server) Health() *Health        { return s.health }
func (s *Server) Probes() *ProbeRecorder { return s.probes }

// Run starts every configured listener and blocks until one fails or ctx is
// cancelled. Listeners with an empty address in the config are skipped.
func (s *Server) Run(ctx context.Context) error {
	s.store.WatchReload(policyReloadInterval, func(err error) {
		s.log.Error("policy reload failed", "err", err)
	})
	s.block.WatchReload(blocklistReloadInterval, func(n int, err error) {
		if err != nil {
			s.log.Error("blocklist reload failed", "err", err)
			return
		}
		s.log.Info("blocklist reloaded", "domains", n)
	})
	s.cache.StartSweeper(time.Minute)
	s.limiter.StartSweeper(time.Minute, s.stop)
	s.usage.StartFlusher(usageFlushInterval, s.stop, func(err error) {
		s.log.Error("usage flush failed", "err", err)
	})

	var tlsCfg *tls.Config
	if s.cfg.ListenDoT != "" || s.cfg.ListenDoH != "" {
		var err error
		tlsCfg, err = LoadTLS(s.cfg)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		// A fresh install has no certificate yet. Serve everything else and
		// say so plainly, rather than exiting and being restarted forever.
		if !HaveCert(s.cfg) {
			s.log.Warn("no certificate yet: DoT and DoH will refuse handshakes until one is installed",
				"cert_file", s.cfg.CertFile,
				"key_file", s.cfg.KeyFile,
				"next", "run privatedns-issue-cert, then nothing else -- it is picked up within a minute")
		}
	}

	res := NewResolver(s.cfg, s.store, s.block, s.cache, s.m).
		WithRateLimiter(s.limiter).
		WithUsage(s.usage).
		WithProbes(s.probes).
		WithLogger(s.log)

	listeners := NewListeners(s.cfg, res, s.store, tlsCfg).
		WithRateLimiter(s.limiter).
		WithLogger(s.log)

	admin := NewAdmin(s.cfg, s.store, s.block, s.cache, s.m).
		WithHealth(s.health).
		WithProbes(s.probes).
		WithRateLimiter(s.limiter).
		WithLogger(s.log)

	fail := make(chan error, 4)
	start := func(name string, fn func() error) {
		go func() {
			if err := fn(); err != nil {
				fail <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	if s.cfg.ListenDoT != "" {
		start("dot", func() error { return listeners.ServeDoT(s.cfg.ListenDoT) })
	}
	if s.cfg.ListenDoH != "" {
		start("doh", func() error { return listeners.ServeDoH(s.cfg.ListenDoH) })
	}
	if s.cfg.ListenPlain != "" {
		start("plain", func() error { return listeners.ServePlain(s.cfg.ListenPlain) })
	}
	if s.cfg.ListenAdmin != "" {
		start("admin", func() error { return admin.Serve(s.cfg.ListenAdmin) })
	}

	s.log.Info("privatedns-resolver ready",
		"version", Version,
		"tenants", s.store.TenantCount(),
		"base_domain", s.cfg.BaseDomain,
		"rate_limit_qps", s.cfg.RateLimitQPS,
		"strip_ecs", s.cfg.StripECS)

	var runErr error
	select {
	case err := <-fail:
		runErr = err
	case <-ctx.Done():
		s.log.Info("shutdown requested")
	}

	// Stop background workers first so the final usage flush runs, then close
	// listeners. Counters accumulated in the last interval are not lost.
	close(s.stop)
	listeners.Shutdown()
	admin.Shutdown()

	// Give the usage flusher a moment to write its final batch.
	select {
	case <-time.After(2 * time.Second):
	case <-context.Background().Done():
	}

	return runErr
}

// parseLeaf extracts the leaf certificate from a loaded key pair. tls does not
// populate Leaf when loading from disk, so health checks that need NotAfter
// have to parse it themselves.
func parseLeaf(crt tls.Certificate) (*x509.Certificate, error) {
	if crt.Leaf != nil {
		return crt.Leaf, nil
	}
	if len(crt.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	return x509.ParseCertificate(crt.Certificate[0])
}
