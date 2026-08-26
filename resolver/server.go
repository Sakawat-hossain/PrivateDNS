package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
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

// Server owns the resolver's long-lived state.
type Server struct {
	cfg   Config
	store *Store
	block *Blocklist
	cache *Cache
	m     *Metrics
}

// New assembles a Server from configuration, opening the policy store and
// loading blocklists. The caller owns shutdown via Close.
func New(cfg Config) (*Server, error) {
	if dir := filepath.Dir(cfg.DBPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("policy store: %w", err)
	}

	block := NewBlocklist(cfg.BlocklistDir)
	n, err := block.Load()
	if err != nil {
		// An absent or unreadable blocklist directory must not stop the
		// resolver starting — filtering is a feature, resolution is the job.
		log.Printf("blocklist load: %v (continuing with an empty list)", err)
	} else {
		log.Printf("blocklist loaded: %d domains", n)
	}

	cache := NewCache()

	return &Server{cfg: cfg, store: store, block: block, cache: cache, m: &Metrics{}}, nil
}

func (s *Server) Close() error { return s.store.Close() }

func (s *Server) Store() *Store         { return s.store }
func (s *Server) Blocklist() *Blocklist { return s.block }
func (s *Server) Metrics() *Metrics     { return s.m }

// Run starts every configured listener and blocks until one fails or ctx is
// cancelled. Listeners with an empty address in the config are skipped.
func (s *Server) Run(ctx context.Context) error {
	s.store.WatchReload(policyReloadInterval, func(err error) {
		log.Printf("policy reload failed: %v", err)
	})
	s.block.WatchReload(blocklistReloadInterval, func(n int, err error) {
		if err != nil {
			log.Printf("blocklist reload failed: %v", err)
			return
		}
		log.Printf("blocklist reloaded: %d domains", n)
	})
	s.cache.StartSweeper(time.Minute)

	var tlsCfg *tls.Config
	if s.cfg.ListenDoT != "" || s.cfg.ListenDoH != "" {
		var err error
		tlsCfg, err = LoadTLS(s.cfg)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}

	res := NewResolver(s.cfg, s.store, s.block, s.cache, s.m)
	listeners := NewListeners(s.cfg, res, s.store, tlsCfg)
	admin := NewAdmin(s.cfg, s.store, s.block, s.cache, s.m)

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

	log.Printf("privatedns-resolver ready — %d tenants, base domain %s",
		s.store.TenantCount(), s.cfg.BaseDomain)

	select {
	case err := <-fail:
		return err
	case <-ctx.Done():
		return nil
	}
}
