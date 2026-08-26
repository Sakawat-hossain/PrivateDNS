package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// certExpiryWarning is how close to expiry a certificate may get before
// readiness starts failing. Renewal runs on a schedule; if it has not
// succeeded with this much runway left, something is wrong and it is better to
// fail a health check than to serve until the certificate lapses.
const certExpiryWarning = 72 * time.Hour

// Check is one component's health.
type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// HealthReport is the aggregate result returned by /ready.
type HealthReport struct {
	OK      bool    `json:"ok"`
	Version string  `json:"version"`
	Uptime  string  `json:"uptime"`
	Checks  []Check `json:"checks"`
}

// Health probes the resolver's real dependencies.
//
// The point of these checks is that they exercise the actual serving path. A
// handler that returns 200 because the process is running tells an operator
// nothing: the process can be up while the upstream is unreachable, the
// database is locked, or the certificate expired last night.
type Health struct {
	cfg     Config
	store   Store
	block   *Blocklist
	started time.Time
	version string

	// lastUpstreamOK caches the upstream probe so a health endpoint being
	// scraped every few seconds does not itself generate upstream traffic.
	lastUpstreamOK   atomic.Bool
	lastUpstreamAt   atomic.Int64
	lastUpstreamNote atomic.Value // string
}

func NewHealth(cfg Config, store Store, block *Blocklist, version string) *Health {
	h := &Health{
		cfg:     cfg,
		store:   store,
		block:   block,
		started: time.Now(),
		version: version,
	}
	h.lastUpstreamNote.Store("")
	return h
}

func (h *Health) Version() string { return h.version }

func (h *Health) Uptime() time.Duration { return time.Since(h.started) }

// Live reports process liveness. It is deliberately trivial: a liveness probe
// that fails on a dependency outage causes an orchestrator to kill a process
// that would have recovered on its own.
func (h *Health) Live() bool { return true }

// Ready runs every dependency check and reports whether the resolver can
// actually serve traffic.
func (h *Health) Ready(ctx context.Context) HealthReport {
	report := HealthReport{
		OK:      true,
		Version: h.version,
		Uptime:  h.Uptime().Truncate(time.Second).String(),
	}

	for _, c := range []func(context.Context) Check{
		h.checkStore,
		h.checkSchema,
		h.checkBlocklist,
		h.checkCertificate,
		h.checkUpstream,
	} {
		chk := c(ctx)
		if !chk.OK {
			report.OK = false
		}
		report.Checks = append(report.Checks, chk)
	}

	return report
}

func (h *Health) checkStore(ctx context.Context) Check {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := h.store.Ping(ctx); err != nil {
		return Check{Name: "policy_store", OK: false, Detail: err.Error()}
	}
	return Check{
		Name:    "policy_store",
		OK:      true,
		Detail:  fmt.Sprintf("%d tenants loaded", h.store.TenantCount()),
		Latency: time.Since(start).Truncate(time.Millisecond).String(),
	}
}

func (h *Health) checkSchema(context.Context) Check {
	got, err := h.store.SchemaVersion()
	if err != nil {
		return Check{Name: "schema", OK: false, Detail: err.Error()}
	}
	want := SchemaVersion()
	if got != want {
		// A binary running against a database it has not migrated will fail in
		// confusing ways later; surface it here instead.
		return Check{
			Name:   "schema",
			OK:     false,
			Detail: fmt.Sprintf("database at version %d, binary expects %d", got, want),
		}
	}
	return Check{Name: "schema", OK: true, Detail: fmt.Sprintf("version %d", got)}
}

func (h *Health) checkBlocklist(context.Context) Check {
	n := h.block.Size()
	// An empty blocklist is a legitimate configuration (filtering off), so
	// this reports rather than fails.
	return Check{Name: "blocklist", OK: true, Detail: fmt.Sprintf("%d domains", n)}
}

func (h *Health) checkCertificate(context.Context) Check {
	if h.cfg.ListenDoT == "" && h.cfg.ListenDoH == "" {
		return Check{Name: "certificate", OK: true, Detail: "not required"}
	}

	crt, err := tls.LoadX509KeyPair(h.cfg.CertFile, h.cfg.KeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return Check{Name: "certificate", OK: false, Detail: "certificate file missing"}
		}
		return Check{Name: "certificate", OK: false, Detail: err.Error()}
	}
	if len(crt.Certificate) == 0 {
		return Check{Name: "certificate", OK: false, Detail: "certificate contains no entries"}
	}

	leaf := crt.Leaf
	if leaf == nil {
		parsed, err := parseLeaf(crt)
		if err != nil {
			return Check{Name: "certificate", OK: false, Detail: err.Error()}
		}
		leaf = parsed
	}

	remaining := time.Until(leaf.NotAfter)
	switch {
	case remaining <= 0:
		return Check{Name: "certificate", OK: false, Detail: "expired " + leaf.NotAfter.Format(time.RFC3339)}
	case remaining < certExpiryWarning:
		return Check{
			Name:   "certificate",
			OK:     false,
			Detail: fmt.Sprintf("expires in %s — renewal has not run", remaining.Truncate(time.Hour)),
		}
	}
	return Check{
		Name:   "certificate",
		OK:     true,
		Detail: fmt.Sprintf("valid for %s", remaining.Truncate(time.Hour)),
	}
}

// checkUpstream resolves a well-known name through the configured upstreams.
// The result is cached briefly so frequent scraping does not amplify into
// upstream load.
func (h *Health) checkUpstream(ctx context.Context) Check {
	const cacheFor = 15 * time.Second

	if last := h.lastUpstreamAt.Load(); last > 0 && time.Since(time.Unix(last, 0)) < cacheFor {
		note, _ := h.lastUpstreamNote.Load().(string)
		return Check{Name: "upstream", OK: h.lastUpstreamOK.Load(), Detail: note}
	}

	if len(h.cfg.Upstreams) == 0 {
		return Check{Name: "upstream", OK: false, Detail: "no upstreams configured"}
	}

	msg := new(dns.Msg)
	msg.SetQuestion("dns.google.", dns.TypeA)

	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	var lastErr string
	for _, addr := range h.cfg.Upstreams {
		start := time.Now()
		reply, _, err := client.ExchangeContext(ctx, msg, addr)
		if err != nil {
			lastErr = fmt.Sprintf("%s: %v", addr, err)
			continue
		}
		if reply == nil || reply.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Sprintf("%s: rcode %s", addr, dns.RcodeToString[reply.Rcode])
			continue
		}

		note := fmt.Sprintf("%s responded in %s", addr, time.Since(start).Truncate(time.Millisecond))
		h.lastUpstreamOK.Store(true)
		h.lastUpstreamNote.Store(note)
		h.lastUpstreamAt.Store(time.Now().Unix())
		return Check{Name: "upstream", OK: true, Detail: note}
	}

	note := "all upstreams failed: " + lastErr
	h.lastUpstreamOK.Store(false)
	h.lastUpstreamNote.Store(note)
	h.lastUpstreamAt.Store(time.Now().Unix())
	return Check{Name: "upstream", OK: false, Detail: note}
}
