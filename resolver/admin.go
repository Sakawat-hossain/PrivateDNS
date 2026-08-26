package resolver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Admin is the provisioning and metrics surface. The billing system calls it
// when an order is paid; the dashboard calls it for "update my IP".
//
// It binds to localhost by default. Expose it only behind a reverse proxy on
// an internal network, never directly to the internet.
type Admin struct {
	cfg     Config
	store   Store
	block   *Blocklist
	cache   *Cache
	m       *Metrics
	start   time.Time
	health  *Health
	limiter *RateLimiter
	log     *slog.Logger
	srv     *http.Server
}

func NewAdmin(cfg Config, store Store, block *Blocklist, cache *Cache, m *Metrics) *Admin {
	return &Admin{
		cfg: cfg, store: store, block: block, cache: cache, m: m,
		start: time.Now(), log: slog.Default(),
	}
}

func (a *Admin) WithHealth(h *Health) *Admin { a.health = h; return a }

func (a *Admin) WithRateLimiter(r *RateLimiter) *Admin { a.limiter = r; return a }

func (a *Admin) WithLogger(l *slog.Logger) *Admin {
	if l != nil {
		a.log = l
	}
	return a
}

// Shutdown stops the admin listener, allowing in-flight requests to finish.
func (a *Admin) Shutdown() {
	if a.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = a.srv.Shutdown(ctx)
}

func (a *Admin) Serve(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /metrics", a.metrics)

	// Health endpoints are unauthenticated because an orchestrator probes them
	// before it has credentials. They expose component status and version only
	// -- never tenant data, configuration values, or secrets.
	mux.HandleFunc("GET /health", a.healthz)
	mux.HandleFunc("GET /healthz", a.healthz) // conventional alias
	mux.HandleFunc("GET /ready", a.readyz)
	mux.HandleFunc("GET /version", a.versionz)

	mux.HandleFunc("GET /v1/tenants/{id}/usage", a.auth(a.tenantUsage))

	mux.HandleFunc("POST /v1/tenants", a.auth(a.createTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/revoke", a.auth(a.revokeTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/extend", a.auth(a.extendTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/pause", a.auth(a.pauseTenant))
	mux.HandleFunc("GET /v1/tenants/{id}", a.auth(a.getTenant))

	mux.HandleFunc("POST /v1/ips", a.auth(a.registerIP))
	mux.HandleFunc("DELETE /v1/ips/{ip}", a.auth(a.releaseIP))

	mux.HandleFunc("POST /v1/overrides", a.auth(a.setOverride))
	mux.HandleFunc("POST /v1/allow", a.auth(a.addAllow))

	a.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	a.log.Info("listening", "transport", "admin", "addr", addr)
	if !isLoopback(addr) {
		// Not fatal -- an operator may deliberately bind an internal
		// interface -- but it must never happen by accident.
		a.log.Warn("admin API is not bound to loopback; ensure it is unreachable from the internet", "addr", addr)
	}

	if err := a.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// isLoopback reports whether the listen address is confined to the local host.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":8053" listens on every interface
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *Admin) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(a.cfg.AdminTokens) == 0 {
			http.Error(w, "admin API has no tokens configured", http.StatusServiceUnavailable)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		for _, want := range a.cfg.AdminTokens {
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
				next(w, r)
				return
			}
		}
		http.Error(w, "unauthorised", http.StatusUnauthorized)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ---- tenants ----

func (a *Admin) createTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RouteID   string `json:"route_id"`
		Label     string `json:"label"`
		Days      int    `json:"days"`
		Minutes   int    `json:"minutes"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if in.RouteID == "" {
		id, err := NewRouteID()
		if err != nil {
			http.Error(w, "id generation failed", http.StatusInternalServerError)
			return
		}
		in.RouteID = id
	}

	expires := in.ExpiresAt
	if expires == 0 {
		d := time.Duration(in.Days)*24*time.Hour + time.Duration(in.Minutes)*time.Minute
		if d == 0 {
			http.Error(w, "one of days, minutes or expires_at is required", http.StatusBadRequest)
			return
		}
		expires = time.Now().Add(d).Unix()
	}

	if err := a.store.CreateTenant(in.RouteID, in.Label, expires); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.Reload()

	writeJSON(w, http.StatusCreated, map[string]any{
		"route_id":   in.RouteID,
		"hostname":   in.RouteID + "." + a.cfg.BaseDomain,
		"expires_at": expires,
	})
}

func (a *Admin) getTenant(w http.ResponseWriter, r *http.Request) {
	t := a.store.Tenant(r.PathValue("id"))
	if t == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	now := time.Now().Unix()
	writeJSON(w, http.StatusOK, map[string]any{
		"route_id":   t.RouteID,
		"label":      t.Label,
		"status":     t.Status,
		"expires_at": t.ExpiresAt,
		"active":     t.Active(now),
		"filtering":  t.Filtering(now),
		"hostname":   t.RouteID + "." + a.cfg.BaseDomain,
	})
}

func (a *Admin) revokeTenant(w http.ResponseWriter, r *http.Request) {
	if err := a.store.SetStatus(r.PathValue("id"), "suspended"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.Reload()
	writeJSON(w, http.StatusOK, map[string]string{"status": "suspended"})
}

func (a *Admin) extendTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Days      int   `json:"days"`
		ExpiresAt int64 `json:"expires_at"`
	}
	json.NewDecoder(r.Body).Decode(&in)

	id := r.PathValue("id")
	expires := in.ExpiresAt
	if expires == 0 {
		base := time.Now()
		if t := a.store.Tenant(id); t != nil && t.ExpiresAt > base.Unix() {
			base = time.Unix(t.ExpiresAt, 0)
		}
		expires = base.AddDate(0, 0, in.Days).Unix()
	}

	if err := a.store.Extend(id, expires); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.SetStatus(id, "active")
	_ = a.store.Reload()
	writeJSON(w, http.StatusOK, map[string]any{"expires_at": expires})
}

// pauseTenant temporarily stops filtering. This is the self-service escape
// hatch for a false positive, and it exists so a blocked bank login is not a
// support ticket.
func (a *Admin) pauseTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Minutes int `json:"minutes"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	if in.Minutes <= 0 {
		in.Minutes = 5
	}

	until := time.Now().Add(time.Duration(in.Minutes) * time.Minute).Unix()
	if err := a.store.PauseFiltering(r.PathValue("id"), until); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.Reload()
	writeJSON(w, http.StatusOK, map[string]any{"paused_until": until})
}

// ---- source-IP binding ----

func (a *Admin) registerIP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RouteID string `json:"route_id"`
		IP      string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if net.ParseIP(in.IP) == nil {
		http.Error(w, "ip must be a valid address", http.StatusBadRequest)
		return
	}
	if a.store.Tenant(in.RouteID) == nil {
		http.Error(w, "unknown route_id", http.StatusNotFound)
		return
	}
	if err := a.store.RegisterIP(in.RouteID, in.IP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.Reload()
	writeJSON(w, http.StatusOK, map[string]string{"ip": in.IP, "route_id": in.RouteID})
}

func (a *Admin) releaseIP(w http.ResponseWriter, r *http.Request) {
	if err := a.store.ReleaseIP(r.PathValue("ip")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.Reload()
	w.WriteHeader(http.StatusNoContent)
}

// ---- policy ----

func (a *Admin) setOverride(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RouteID string `json:"route_id"`
		Domain  string `json:"domain"`
		Answer  string `json:"answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if in.RouteID == "" {
		in.RouteID = "*"
	}
	if err := a.store.SetOverride(in.RouteID, in.Domain, in.Answer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = a.store.Reload()
	writeJSON(w, http.StatusOK, in)
}

func (a *Admin) addAllow(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RouteID string `json:"route_id"`
		Domain  string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if in.RouteID == "" {
		in.RouteID = "*"
	}
	if err := a.store.AddAllow(in.RouteID, in.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.Reload()
	writeJSON(w, http.StatusOK, in)
}

// ---- metrics ----

func (a *Admin) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	c := func(name, help string, v uint64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	g := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
	}

	c("privatedns_queries_total", "Queries received.", a.m.Queries.Load())
	c("privatedns_blocked_total", "Queries answered from the blocklist.", a.m.Blocked.Load())
	c("privatedns_overridden_total", "Queries answered from the override table.", a.m.Overridden.Load())
	c("privatedns_allowlisted_total", "Queries matched by an allowlist rule.", a.m.Allowed.Load())
	c("privatedns_refused_total", "Queries refused for lack of a valid tenant.", a.m.Refused.Load())
	c("privatedns_throttled_total", "Queries rejected by the per-tenant rate limit.", a.m.Throttled.Load())
	c("privatedns_malformed_total", "Messages rejected as malformed.", a.m.Malformed.Load())
	c("privatedns_cache_hits_total", "Queries served from cache.", a.m.CacheHits.Load())
	c("privatedns_upstream_total", "Queries forwarded upstream.", a.m.Upstream.Load())
	c("privatedns_upstream_errors_total", "Upstream failures.", a.m.UpstreamNG.Load())

	g("privatedns_tenants", "Tenants loaded in the policy snapshot.", int64(a.store.TenantCount()))
	g("privatedns_blocklist_size", "Domains in the compiled blocklist.", int64(a.block.Size()))
	g("privatedns_cache_entries", "Entries currently cached.", int64(a.cache.Len()))
	g("privatedns_ratelimit_tracked", "Tenants with an active rate-limit bucket.", int64(a.limiter.Tracked()))
	g("privatedns_uptime_seconds", "Process uptime.", int64(time.Since(a.start).Seconds()))

	if v, err := a.store.SchemaVersion(); err == nil {
		g("privatedns_schema_version", "Applied database schema version.", int64(v))
	}
	if a.health != nil {
		ready := int64(0)
		if a.health.Ready(r.Context()).OK {
			ready = 1
		}
		g("privatedns_ready", "1 when every dependency check passes.", ready)
	}
}

// ---- health ----

// healthz is liveness: is the process running. Deliberately trivial, because a
// liveness probe that fails on a dependency outage causes an orchestrator to
// kill a process that would have recovered by itself.
func (a *Admin) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok\n"))
}

// readyz reports whether the resolver can actually serve traffic, by probing
// the policy store, schema version, certificate expiry and a real upstream
// resolution. It returns 503 when any of those fail, so a load balancer stops
// sending traffic to an instance that would answer SERVFAIL.
func (a *Admin) readyz(w http.ResponseWriter, r *http.Request) {
	if a.health == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checks": []any{}})
		return
	}

	report := a.health.Ready(r.Context())
	code := http.StatusOK
	if !report.OK {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, report)
}

func (a *Admin) versionz(w http.ResponseWriter, r *http.Request) {
	schema, _ := a.store.SchemaVersion()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        Version,
		"schema_version": schema,
		"uptime":         time.Since(a.start).Truncate(time.Second).String(),
	})
}

// tenantUsage returns a tenant's aggregate counters. Query names are never
// recorded, so there is no per-domain history to return here.
func (a *Admin) tenantUsage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if a.store.Tenant(id) == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	u, ok := a.store.Usage(id)
	if !ok {
		// A tenant that has never resolved anything has no usage row yet.
		u = Usage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"route_id":   id,
		"queries":    u.Queries,
		"blocked":    u.Blocked,
		"overridden": u.Overridden,
		"throttled":  u.Throttled,
		"last_seen":  u.LastSeen,
	})
}

// NewRouteID returns a short, unambiguous tenant identifier. The alphabet
// omits look-alike characters because customers read these off a screen and
// type them into a phone.
func NewRouteID() (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	const length = 10

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf), nil
}
