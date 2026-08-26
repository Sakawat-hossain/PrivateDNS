package resolver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
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
	cfg   Config
	store *Store
	block *Blocklist
	cache *Cache
	m     *Metrics
	start time.Time
}

func NewAdmin(cfg Config, store *Store, block *Blocklist, cache *Cache, m *Metrics) *Admin {
	return &Admin{cfg: cfg, store: store, block: block, cache: cache, m: m, start: time.Now()}
}

func (a *Admin) Serve(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /metrics", a.metrics)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("POST /v1/tenants", a.auth(a.createTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/revoke", a.auth(a.revokeTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/extend", a.auth(a.extendTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/pause", a.auth(a.pauseTenant))
	mux.HandleFunc("GET /v1/tenants/{id}", a.auth(a.getTenant))

	mux.HandleFunc("POST /v1/ips", a.auth(a.registerIP))
	mux.HandleFunc("DELETE /v1/ips/{ip}", a.auth(a.releaseIP))

	mux.HandleFunc("POST /v1/overrides", a.auth(a.setOverride))
	mux.HandleFunc("POST /v1/allow", a.auth(a.addAllow))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("admin API listening on %s", addr)
	return srv.ListenAndServe()
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
	c("privatedns_cache_hits_total", "Queries served from cache.", a.m.CacheHits.Load())
	c("privatedns_upstream_total", "Queries forwarded upstream.", a.m.Upstream.Load())
	c("privatedns_upstream_errors_total", "Upstream failures.", a.m.UpstreamNG.Load())

	g("privatedns_tenants", "Tenants loaded in the policy snapshot.", int64(a.store.TenantCount()))
	g("privatedns_blocklist_size", "Domains in the compiled blocklist.", int64(a.block.Size()))
	g("privatedns_cache_entries", "Entries currently cached.", int64(a.cache.Len()))
	g("privatedns_uptime_seconds", "Process uptime.", int64(time.Since(a.start).Seconds()))
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
