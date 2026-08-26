package backend

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/resolver"
)

// Version is the build version, set by the command wrapper.
var Version = "dev"

// Config is the backend's configuration.
type Config struct {
	Listen string `yaml:"listen" json:"listen"`

	// PolicyDB is the resolver's database. The backend shares it rather than
	// keeping its own: one source of truth about who has paid.
	PolicyDB string `yaml:"policy_db" json:"policy_db"`

	// BaseDomain is used to render tenant hostnames back to callers.
	BaseDomain string `yaml:"base_domain" json:"base_domain"`

	// CORSOrigins is the explicit allowlist for browser clients. Empty means
	// no cross-origin access at all, which is correct when the dashboard is
	// served from the same origin.
	CORSOrigins []string `yaml:"cors_origins" json:"cors_origins"`

	// TrustedProxies may set X-Forwarded-For. Leave empty unless the backend
	// genuinely sits behind a reverse proxy you control.
	TrustedProxies []string `yaml:"trusted_proxies" json:"trusted_proxies"`

	SessionTTL time.Duration `yaml:"session_ttl" json:"session_ttl"`

	// SecureCookies marks the session cookie Secure. Disable only for local
	// development over plain HTTP.
	SecureCookies bool `yaml:"secure_cookies" json:"secure_cookies"`

	RateLimitQPS   float64 `yaml:"rate_limit_qps" json:"rate_limit_qps"`
	RateLimitBurst int     `yaml:"rate_limit_burst" json:"rate_limit_burst"`

	// MaxLoginFailures and LoginWindow throttle credential stuffing.
	MaxLoginFailures int           `yaml:"max_login_failures" json:"max_login_failures"`
	LoginWindow      time.Duration `yaml:"login_window" json:"login_window"`

	LogLevel  string `yaml:"log_level" json:"log_level"`
	LogFormat string `yaml:"log_format" json:"log_format"`
}

func DefaultConfig() Config {
	return Config{
		Listen:           "127.0.0.1:8080",
		PolicyDB:         "/var/lib/private-dns/policy.db",
		BaseDomain:       "dns.example.com",
		SessionTTL:       12 * time.Hour,
		SecureCookies:    true,
		RateLimitQPS:     20,
		RateLimitBurst:   60,
		MaxLoginFailures: 10,
		LoginWindow:      15 * time.Minute,
		LogLevel:         "info",
		LogFormat:        "text",
	}
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	if c.PolicyDB == "" {
		return fmt.Errorf("policy_db is required")
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 12 * time.Hour
	}
	if c.MaxLoginFailures <= 0 {
		c.MaxLoginFailures = 10
	}
	if c.LoginWindow <= 0 {
		c.LoginWindow = 15 * time.Minute
	}
	return nil
}

// Server is the backend API.
type Server struct {
	cfg     Config
	store   *Store
	policy  resolver.Store
	limiter *resolver.RateLimiter
	log     *slog.Logger
	started time.Time
	srv     *http.Server
	stopCh  chan struct{}
}

// New opens the shared database and prepares the API.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}

	// Opening through the resolver applies every registered migration,
	// including this package's, and gives us the same policy view the
	// resolver serves from.
	policy, err := resolver.OpenStore(cfg.PolicyDB)
	if err != nil {
		return nil, fmt.Errorf("policy store: %w", err)
	}

	db, err := sql.Open("sqlite", cfg.PolicyDB+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		policy.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}

	SetTrustedProxies(cfg.TrustedProxies)

	return &Server{
		cfg:     cfg,
		store:   NewStore(db),
		policy:  policy,
		limiter: resolver.NewRateLimiter(cfg.RateLimitQPS, cfg.RateLimitBurst, 0),
		log:     log,
		started: time.Now(),
		stopCh:  make(chan struct{}),
	}, nil
}

func (s *Server) Store() *Store          { return s.store }
func (s *Server) Policy() resolver.Store { return s.policy }

func (s *Server) Close() error {
	if err := s.store.DB().Close(); err != nil {
		return err
	}
	return s.policy.Close()
}

// Handler builds the routing table with its middleware chain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public. No authentication, and deliberately minimal: version and
	// liveness reveal nothing an attacker can use.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)

	// Authentication.
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /v1/auth/me", s.handleMe)
	mux.HandleFunc("POST /v1/auth/password", s.handleChangePassword)

	// Users — administrators only.
	mux.HandleFunc("GET /v1/users", RequireAdmin(s.handleListUsers))
	mux.HandleFunc("POST /v1/users", RequireAdmin(s.handleCreateUser))
	mux.HandleFunc("POST /v1/users/{id}/status", RequireAdmin(s.handleSetUserStatus))

	// Customers.
	mux.HandleFunc("GET /v1/customers", Require(ScopeCustomersRead, s.handleListCustomers))
	mux.HandleFunc("POST /v1/customers", Require(ScopeCustomersWrite, s.handleCreateCustomer))
	mux.HandleFunc("GET /v1/customers/{id}", Require(ScopeCustomersRead, s.handleGetCustomer))
	mux.HandleFunc("PATCH /v1/customers/{id}", Require(ScopeCustomersWrite, s.handleUpdateCustomer))

	// Tenants.
	mux.HandleFunc("POST /v1/tenants", Require(ScopeTenantsWrite, s.handleCreateTenant))
	mux.HandleFunc("GET /v1/tenants/{id}", Require(ScopeTenantsRead, s.handleGetTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/revoke", Require(ScopeTenantsWrite, s.handleRevokeTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/extend", Require(ScopeTenantsWrite, s.handleExtendTenant))
	mux.HandleFunc("POST /v1/tenants/{id}/pause", Require(ScopePolicyWrite, s.handlePauseTenant))
	mux.HandleFunc("GET /v1/tenants/{id}/usage", Require(ScopeStatsRead, s.handleTenantUsage))

	// Source-IP binding — the "update my IP" control.
	mux.HandleFunc("POST /v1/tenants/{id}/ips", Require(ScopeTenantsBindIP, s.handleRegisterIP))
	mux.HandleFunc("DELETE /v1/tenants/{id}/ips/{ip}", Require(ScopeTenantsBindIP, s.handleReleaseIP))

	// Policy.
	mux.HandleFunc("POST /v1/tenants/{id}/allow", Require(ScopePolicyWrite, s.handleAddAllow))
	mux.HandleFunc("DELETE /v1/tenants/{id}/allow/{domain}", Require(ScopePolicyWrite, s.handleRemoveAllow))
	mux.HandleFunc("POST /v1/overrides", Require(ScopePolicyWrite, s.handleSetOverride))
	mux.HandleFunc("DELETE /v1/overrides/{domain}", Require(ScopePolicyWrite, s.handleRemoveOverride))

	// Plans.
	mux.HandleFunc("GET /v1/plans", Require(ScopeTenantsRead, s.handleListPlans))
	mux.HandleFunc("POST /v1/plans", RequireAdmin(s.handleCreatePlan))

	// API tokens.
	mux.HandleFunc("GET /v1/tokens", s.handleListTokens)
	mux.HandleFunc("POST /v1/tokens", s.handleCreateToken)
	mux.HandleFunc("DELETE /v1/tokens/{id}", s.handleRevokeToken)

	// System and audit — administrators only.
	mux.HandleFunc("GET /v1/system/status", Require(ScopeSystemRead, s.handleSystemStatus))
	mux.HandleFunc("GET /v1/audit", Require(ScopeAuditRead, s.handleListAudit))

	return Chain(mux,
		RequestID,
		Recover(s.log),
		SecurityHeaders,
		AccessLog(s.log),
		CORS(s.cfg.CORSOrigins),
		BodyLimit,
		s.Authenticate,
		s.RateLimit,
		CSRF,
	)
}

// Serve runs the API until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	s.startBackgroundWork()

	s.srv = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	go func() {
		<-ctx.Done()
		close(s.stopCh)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()

	s.log.Info("backend listening",
		"addr", s.cfg.Listen,
		"version", Version,
		"cors_origins", len(s.cfg.CORSOrigins),
		"secure_cookies", s.cfg.SecureCookies)

	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// startBackgroundWork keeps expired rows from accumulating. Sessions and login
// attempts are both unbounded otherwise.
func (s *Server) startBackgroundWork() {
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-t.C:
				if n, err := s.store.PurgeExpiredSessions(); err != nil {
					s.log.Error("session purge failed", "err", err)
				} else if n > 0 {
					s.log.Debug("purged expired sessions", "count", n)
				}
				if err := s.store.PurgeOldLoginAttempts(24 * time.Hour); err != nil {
					s.log.Error("login attempt purge failed", "err", err)
				}
			}
		}
	}()
}

// ---- response helpers ----

type errorBody struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError returns a message safe to show a caller.
//
// Internal detail — SQL text, stack traces, file paths — never reaches here.
// Those go to the log, where the request ID ties them back to this response.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, public string, err error) {
	if err != nil {
		s.log.Error("request failed",
			"path", r.URL.Path,
			"status", code,
			"request_id", RequestIDFrom(r.Context()),
			"err", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorBody{Error: public, RequestID: RequestIDFrom(r.Context())})
}

// decodeJSON reads a request body with unknown fields rejected, so a typo in a
// field name fails loudly instead of being silently ignored.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
