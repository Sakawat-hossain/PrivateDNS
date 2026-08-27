package admin

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
	"github.com/Sakawat-hossain/PrivateDNS/resolver"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Version is the build version, set by the command wrapper.
var Version = "dev"

const (
	sessionCookie = "pdns_admin"
	csrfField     = "csrf_token"
)

// Config is the dashboard's configuration.
type Config struct {
	// Listen defaults to loopback. This surface can create tenants, read the
	// audit log and change routing — it is an operator tool, not a public one.
	Listen string `yaml:"listen"`

	PolicyDB   string `yaml:"policy_db"`
	BaseDomain string `yaml:"base_domain"`
	BrandName  string `yaml:"brand_name"`

	// ResolverAdmin is the resolver's admin API, used for live status: cache
	// size, upstream health, blocklist size and uptime.
	ResolverAdmin string `yaml:"resolver_admin"`
	ResolverToken string `yaml:"resolver_token"`

	SessionTTL    time.Duration `yaml:"session_ttl"`
	SecureCookies bool          `yaml:"secure_cookies"`

	TrustedProxies []string `yaml:"trusted_proxies"`

	RateLimitQPS   float64 `yaml:"rate_limit_qps"`
	RateLimitBurst int     `yaml:"rate_limit_burst"`

	MaxLoginFailures int           `yaml:"max_login_failures"`
	LoginWindow      time.Duration `yaml:"login_window"`

	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`
}

func DefaultConfig() Config {
	return Config{
		Listen:        "127.0.0.1:8082",
		PolicyDB:      "/var/lib/private-dns/policy.db",
		BaseDomain:    "dns.example.com",
		BrandName:     "PrivateDNS",
		ResolverAdmin: "http://127.0.0.1:8053",
		// Much shorter than the customer portal's. An operator session can
		// create and revoke tenants; leaving one valid for a month on a shared
		// machine is a different risk entirely.
		SessionTTL:       8 * time.Hour,
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
	if c.BaseDomain == "" {
		return fmt.Errorf("base_domain is required")
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 8 * time.Hour
	}
	if c.MaxLoginFailures <= 0 {
		c.MaxLoginFailures = 10
	}
	if c.LoginWindow <= 0 {
		c.LoginWindow = 15 * time.Minute
	}
	if c.BrandName == "" {
		c.BrandName = "PrivateDNS"
	}
	return nil
}

// Server is the operator dashboard.
type Server struct {
	cfg     Config
	store   *backend.Store
	policy  resolver.Store
	limiter *resolver.RateLimiter
	tmpl    *template.Template
	log     *slog.Logger
	started time.Time
	srv     *http.Server
	stopCh  chan struct{}

	// Holds a freshly created API token across one redirect, so the secret
	// never travels in a URL.
	tokens *tokenStash
}

func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}

	policy, err := resolver.OpenStore(cfg.PolicyDB)
	if err != nil {
		return nil, fmt.Errorf("policy store: %w", err)
	}

	db, err := sql.Open("sqlite",
		cfg.PolicyDB+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		policy.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}

	tmpl, err := parseTemplates()
	if err != nil {
		policy.Close()
		db.Close()
		return nil, fmt.Errorf("templates: %w", err)
	}

	backend.SetTrustedProxies(cfg.TrustedProxies)

	return &Server{
		cfg:     cfg,
		store:   backend.NewStore(db),
		policy:  policy,
		limiter: resolver.NewRateLimiter(cfg.RateLimitQPS, cfg.RateLimitBurst, 0),
		tmpl:    tmpl,
		log:     log,
		started: time.Now(),
		stopCh:  make(chan struct{}),
		tokens:  newTokenStash(),
	}, nil
}

func (s *Server) Store() *backend.Store  { return s.store }
func (s *Server) Policy() resolver.Store { return s.policy }

func (s *Server) Close() error {
	if err := s.store.DB().Close(); err != nil {
		return err
	}
	return s.policy.Close()
}

func parseTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"ts":      formatTime,
		"since":   humanSince,
		"until":   humanUntil,
		"comma":   comma,
		"pct":     percent,
		"hasPfx":  strings.HasPrefix,
		"joinStr": strings.Join,
		"int64":   func(n int) int64 { return int64(n) },
	}
	return template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
}

// Handler builds the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fsSub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Every route below requires an operator session. Resellers reach a subset
	// enforced inside each handler, not by the route table, because the
	// filtering is per-row rather than per-page.
	mux.HandleFunc("GET /", s.operator(s.handleOverview))

	mux.HandleFunc("GET /customers", s.operator(s.handleCustomerList))
	mux.HandleFunc("POST /customers", s.operator(s.handleCustomerCreate))
	mux.HandleFunc("GET /customers/{id}", s.operator(s.handleCustomerDetail))
	mux.HandleFunc("POST /customers/{id}", s.operator(s.handleCustomerUpdate))
	mux.HandleFunc("POST /customers/{id}/tenants", s.operator(s.handleTenantIssue))

	mux.HandleFunc("GET /tenants/{id}", s.operator(s.handleTenantDetail))
	mux.HandleFunc("POST /tenants/{id}/revoke", s.operator(s.handleTenantRevoke))
	mux.HandleFunc("POST /tenants/{id}/extend", s.operator(s.handleTenantExtend))
	mux.HandleFunc("POST /tenants/{id}/allow", s.operator(s.handleAllowAdd))
	mux.HandleFunc("POST /tenants/{id}/allow/remove", s.operator(s.handleAllowRemove))

	mux.HandleFunc("GET /policy", s.admin(s.handlePolicyPage))
	mux.HandleFunc("POST /policy/overrides", s.admin(s.handleOverrideSet))
	mux.HandleFunc("POST /policy/overrides/remove", s.admin(s.handleOverrideRemove))

	mux.HandleFunc("GET /triage", s.operator(s.handleTriage))
	mux.HandleFunc("POST /triage/allow", s.operator(s.handleTriageAllow))

	mux.HandleFunc("GET /system", s.admin(s.handleSystem))
	mux.HandleFunc("GET /audit", s.admin(s.handleAudit))

	mux.HandleFunc("GET /tokens", s.operator(s.handleTokenList))
	mux.HandleFunc("POST /tokens", s.operator(s.handleTokenCreate))
	mux.HandleFunc("POST /tokens/{id}/revoke", s.operator(s.handleTokenRevoke))

	mux.HandleFunc("GET /users", s.admin(s.handleUserList))
	mux.HandleFunc("POST /users", s.admin(s.handleUserCreate))
	mux.HandleFunc("POST /users/{id}/status", s.admin(s.handleUserStatus))

	return chain(mux,
		backend.RequestID,
		backend.Recover(s.log),
		s.securityHeaders,
		backend.AccessLog(s.log),
		s.rateLimit,
	)
}

func chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// No inline script, no external origin at all. The dashboard displays
		// customer data and stored strings; a CSP that permitted inline script
		// would give away the main protection against one of those strings
		// carrying markup.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter == nil || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if !s.limiter.Allow("admin:" + backend.ClientIP(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Serve runs the dashboard until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	go s.purgeLoop()

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

	s.log.Info("admin dashboard listening", "addr", s.cfg.Listen, "version", Version)
	if !isLoopback(s.cfg.Listen) {
		// Worth saying loudly. This surface issues and revokes tenants and
		// reads the audit log across every reseller.
		s.log.Warn("admin dashboard is NOT bound to loopback; put it behind authentication and a private network",
			"addr", s.cfg.Listen)
	}

	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) purgeLoop() {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			if _, err := s.store.PurgeExpiredSessions(); err != nil {
				s.log.Error("session purge failed", "err", err)
			}
		}
	}
}

// ---- sessions ----

type opSession struct {
	token string
	user  *backend.User
	csrf  string
}

func (o *opSession) isAdmin() bool { return o != nil && o.user.Role == backend.RoleAdmin }

// principal renders the session as the type the backend's authorisation
// helpers expect, so row-level visibility uses one implementation rather than
// a second copy that could drift from it.
func (o *opSession) principal() *backend.Principal {
	scopes := map[backend.Scope]bool{}
	for _, sc := range backend.ScopesForRole(o.user.Role) {
		scopes[sc] = true
	}
	return &backend.Principal{
		Kind: "session", UserID: o.user.ID, Email: o.user.Email,
		Role: o.user.Role, Scopes: scopes,
	}
}

// operator admits administrators and resellers.
func (s *Server) operator(next func(http.ResponseWriter, *http.Request, *opSession)) http.HandlerFunc {
	return s.guard(next, false)
}

// admin admits administrators only.
func (s *Server) admin(next func(http.ResponseWriter, *http.Request, *opSession)) http.HandlerFunc {
	return s.guard(next, true)
}

func (s *Server) guard(next func(http.ResponseWriter, *http.Request, *opSession), adminOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFrom(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if adminOnly && !sess.isAdmin() {
			s.renderError(w, r, http.StatusForbidden, "This page is restricted to administrators.")
			return
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				s.renderError(w, r, http.StatusBadRequest, "Malformed form submission.")
				return
			}
			if subtle.ConstantTimeCompare(
				[]byte(r.PostFormValue(csrfField)), []byte(sess.csrf)) != 1 {
				s.renderError(w, r, http.StatusForbidden, "This form has expired. Reload the page and try again.")
				return
			}
		}

		next(w, r, sess)
	}
}

func (s *Server) sessionFrom(r *http.Request) *opSession {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}

	sess, err := s.store.SessionByToken(c.Value)
	if err != nil {
		return nil
	}
	user, err := s.store.UserByID(sess.UserID)
	if err != nil || !user.Active() {
		return nil
	}
	// Customers have their own portal. Admitting one here would give a
	// customer an operator view of data it does not own.
	if user.Role != backend.RoleAdmin && user.Role != backend.RoleReseller {
		return nil
	}

	return &opSession{token: c.Value, user: user, csrf: sess.CSRFToken}
}

func isLoopback(addr string) bool {
	host, _, ok := strings.Cut(addr, ":")
	if !ok {
		return false
	}
	return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
}
