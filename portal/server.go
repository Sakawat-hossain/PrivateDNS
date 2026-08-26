package portal

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
	sessionCookie = "pdns_portal"
	csrfField     = "csrf_token"
)

// Config is the portal's configuration.
type Config struct {
	// Listen is the public-facing address. Unlike the backend API, this is
	// meant to be reachable from the internet — behind Nginx for TLS.
	Listen string `yaml:"listen"`

	PolicyDB   string `yaml:"policy_db"`
	BaseDomain string `yaml:"base_domain"`

	// BrandName appears in the interface and in the iOS profile.
	BrandName string `yaml:"brand_name"`

	// SupportURL is where "renew" and "contact us" point. A WhatsApp link is
	// the norm for this market.
	SupportURL string `yaml:"support_url"`

	// ResolverAdmin is the resolver's admin API, used to read diagnostic
	// probe results. It is normally on loopback.
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
		Listen:           "127.0.0.1:8081",
		PolicyDB:         "/var/lib/private-dns/policy.db",
		BaseDomain:       "dns.example.com",
		BrandName:        "PrivateDNS",
		ResolverAdmin:    "http://127.0.0.1:8053",
		SessionTTL:       30 * 24 * time.Hour,
		SecureCookies:    true,
		RateLimitQPS:     10,
		RateLimitBurst:   30,
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
		// Customers are not operators. A month-long session is the difference
		// between a product they open and one they give up on.
		c.SessionTTL = 30 * 24 * time.Hour
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

// Server is the customer-facing portal.
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
	// html/template escapes by context, so a hostname or customer name cannot
	// break out of the markup it is rendered into.
	funcs := template.FuncMap{
		"t": T,
	}
	return template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
}

// Handler builds the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fsSub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /manifest.webmanifest", s.handleManifest)
	mux.HandleFunc("GET /sw.js", s.handleServiceWorker)

	mux.HandleFunc("GET /lang/{lang}", s.handleSetLang)

	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)

	mux.HandleFunc("GET /", s.requireCustomer(s.handleStatus))
	mux.HandleFunc("GET /setup", s.requireCustomer(s.handleSetup))
	mux.HandleFunc("GET /profile.mobileconfig", s.requireCustomer(s.handleMobileConfig))

	mux.HandleFunc("POST /ip", s.requireCustomer(s.handleUpdateIP))
	mux.HandleFunc("POST /pause", s.requireCustomer(s.handlePause))

	// The diagnostic is reachable without signing in. Someone whose DNS is
	// misconfigured may not be able to reach the portal at all, and telling
	// them why is more useful than a login form.
	mux.HandleFunc("GET /check", s.handleCheckPage)
	mux.HandleFunc("GET /check/start", s.handleCheckStart)
	mux.HandleFunc("GET /check/result/{nonce}", s.handleCheckResult)

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

// securityHeaders is stricter than the API's, because this surface renders
// HTML that a browser executes.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// No inline script and no external origin. The diagnostic page needs
		// to reach an arbitrary probe hostname, which is why connect-src is
		// wider than the rest.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter == nil || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if !s.limiter.Allow("portal:" + clientIP(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Serve runs the portal until ctx is cancelled.
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

	s.log.Info("portal listening",
		"addr", s.cfg.Listen, "version", Version, "base_domain", s.cfg.BaseDomain)

	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) purgeLoop() {
	t := time.NewTicker(time.Hour)
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

// ---- session handling ----

type customerSession struct {
	token    string
	user     *backend.User
	csrf     string
	routeIDs []string
}

// requireCustomer resolves the signed-in customer, redirecting to the login
// page rather than returning a status code — this surface is used by people,
// not programs.
func (s *Server) requireCustomer(next func(http.ResponseWriter, *http.Request, *customerSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFrom(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Mutating requests are form posts from a cookie-authenticated
		// session, so they carry a CSRF token.
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			presented := r.PostFormValue(csrfField)
			if subtle.ConstantTimeCompare([]byte(presented), []byte(sess.csrf)) != 1 {
				http.Error(w, "invalid form token", http.StatusForbidden)
				return
			}
		}

		next(w, r, sess)
	}
}

func (s *Server) sessionFrom(r *http.Request) *customerSession {
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
	// This portal serves customers only. An operator account signing in here
	// would see a customer view of data it does not own.
	if user.Role != backend.RoleCustomer || user.CustomerID == 0 {
		return nil
	}

	routeIDs, err := s.store.TenantsForCustomer(user.CustomerID)
	if err != nil {
		return nil
	}

	return &customerSession{token: c.Value, user: user, csrf: sess.CSRFToken, routeIDs: routeIDs}
}

// primaryTenant is the tenant the portal shows. Most customers hold exactly
// one; the first is used when there are several, and the setup page lists them
// all.
func (c *customerSession) primaryTenant() string {
	if len(c.routeIDs) == 0 {
		return ""
	}
	return c.routeIDs[0]
}

// owns reports whether a route belongs to this session, so a hand-edited form
// cannot act on someone else's tenant.
func (c *customerSession) owns(routeID string) bool {
	for _, id := range c.routeIDs {
		if id == routeID {
			return true
		}
	}
	return false
}

// clientIP defers to the backend so trusted-proxy handling is not duplicated.
func clientIP(r *http.Request) string { return backend.ClientIP(r) }
