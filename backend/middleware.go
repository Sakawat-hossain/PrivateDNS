package backend

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxPrincipal
	ctxSession
)

const (
	sessionCookie = "pdns_session"
	csrfHeader    = "X-CSRF-Token"

	// maxBodyBytes caps request bodies. Every endpoint here takes small JSON;
	// without a cap a single request can exhaust memory.
	maxBodyBytes = 1 << 20 // 1 MiB
)

// RequestID attaches an identifier used in logs and the audit trail, so one
// request can be followed across both.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 64 {
			buf := make([]byte, 8)
			_, _ = rand.Read(buf)
			id = hex.EncodeToString(buf)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
	})
}

func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

// Recover turns a panic into a 500 rather than a dropped connection, and logs
// the stack. One bad request must not take down the process.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic recovered",
						"err", rec,
						"path", r.URL.Path,
						"request_id", RequestIDFrom(r.Context()),
						"stack", string(debug.Stack()))
					// Deliberately generic: the stack goes to the log, never
					// to the caller.
					writeError(w, http.StatusInternalServerError, "internal error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets defensive response headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// This is a JSON API and renders nothing, so everything is denied.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// BodyLimit caps how much a client may send.
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// CORS applies an explicit allowlist of origins.
//
// There is no wildcard and no origin reflection. Reflecting the Origin header
// while allowing credentials is the classic mistake: it makes every site on the
// internet a trusted origin for an authenticated API.
func CORS(allowed []string) func(http.Handler) http.Handler {
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		set[strings.TrimRight(strings.ToLower(strings.TrimSpace(o)), "/")] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimRight(strings.ToLower(r.Header.Get("Origin")), "/")

			if origin != "" && set[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+csrfHeader)
				h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
				h.Set("Access-Control-Max-Age", "600")
				h.Add("Vary", "Origin")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog records the outcome of each request. Paths and status codes only —
// never bodies, which carry credentials on the login route.
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFrom(r.Context()),
				"ip", clientIP(r))
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Authenticate resolves the caller from a session cookie or a bearer token.
//
// It does not reject anonymous requests; that is Require's job. Separating the
// two keeps endpoints that are legitimately public from having to opt out of
// authentication.
func (s *Server) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			if p := s.principalFromToken(token); p != nil {
				next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, ctxPrincipal, p)))
				return
			}
			// A presented-but-invalid token is not silently downgraded to
			// anonymous; that would turn a revoked token into a confusing 404
			// instead of a clear 401.
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			if p, sess := s.principalFromSession(c.Value); p != nil {
				ctx = context.WithValue(ctx, ctxPrincipal, p)
				ctx = context.WithValue(ctx, ctxSession, sess)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) principalFromToken(token string) *Principal {
	tok, err := s.store.APITokenByValue(token)
	if err != nil || !tok.Usable(time.Now().Unix()) {
		return nil
	}

	user, err := s.store.UserByID(tok.UserID)
	if err != nil || !user.Active() {
		return nil
	}

	// Intersect the token's grant with the role's current ceiling, so
	// demoting a user immediately narrows every token they issued.
	granted := ParseScopes(tok.Scopes)
	effective := map[Scope]bool{}
	for scope := range granted {
		if RoleHasScope(user.Role, scope) {
			effective[scope] = true
		}
	}

	s.store.TouchAPIToken(tok.ID)

	return &Principal{
		Kind: "token", UserID: user.ID, Email: user.Email,
		Role: user.Role, Scopes: effective, CustomerID: user.CustomerID, TokenID: tok.ID,
	}
}

func (s *Server) principalFromSession(token string) (*Principal, *Session) {
	sess, err := s.store.SessionByToken(token)
	if err != nil {
		return nil, nil
	}
	user, err := s.store.UserByID(sess.UserID)
	if err != nil || !user.Active() {
		return nil, nil
	}

	// A session carries everything the role allows.
	scopes := map[Scope]bool{}
	for _, sc := range ScopesForRole(user.Role) {
		scopes[sc] = true
	}

	return &Principal{
		Kind: "session", UserID: user.ID, Email: user.Email,
		Role: user.Role, Scopes: scopes, CustomerID: user.CustomerID,
	}, sess
}

func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxPrincipal).(*Principal)
	return p
}

func sessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(ctxSession).(*Session)
	return s
}

// Require enforces a scope. It is applied per route rather than globally, so a
// new endpoint has to state what it needs and cannot inherit access by accident.
func Require(scope Scope, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !p.Can(scope) {
			writeError(w, http.StatusForbidden, "insufficient scope: "+string(scope))
			return
		}
		next(w, r)
	}
}

// RequireAdmin restricts a route to administrators.
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !p.IsAdmin() {
			writeError(w, http.StatusForbidden, "administrator role required")
			return
		}
		next(w, r)
	}
}

// CSRF protects cookie-authenticated mutating requests.
//
// It applies only to sessions. Bearer tokens are immune by construction: a
// browser never attaches an Authorization header on a cross-site request, so
// there is nothing for an attacker to ride. Requiring a CSRF token from API
// clients would be friction with no security benefit.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		sess := sessionFrom(r.Context())
		if sess == nil {
			next.ServeHTTP(w, r) // token-authenticated or anonymous
			return
		}

		presented := r.Header.Get(csrfHeader)
		if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(sess.CSRFToken)) != 1 {
			writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimit throttles by principal where one is known, and by source address
// otherwise.
//
// Keying on the principal matters: rate limiting purely by IP lets many users
// behind one NAT throttle each other, which in Bangladesh — where carrier-grade
// NAT is widespread — would affect a large share of legitimate traffic.
func (s *Server) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter == nil {
			next.ServeHTTP(w, r)
			return
		}

		key := "ip:" + clientIP(r)
		if p := PrincipalFrom(r.Context()); p != nil {
			key = "user:" + itoa(p.UserID)
		}

		if !s.limiter.Allow(key) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the source address.
//
// X-Forwarded-For is honoured only when the request arrives from a configured
// trusted proxy. Trusting it unconditionally would let any client spoof its
// address and defeat both rate limiting and login throttling.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if trustedProxy(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first, _, ok := strings.Cut(xff, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(xff)
		}
	}
	return host
}

// trustedProxies is set from configuration at startup.
var trustedProxies []string

func trustedProxy(ip string) bool {
	for _, t := range trustedProxies {
		if t == ip {
			return true
		}
	}
	return false
}

// SetTrustedProxies configures which peers may set X-Forwarded-For.
func SetTrustedProxies(ips []string) { trustedProxies = ips }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Chain applies middleware in the order given, so the first listed is outermost.
func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

var errUnauthenticated = errors.New("authentication required")

// ClientIP is the exported form used by the portal, so trusted-proxy handling
// is implemented once rather than diverging between the two surfaces.
func ClientIP(r *http.Request) string { return clientIP(r) }
