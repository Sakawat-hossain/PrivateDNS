package portal

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
)

// pageData is what every template receives.
type pageData struct {
	Lang      Lang
	Brand     string
	Support   string
	Version   string
	CSRF      string
	Flash     string
	FlashKind string // "ok" or "error"

	Hostname   string
	BaseDomain string
	RouteID    string
	Tenants    []tenantView
	ClientIP   string

	Status    string
	Active    bool
	Filtering bool
	Paused    bool
	ExpiresAt int64
	ExpiresIn string
	Expiring  bool
	Queries   int64
	Blocked   int64
	SignedIn  bool
}

type tenantView struct {
	RouteID   string
	Hostname  string
	Label     string
	Active    bool
	ExpiresAt int64
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, d pageData) {
	d.Lang = LangFrom(r)
	d.Brand = s.cfg.BrandName
	d.Support = s.cfg.SupportURL
	d.Version = Version
	d.BaseDomain = s.cfg.BaseDomain

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, d); err != nil {
		s.log.Error("template render failed", "template", name, "err", err)
	}
}

// ---- language ----

func (s *Server) handleSetLang(w http.ResponseWriter, r *http.Request) {
	lang := Lang(r.PathValue("lang"))
	if !lang.Valid() {
		lang = LangEN
	}

	http.SetCookie(w, &http.Cookie{
		Name: langCookie, Value: string(lang), Path: "/",
		HttpOnly: true, Secure: s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: 365 * 24 * 3600,
	})

	// Return where they were, but only to a local path — an open redirect
	// here would let a phishing link bounce through our domain.
	back := r.URL.Query().Get("next")
	if !safeLocalPath(back) {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// safeLocalPath permits only same-site absolute paths. "//evil.example" is a
// protocol-relative URL and must not pass.
func safeLocalPath(p string) bool {
	return len(p) > 0 && p[0] == '/' && (len(p) == 1 || p[1] != '/')
}

// ---- authentication ----

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.sessionFrom(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login.html", pageData{})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	ip := backend.ClientIP(r)
	lang := LangFrom(r)

	byEmail, byIP, err := s.store.RecentFailures(email, ip, s.cfg.LoginWindow)
	if err != nil {
		s.render(w, r, "login.html", pageData{Flash: T(lang, "error.generic"), FlashKind: "error"})
		return
	}
	if byEmail >= s.cfg.MaxLoginFailures || byIP >= s.cfg.MaxLoginFailures*3 {
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, r, "login.html", pageData{Flash: T(lang, "login.throttled"), FlashKind: "error"})
		return
	}

	user, err := s.store.UserByEmail(email)
	ok := err == nil &&
		user.Active() &&
		user.Role == backend.RoleCustomer &&
		user.CustomerID != 0 &&
		s.store.VerifyUserPassword(user, password) == nil

	if !ok {
		// Spend comparable time whether or not the account exists, so timing
		// does not enumerate customers.
		if err != nil {
			s.store.BurnPasswordTime(password)
		}
		s.store.RecordLoginAttempt(email, ip, false)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login.html", pageData{Flash: T(lang, "login.failed"), FlashKind: "error"})
		return
	}

	token, sess, err := s.store.CreateSession(user.ID, s.cfg.SessionTTL, ip, r.UserAgent())
	if err != nil {
		s.render(w, r, "login.html", pageData{Flash: T(lang, "error.generic"), FlashKind: "error"})
		return
	}

	s.store.RecordLoginAttempt(email, ip, true)
	s.store.Record(backend.AuditEntry{
		ActorType: "customer", ActorID: fmt.Sprint(user.ID), ActorLabel: user.Email,
		Action: backend.ActionLogin, IP: ip,
		RequestID: backend.RequestIDFrom(r.Context()),
	})

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(sess.ExpiresAt, 0),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = s.store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- status ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, sess *customerSession) {
	lang := LangFrom(r)
	d := pageData{
		SignedIn: true,
		CSRF:     sess.csrf,
		ClientIP: backend.ClientIP(r),
	}

	routeID := sess.primaryTenant()
	if routeID == "" {
		d.Flash = T(lang, "renew.help")
		d.FlashKind = "error"
		s.render(w, r, "status.html", d)
		return
	}

	t := s.policy.Tenant(routeID)
	if t == nil {
		d.Flash = T(lang, "renew.help")
		d.FlashKind = "error"
		s.render(w, r, "status.html", d)
		return
	}

	now := time.Now()
	d.RouteID = routeID
	d.Hostname = routeID + "." + s.cfg.BaseDomain
	d.Active = t.Active(now.Unix())
	d.Filtering = t.Filtering(now.Unix())
	d.Paused = t.PausedUntil > now.Unix()
	d.ExpiresAt = t.ExpiresAt
	d.Status = t.Status

	remaining := time.Until(time.Unix(t.ExpiresAt, 0))
	d.ExpiresIn = humanRemaining(lang, remaining)
	// A week is enough warning to arrange payment without nagging daily.
	d.Expiring = remaining > 0 && remaining < 7*24*time.Hour

	if u, ok := s.policy.Usage(routeID); ok {
		d.Queries = u.Queries
		d.Blocked = u.Blocked
	}

	if msg := r.URL.Query().Get("m"); msg != "" {
		d.Flash, d.FlashKind = flashFor(lang, msg)
	}

	s.render(w, r, "status.html", d)
}

func humanRemaining(lang Lang, d time.Duration) string {
	if d <= 0 {
		return T(lang, "status.expired")
	}
	if days := int(d.Hours() / 24); days >= 1 {
		return fmt.Sprintf("%d %s", days, T(lang, "status.daysleft"))
	}
	return fmt.Sprintf("%d %s", int(d.Hours())+1, T(lang, "status.hoursleft"))
}

func flashFor(lang Lang, code string) (string, string) {
	switch code {
	case "ip":
		return T(lang, "ip.updated"), "ok"
	case "paused":
		return T(lang, "pause.active"), "ok"
	case "err":
		return T(lang, "error.generic"), "error"
	}
	return "", ""
}

// ---- the update-my-IP control ----

// handleUpdateIP binds the address this request arrived from.
//
// This is the most-used control in the product. A customer abroad moves between
// mobile data and Wi-Fi constantly, and each move changes the address the proxy
// tier authorises against. If this is not one tap, every network change becomes
// a support message — which is precisely the ceiling both competitors are stuck
// under.
func (s *Server) handleUpdateIP(w http.ResponseWriter, r *http.Request, sess *customerSession) {
	routeID := r.PostFormValue("route_id")
	if routeID == "" {
		routeID = sess.primaryTenant()
	}
	// Never trust the form: the session decides what it may touch.
	if !sess.owns(routeID) {
		http.Redirect(w, r, "/?m=err", http.StatusSeeOther)
		return
	}

	// Always the observed address, never one the client nominates. Otherwise a
	// customer could authorise a stranger's connection through the proxy.
	ip := backend.ClientIP(r)
	if net.ParseIP(ip) == nil {
		http.Redirect(w, r, "/?m=err", http.StatusSeeOther)
		return
	}

	if err := s.policy.RegisterIP(routeID, ip); err != nil {
		s.log.Error("ip registration failed", "err", err)
		http.Redirect(w, r, "/?m=err", http.StatusSeeOther)
		return
	}
	_ = s.policy.Reload()

	s.store.Record(backend.AuditEntry{
		ActorType: "customer", ActorID: fmt.Sprint(sess.user.ID), ActorLabel: sess.user.Email,
		Action: backend.ActionIPRegister, TargetType: "tenant", TargetID: routeID,
		Detail: backend.AuditDetail(map[string]any{"ip": ip}), IP: ip,
		RequestID: backend.RequestIDFrom(r.Context()),
	})

	http.Redirect(w, r, "/?m=ip", http.StatusSeeOther)
}

// ---- pause filtering ----

func (s *Server) handlePause(w http.ResponseWriter, r *http.Request, sess *customerSession) {
	routeID := r.PostFormValue("route_id")
	if routeID == "" {
		routeID = sess.primaryTenant()
	}
	if !sess.owns(routeID) {
		http.Redirect(w, r, "/?m=err", http.StatusSeeOther)
		return
	}

	// Five minutes, fixed. Long enough to finish what was blocked, short
	// enough that "pause" cannot quietly become "off".
	until := time.Now().Add(5 * time.Minute).Unix()
	if err := s.policy.PauseFiltering(routeID, until); err != nil {
		http.Redirect(w, r, "/?m=err", http.StatusSeeOther)
		return
	}
	_ = s.policy.Reload()

	s.store.Record(backend.AuditEntry{
		ActorType: "customer", ActorID: fmt.Sprint(sess.user.ID), ActorLabel: sess.user.Email,
		Action: backend.ActionTenantPause, TargetType: "tenant", TargetID: routeID,
		IP: backend.ClientIP(r), RequestID: backend.RequestIDFrom(r.Context()),
	})

	http.Redirect(w, r, "/?m=paused", http.StatusSeeOther)
}

// ---- setup ----

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request, sess *customerSession) {
	d := pageData{SignedIn: true, CSRF: sess.csrf, ClientIP: backend.ClientIP(r)}

	now := time.Now().Unix()
	for _, id := range sess.routeIDs {
		v := tenantView{RouteID: id, Hostname: id + "." + s.cfg.BaseDomain}
		if t := s.policy.Tenant(id); t != nil {
			v.Label, v.Active, v.ExpiresAt = t.Label, t.Active(now), t.ExpiresAt
		}
		d.Tenants = append(d.Tenants, v)
	}
	if len(d.Tenants) > 0 {
		d.RouteID = d.Tenants[0].RouteID
		d.Hostname = d.Tenants[0].Hostname
	}

	s.render(w, r, "setup.html", d)
}

func (s *Server) handleMobileConfig(w http.ResponseWriter, r *http.Request, sess *customerSession) {
	routeID := r.URL.Query().Get("route_id")
	if routeID == "" {
		routeID = sess.primaryTenant()
	}
	if !sess.owns(routeID) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	profile := MobileConfig{
		Hostname:     routeID + "." + s.cfg.BaseDomain,
		DisplayName:  s.cfg.BrandName,
		Organization: s.cfg.BrandName,
		Identifier:   "io.privatedns.profile." + routeID,
		Description:  s.cfg.BrandName + " encrypted DNS",
	}

	body, err := profile.Generate()
	if err != nil {
		http.Error(w, "could not generate profile", http.StatusInternalServerError)
		return
	}

	// The content type is what makes iOS offer to install it rather than
	// showing XML in the browser.
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+profile.Filename()+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// ---- PWA ----

// handleManifest makes the portal installable to a home screen.
//
// A PWA rather than a native app is deliberate: app stores are hostile to this
// category, review would be a recurring risk, and the portal is a handful of
// pages. Installing from the browser sidesteps that entirely.
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	manifest := map[string]any{
		"name":             s.cfg.BrandName,
		"short_name":       s.cfg.BrandName,
		"start_url":        "/",
		"scope":            "/",
		"display":          "standalone",
		"background_color": "#0e1218",
		"theme_color":      "#0e1218",
		"icons": []map[string]any{
			{"src": "/static/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"},
		},
	}
	w.Header().Set("Content-Type", "application/manifest+json")
	_ = json.NewEncoder(w).Encode(manifest)
}

// handleServiceWorker serves a deliberately minimal worker.
//
// It caches the shell only. Caching status data would be actively harmful: a
// customer checking whether their subscription is still active must not be
// shown a stale answer.
func (s *Server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	const sw = `// Caches the interface shell only. Status, usage and expiry are always
// fetched live: showing a customer a cached "active" after their subscription
// lapsed would be worse than showing nothing.
const CACHE = 'privatedns-shell-v1';
const SHELL = ['/static/app.css', '/static/app.js', '/static/icon.svg'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) =>
    Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || !url.pathname.startsWith('/static/')) return;
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});
`
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(sw))
}
