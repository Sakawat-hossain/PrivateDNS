package portal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
)

// ---- harness ----

type harness struct {
	t   *testing.T
	srv *Server
	h   http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	cfg := DefaultConfig()
	cfg.PolicyDB = filepath.Join(t.TempDir(), "policy.db")
	cfg.BaseDomain = "dns.example.com"
	cfg.BrandName = "PrivateDNS"
	cfg.SecureCookies = false
	cfg.RateLimitQPS = 0
	cfg.ResolverAdmin = "" // probe tests stub this
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	srv, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	return &harness{t: t, srv: srv, h: srv.Handler()}
}

// customer creates a customer record, a login for it, and a tenant.
func (h *harness) customer(email string) (customerID int64, routeID string) {
	h.t.Helper()

	c, err := h.srv.Store().CreateCustomer(email, "Test", "01700000000", 1)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.srv.Store().CreateCustomerUser(email, "Test", "correct-horse-battery", c.ID); err != nil {
		h.t.Fatal(err)
	}

	routeID = strings.ToLower(strings.ReplaceAll(strings.Split(email, "@")[0], ".", ""))
	if err := h.srv.Policy().CreateTenant(routeID, "phone", time.Now().Add(30*24*time.Hour).Unix()); err != nil {
		h.t.Fatal(err)
	}
	if err := h.srv.Store().AttachTenant(routeID, c.ID); err != nil {
		h.t.Fatal(err)
	}
	h.srv.Policy().Reload()

	return c.ID, routeID
}

type loginResult struct {
	cookie *http.Cookie
	csrf   string
}

func (h *harness) login(email string) *loginResult {
	h.t.Helper()

	form := url.Values{"email": {email}, "password": {"correct-horse-battery"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		h.t.Fatalf("login = %d, want 303: %s", rec.Code, rec.Body.String())
	}

	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			sess, err := h.srv.Store().SessionByToken(c.Value)
			if err != nil {
				h.t.Fatal(err)
			}
			return &loginResult{cookie: c, csrf: sess.CSRFToken}
		}
	}
	h.t.Fatal("no session cookie set")
	return nil
}

func (h *harness) get(l *loginResult, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if l != nil {
		req.AddCookie(l.cookie)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func (h *harness) post(l *loginResult, path string, form url.Values) *httptest.ResponseRecorder {
	if form == nil {
		form = url.Values{}
	}
	if l != nil {
		form.Set("csrf_token", l.csrf)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if l != nil {
		req.AddCookie(l.cookie)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// ---- iOS configuration profile ----

func TestMobileConfigIsValidAndCarriesDoT(t *testing.T) {
	profile := MobileConfig{
		Hostname:     "k7mp2qx9rt.dns.example.com",
		DisplayName:  "PrivateDNS",
		Organization: "PrivateDNS",
		Identifier:   "io.privatedns.profile.k7mp2qx9rt",
	}

	body, err := profile.Generate()
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	for _, want := range []string{
		`<!DOCTYPE plist`,
		`com.apple.dnsSettings.managed`,
		// TLS, not HTTPS: DoT is what carries the tenant in the SNI.
		`<key>DNSProtocol</key>`,
		`<string>TLS</string>`,
		`<key>ServerName</key>`,
		`k7mp2qx9rt.dns.example.com`,
		`<key>PayloadType</key>`,
		`<string>Configuration</string>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile is missing %q", want)
		}
	}

	// Removable, or a customer whose subscription lapses is trapped with a
	// resolver that refuses them.
	if !strings.Contains(got, "<key>PayloadRemovalDisallowed</key>\n\t<false/>") {
		t.Error("the profile must be removable")
	}
}

func TestMobileConfigUUIDsAreStable(t *testing.T) {
	p := MobileConfig{Hostname: "abc.dns.example.com"}

	first, err := p.Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Regenerating must produce the same identifiers, so a reinstall replaces
	// the existing profile rather than leaving two fighting over one setting.
	if string(first) != string(second) {
		t.Fatal("two generations of the same profile differ")
	}

	other := MobileConfig{Hostname: "xyz.dns.example.com"}
	otherBody, _ := other.Generate()
	if string(otherBody) == string(first) {
		t.Fatal("different hostnames produced identical profiles")
	}
}

func TestMobileConfigRejectsHostileHostnames(t *testing.T) {
	for _, h := range []string{
		"", "not a host", "host<injected>.example.com",
		"a..b.example.com", "-bad.example.com", "trailing.example.com.",
	} {
		p := MobileConfig{Hostname: h}
		if _, err := p.Generate(); err == nil {
			t.Errorf("Generate accepted hostile hostname %q", h)
		}
	}
}

func TestMobileConfigFilename(t *testing.T) {
	p := MobileConfig{Hostname: "k7mp2qx9rt.dns.example.com"}
	if got := p.Filename(); got != "k7mp2qx9rt.mobileconfig" {
		t.Fatalf("filename = %q", got)
	}
}

// ---- access control ----

func TestSignedOutIsRedirectedToLogin(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/", "/setup", "/profile.mobileconfig"} {
		rec := h.get(nil, path)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s = %d, want a redirect to the login page", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s redirected to %q, want /login", path, loc)
		}
	}
}

func TestOperatorAccountsCannotUseTheCustomerPortal(t *testing.T) {
	h := newHarness(t)

	// An admin account exists in the same users table.
	if _, err := h.srv.Store().CreateUser("admin@example.com", "Admin",
		"correct-horse-battery", backend.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"email": {"admin@example.com"}, "password": {"correct-horse-battery"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	// This portal serves customers only; an operator signing in here would get
	// a customer view of data it does not own.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an operator account", rec.Code)
	}
}

func TestCustomerCannotActOnAnotherCustomersTenant(t *testing.T) {
	h := newHarness(t)
	h.customer("alice@example.com")
	_, bobRoute := h.customer("bob@example.com")

	alice := h.login("alice@example.com")

	// A hand-edited form naming Bob's tenant must not be honoured.
	rec := h.post(alice, "/ip", url.Values{"route_id": {bobRoute}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/?m=err" {
		t.Fatalf("update-ip on another tenant: %d %s",
			rec.Code, rec.Header().Get("Location"))
	}

	rec = h.post(alice, "/pause", url.Values{"route_id": {bobRoute}})
	if rec.Header().Get("Location") != "/?m=err" {
		t.Fatalf("pause on another tenant was not refused")
	}

	rec = h.get(alice, "/profile.mobileconfig?route_id="+bobRoute)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("profile download for another tenant = %d, want 404", rec.Code)
	}
}

func TestFormsRequireCSRFToken(t *testing.T) {
	h := newHarness(t)
	h.customer("alice@example.com")
	alice := h.login("alice@example.com")

	// Post without the token.
	req := httptest.NewRequest("POST", "/ip", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(alice.cookie)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without a form token", rec.Code)
	}
}

// ---- the update-my-IP control ----

func TestUpdateIPBindsTheObservedAddress(t *testing.T) {
	h := newHarness(t)
	_, routeID := h.customer("alice@example.com")
	alice := h.login("alice@example.com")

	// Nominating an address must be ignored: honouring it would let a customer
	// authorise a stranger's connection through the proxy.
	form := url.Values{"route_id": {routeID}, "ip": {"203.0.113.99"}}
	req := httptest.NewRequest("POST", "/ip", strings.NewReader(form.Encode()))
	form.Set("csrf_token", alice.csrf)
	req = httptest.NewRequest("POST", "/ip", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(alice.cookie)
	req.RemoteAddr = "198.51.100.7:5555"

	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	h.srv.Policy().Reload()
	if tn := h.srv.Policy().TenantByIP("198.51.100.7"); tn == nil || tn.RouteID != routeID {
		t.Fatal("the observed address was not bound to the tenant")
	}
	if tn := h.srv.Policy().TenantByIP("203.0.113.99"); tn != nil {
		t.Fatal("the nominated address was bound; only the observed one may be")
	}
}

func TestUpdateIPIsAudited(t *testing.T) {
	h := newHarness(t)
	_, routeID := h.customer("alice@example.com")
	alice := h.login("alice@example.com")

	h.post(alice, "/ip", url.Values{"route_id": {routeID}})

	entries, err := h.srv.Store().ListAudit(backend.AuditQuery{
		Action: backend.ActionIPRegister, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the IP update was not audited")
	}
	if entries[0].ActorType != "customer" {
		t.Fatalf("actor type = %q, want customer", entries[0].ActorType)
	}
}

// ---- pause ----

func TestPauseIsBounded(t *testing.T) {
	h := newHarness(t)
	_, routeID := h.customer("alice@example.com")
	alice := h.login("alice@example.com")

	before := time.Now()
	h.post(alice, "/pause", url.Values{"route_id": {routeID}})
	h.srv.Policy().Reload()

	tn := h.srv.Policy().Tenant(routeID)
	if tn == nil {
		t.Fatal("tenant vanished")
	}
	// Long enough to finish what was blocked, short enough that pause cannot
	// quietly become off.
	paused := time.Unix(tn.PausedUntil, 0)
	if paused.Before(before) || paused.After(before.Add(6*time.Minute)) {
		t.Fatalf("paused until %v, want roughly five minutes from now", paused)
	}
}

// ---- language ----

func TestLanguageSwitching(t *testing.T) {
	h := newHarness(t)

	rec := h.get(nil, "/lang/bn?next=/login")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}

	var langCookieValue string
	for _, c := range rec.Result().Cookies() {
		if c.Name == langCookie {
			langCookieValue = c.Value
		}
	}
	if langCookieValue != "bn" {
		t.Fatalf("language cookie = %q, want bn", langCookieValue)
	}

	// The page should now render Bengali.
	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: langCookie, Value: "bn"})
	rec = httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "সাইন ইন") {
		t.Fatal("the Bengali sign-in string was not rendered")
	}
}

func TestLanguageRedirectCannotLeaveTheSite(t *testing.T) {
	h := newHarness(t)

	// An open redirect here would let a phishing link bounce through our own
	// domain, which is exactly what makes such links convincing.
	for _, hostile := range []string{
		"https://evil.example", "//evil.example", "http://evil.example/x",
	} {
		rec := h.get(nil, "/lang/en?next="+url.QueryEscape(hostile))
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("next=%q redirected to %q, want /", hostile, loc)
		}
	}
}

func TestTranslationFallsBackRatherThanRenderingEmpty(t *testing.T) {
	// A key present in English but missing from Bengali must fall back, not
	// render an empty element.
	if got := T(LangBN, "app.name"); got == "" {
		t.Fatal("a known key returned empty")
	}
	if got := T(LangBN, "no.such.key"); got != "no.such.key" {
		t.Fatalf("an unknown key returned %q, want the key itself", got)
	}
}

// ---- diagnostic ----

func TestCheckPageIsReachableWithoutSigningIn(t *testing.T) {
	h := newHarness(t)

	// Someone whose DNS is misconfigured may not be able to reach anything
	// else; telling them why is more useful than a login form.
	rec := h.get(nil, "/check")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an anonymous visitor", rec.Code)
	}
}

func TestCheckStartIssuesAUsableProbeHost(t *testing.T) {
	h := newHarness(t)

	rec := h.get(nil, "/check/start")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, ".check.dns.example.com") {
		t.Fatalf("probe host is not in the diagnostic zone: %s", body)
	}
	if !strings.Contains(body, `"nonce"`) {
		t.Fatalf("no nonce issued: %s", body)
	}
}

func TestCheckRejectsMalformedNonce(t *testing.T) {
	h := newHarness(t)

	for _, n := range []string{
		"short", "../../etc/passwd", "ZZZZZZZZZZZZZZZZZZZZZZZZ",
		strings.Repeat("a", 100),
	} {
		rec := h.get(nil, "/check/result/"+url.PathEscape(n))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("nonce %q = %d, want 400", n, rec.Code)
		}
	}
}

// ---- rendering ----

func TestStatusPageEscapesRenderedValues(t *testing.T) {
	h := newHarness(t)

	c, err := h.srv.Store().CreateCustomer("x@example.com", `<script>alert(1)</script>`, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.Store().CreateCustomerUser("x@example.com", "x", "correct-horse-battery", c.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Policy().CreateTenant("xtenant", `<img src=x onerror=alert(1)>`,
		time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	h.srv.Store().AttachTenant("xtenant", c.ID)
	h.srv.Policy().Reload()

	l := h.login("x@example.com")
	rec := h.get(l, "/setup")

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") ||
		strings.Contains(body, "<img src=x onerror=") {
		t.Fatal("a stored value was rendered unescaped")
	}
}

func TestSecurityHeadersOnHTML(t *testing.T) {
	h := newHarness(t)
	rec := h.get(nil, "/login")

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy")
	}
	// The portal has no inline script; allowing unsafe-inline would give away
	// the main protection a CSP provides.
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("CSP permits unsafe script execution: %s", csp)
	}
}

func TestManifestAndServiceWorkerAreServed(t *testing.T) {
	h := newHarness(t)

	rec := h.get(nil, "/manifest.webmanifest")
	if rec.Code != http.StatusOK {
		t.Fatalf("manifest = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "manifest") {
		t.Fatalf("manifest content type = %q", ct)
	}

	rec = h.get(nil, "/sw.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("service worker = %d", rec.Code)
	}
	// Caching status would let a customer see "active" after their
	// subscription lapsed, which is worse than showing nothing.
	if !strings.Contains(rec.Body.String(), "/static/") {
		t.Fatal("the service worker should cache the shell only")
	}
}

func TestStaticAssetsAreEmbedded(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/static/app.css", "/static/app.js", "/static/icon.svg"} {
		rec := h.get(nil, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200 from the embedded filesystem", path, rec.Code)
		}
	}
}
