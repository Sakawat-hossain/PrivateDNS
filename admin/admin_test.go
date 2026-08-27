package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

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
	cfg.SecureCookies = false
	cfg.RateLimitQPS = 0
	cfg.ResolverAdmin = ""
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

const testPassword = "correct-horse-battery"

func (h *harness) user(email string, role backend.Role) *backend.User {
	h.t.Helper()
	u, err := h.srv.Store().CreateUser(email, "Test", testPassword, role)
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

// customerOf creates a customer owned by ownerID, plus one tenant.
func (h *harness) customerOf(ownerID int64, name, routeID string) int64 {
	h.t.Helper()

	c, err := h.srv.Store().CreateCustomer(name+"@example.com", name, "", ownerID)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.srv.Policy().CreateTenant(routeID, "phone",
		time.Now().Add(30*24*time.Hour).Unix()); err != nil {
		h.t.Fatal(err)
	}
	if err := h.srv.Store().AttachTenant(routeID, c.ID); err != nil {
		h.t.Fatal(err)
	}
	h.srv.Policy().Reload()
	return c.ID
}

type session struct {
	cookie *http.Cookie
	csrf   string
}

func (h *harness) login(email string) *session {
	h.t.Helper()

	form := url.Values{"email": {email}, "password": {testPassword}}
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
			return &session{cookie: c, csrf: sess.CSRFToken}
		}
	}
	h.t.Fatal("no session cookie")
	return nil
}

func (h *harness) get(s *session, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if s != nil {
		req.AddCookie(s.cookie)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func (h *harness) post(s *session, path string, form url.Values) *httptest.ResponseRecorder {
	if form == nil {
		form = url.Values{}
	}
	if s != nil {
		form.Set("csrf_token", s.csrf)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s != nil {
		req.AddCookie(s.cookie)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// ---- access control ----

func TestSignedOutRedirectsToLogin(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/", "/customers", "/tokens", "/triage", "/system", "/audit", "/users", "/policy"} {
		rec := h.get(nil, path)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Errorf("%s = %d (Location %q), want a redirect to /login",
				path, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestCustomerAccountsCannotUseTheDashboard(t *testing.T) {
	h := newHarness(t)
	h.user("cust@example.com", backend.RoleCustomer)

	form := url.Values{"email": {"cust@example.com"}, "password": {testPassword}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	// Customers have their own portal. Admitting one here would give them an
	// operator view of data they do not own.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a customer account", rec.Code)
	}
}

func TestResellersAreLockedOutOfAdminOnlyPages(t *testing.T) {
	h := newHarness(t)
	h.user("reseller@example.com", backend.RoleReseller)
	s := h.login("reseller@example.com")

	// Routing changes where traffic goes for everyone; the audit log spans
	// every reseller. Neither is a reseller's to see or set.
	for _, path := range []string{"/policy", "/system", "/audit", "/users"} {
		rec := h.get(s, path)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d for a reseller, want 403", path, rec.Code)
		}
	}

	// But the operator pages are reachable.
	for _, path := range []string{"/", "/customers", "/triage", "/tokens"} {
		rec := h.get(s, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d for a reseller, want 200", path, rec.Code)
		}
	}
}

// TestResellerIsolation is the commercially important one: resellers compete
// with each other, so one reading another's book is a direct business harm.
func TestResellerCannotSeeAnotherResellersCustomers(t *testing.T) {
	h := newHarness(t)

	a := h.user("a@example.com", backend.RoleReseller)
	b := h.user("b@example.com", backend.RoleReseller)

	aCustomer := h.customerOf(a.ID, "alpha", "alpharoute")
	bCustomer := h.customerOf(b.ID, "bravo", "bravoroute")

	sessA := h.login("a@example.com")

	// The list shows only their own.
	body := h.get(sessA, "/customers").Body.String()
	if !strings.Contains(body, "alpha") {
		t.Fatal("reseller A cannot see its own customer")
	}
	if strings.Contains(body, "bravo") {
		t.Fatal("reseller A can see reseller B's customer in the list")
	}

	// Direct access is refused, and with the same 404 a missing record gives,
	// so probing ids cannot map another reseller's book.
	rec := h.get(sessA, "/customers/"+strconv.FormatInt(bCustomer, 10))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-reseller customer fetch = %d, want 404", rec.Code)
	}

	rec = h.get(sessA, "/tenants/bravoroute")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-reseller tenant fetch = %d, want 404", rec.Code)
	}

	// And mutation is refused too, not merely hidden from the interface.
	rec = h.post(sessA, "/tenants/bravoroute/revoke", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-reseller revoke = %d, want 404", rec.Code)
	}
	if tn := h.srv.Policy().Tenant("bravoroute"); tn == nil || tn.Status != "active" {
		t.Fatal("reseller A revoked reseller B's tenant")
	}

	_ = aCustomer
}

func TestResellerCannotAssignOwnershipToAnother(t *testing.T) {
	h := newHarness(t)
	a := h.user("a@example.com", backend.RoleReseller)
	b := h.user("b@example.com", backend.RoleReseller)
	sessA := h.login("a@example.com")

	// A form naming another owner must be ignored, or one reseller could plant
	// customers under another.
	h.post(sessA, "/customers", url.Values{
		"name": {"planted"}, "owner_id": {strconv.FormatInt(b.ID, 10)},
	})

	principalB := &backend.Principal{UserID: b.ID, Role: backend.RoleReseller}
	list, err := h.srv.Store().ListCustomers(principalB, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.Name == "planted" {
			t.Fatal("a reseller created a customer owned by another reseller")
		}
	}
	_ = a
}

func TestFormsRequireCSRF(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)
	s := h.login("admin@example.com")

	req := httptest.NewRequest("POST", "/customers", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(s.cookie)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d without a CSRF token, want 403", rec.Code)
	}
}

// ---- operations ----

func TestIssueAndRevokeTenant(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)
	cid := h.customerOf(admin.ID, "acme", "acmeroute")
	s := h.login("admin@example.com")

	rec := h.post(s, "/customers/"+strconv.FormatInt(cid, 10)+"/tenants",
		url.Values{"days": {"30"}, "label": {"router"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("issue = %d: %s", rec.Code, rec.Body.String())
	}

	ids, err := h.srv.Store().TenantsForCustomer(cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 { // the seeded one plus the newly issued
		t.Fatalf("customer has %d tenants, want 2", len(ids))
	}

	h.post(s, "/tenants/acmeroute/revoke", nil)
	h.srv.Policy().Reload()
	if tn := h.srv.Policy().Tenant("acmeroute"); tn == nil || tn.Status != "suspended" {
		t.Fatal("revoke did not suspend the tenant")
	}
}

func TestRenewingEarlyAddsToRemainingTime(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)
	h.customerOf(admin.ID, "acme", "acmeroute")
	s := h.login("admin@example.com")

	before := h.srv.Policy().Tenant("acmeroute").ExpiresAt

	h.post(s, "/tenants/acmeroute/extend", url.Values{"days": {"30"}})
	h.srv.Policy().Reload()

	after := h.srv.Policy().Tenant("acmeroute").ExpiresAt
	added := after - before

	// Renewing early must not cost the customer the time they had left.
	if added < 29*24*3600 || added > 31*24*3600 {
		t.Fatalf("renewal added %d seconds, want roughly 30 days on top of the existing expiry", added)
	}
}

func TestAllowlistRoundTrip(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)
	h.customerOf(admin.ID, "acme", "acmeroute")
	s := h.login("admin@example.com")

	h.post(s, "/tenants/acmeroute/allow", url.Values{"domain": {"bank.example.com"}})
	h.srv.Policy().Reload()

	if !h.srv.Policy().Allowed("acmeroute", "bank.example.com") {
		t.Fatal("the domain was not allowlisted")
	}

	h.post(s, "/tenants/acmeroute/allow/remove", url.Values{"domain": {"bank.example.com"}})
	h.srv.Policy().Reload()

	if h.srv.Policy().Allowed("acmeroute", "bank.example.com") {
		t.Fatal("the allowlist entry was not removed")
	}
}

func TestAllowlistRejectsHostileDomains(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)
	h.customerOf(admin.ID, "acme", "acmeroute")
	s := h.login("admin@example.com")

	// These reach the resolver's policy tables and are matched against every
	// query, so a wildcard or a stray character could match far more than
	// intended.
	for _, d := range []string{"", "no-dot", "*.example.com", "a..b.com", "-bad.com", "sp ace.com"} {
		rec := h.post(s, "/tenants/acmeroute/allow", url.Values{"domain": {d}})
		if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "m=err") {
			t.Errorf("domain %q was accepted (Location %q)", d, loc)
		}
	}
}

func TestOverridesAreAdminOnly(t *testing.T) {
	h := newHarness(t)
	h.user("reseller@example.com", backend.RoleReseller)
	s := h.login("reseller@example.com")

	rec := h.post(s, "/policy/overrides", url.Values{
		"domain": {"example.com"}, "answer": {"203.0.113.10"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reseller override = %d, want 403", rec.Code)
	}

	rows, _ := h.srv.Policy().ListOverrides()
	if len(rows) != 0 {
		t.Fatal("a reseller wrote an override")
	}
}

func TestOverrideRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)
	s := h.login("admin@example.com")

	h.post(s, "/policy/overrides", url.Values{
		"domain": {"example.com"}, "answer": {"203.0.113.10"},
	})
	h.srv.Policy().Reload()

	addr, ok := h.srv.Policy().Override("anyone", "api.example.com")
	if !ok || addr.String() != "203.0.113.10" {
		t.Fatalf("override = %v %v, want 203.0.113.10 for a subdomain", addr, ok)
	}

	h.post(s, "/policy/overrides/remove", url.Values{"domain": {"example.com"}})
	h.srv.Policy().Reload()

	if _, ok := h.srv.Policy().Override("anyone", "api.example.com"); ok {
		t.Fatal("the override was not removed")
	}
}

func TestOverrideRejectsBadAddress(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)
	s := h.login("admin@example.com")

	for _, a := range []string{"", "not-an-ip", "example.com", "999.1.1.1"} {
		rec := h.post(s, "/policy/overrides", url.Values{
			"domain": {"example.com"}, "answer": {a},
		})
		if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "m=err") {
			t.Errorf("answer %q was accepted", a)
		}
	}
}

// ---- triage ----

func TestTriageSurfacesPausesAndScopesThemToTheReseller(t *testing.T) {
	h := newHarness(t)

	a := h.user("a@example.com", backend.RoleReseller)
	b := h.user("b@example.com", backend.RoleReseller)
	h.customerOf(a.ID, "alpha", "alpharoute")
	h.customerOf(b.ID, "bravo", "bravoroute")

	// A pause on each reseller's tenant.
	for _, rid := range []string{"alpharoute", "bravoroute"} {
		h.srv.Store().Record(backend.AuditEntry{
			ActorType: "customer", Action: backend.ActionTenantPause,
			TargetType: "tenant", TargetID: rid, At: time.Now().Unix(),
		})
	}

	body := h.get(h.login("a@example.com"), "/triage").Body.String()
	if !strings.Contains(body, "alpharoute") {
		t.Fatal("reseller A's own paused tenant is missing from triage")
	}
	if strings.Contains(body, "bravoroute") {
		t.Fatal("reseller A can see reseller B's paused tenant")
	}
	_ = b
}

func TestTriageAllowWritesTheAllowlist(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)
	h.customerOf(admin.ID, "acme", "acmeroute")
	s := h.login("admin@example.com")

	h.post(s, "/triage/allow", url.Values{
		"route_id": {"acmeroute"}, "domain": {"cdn.example.com"},
	})
	h.srv.Policy().Reload()

	if !h.srv.Policy().Allowed("acmeroute", "cdn.example.com") {
		t.Fatal("the triage fix did not reach the allowlist")
	}
}

// ---- tokens ----

func TestTokenCreationCannotExceedTheOwnersRole(t *testing.T) {
	h := newHarness(t)
	h.user("reseller@example.com", backend.RoleReseller)
	s := h.login("reseller@example.com")

	// audit:read is an administrator scope. A reseller must not be able to
	// mint a token carrying it.
	rec := h.post(s, "/tokens", url.Values{
		"name": {"escalation"}, "scopes": {"audit:read"},
	})
	if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "m=err") {
		t.Fatalf("a reseller minted an audit:read token (Location %q)", loc)
	}

	tokens, _ := h.srv.Store().ListAPITokens(1, true)
	for _, tok := range tokens {
		if strings.Contains(tok.Scopes, "audit:read") {
			t.Fatal("an audit:read token exists")
		}
	}
}

// TestTokenIsShownOnceThenOnlyByPrefix checks what remains visible afterwards.
//
// This test previously asserted the token arrived in the redirect URL, which
// was the defect rather than the requirement. It now checks the property that
// was actually intended: after the one-time reveal, the listing shows only the
// 12-character lookup prefix and never the full secret.
func TestTokenIsShownOnceThenOnlyByPrefix(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)
	s := h.login("admin@example.com")

	h.post(s, "/tokens", url.Values{
		"name": {"integration"}, "scopes": {"tenants:read"},
	})

	// The reveal, once.
	first := h.get(s, "/tokens").Body.String()
	if !revealsToken(first) {
		t.Fatal("the token was not revealed after creation")
	}

	// Recover the full value from the reveal so the listing can be checked
	// against it directly.
	full := extractRevealedToken(first)
	if len(full) < 32 {
		t.Fatalf("could not read the revealed token (got %q)", full)
	}

	// Afterwards: prefix only.
	body := h.get(s, "/tokens").Body.String()
	if strings.Contains(body, full) {
		t.Fatal("the full token value appears in the listing")
	}
	if !strings.Contains(body, full[:12]) {
		t.Fatal("the lookup prefix is not shown, so a token cannot be identified")
	}
}

// extractRevealedToken pulls the token out of the reveal card.
func extractRevealedToken(body string) string {
	const marker = `<code id="newtoken">`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, "<")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// ---- accounts ----

func TestAdminCannotDisableTheirOwnAccount(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)
	s := h.login("admin@example.com")

	// Locking yourself out of the only administrator account is unrecoverable
	// without database surgery.
	h.post(s, "/users/"+strconv.FormatInt(admin.ID, 10)+"/status",
		url.Values{"status": {"disabled"}})

	u, err := h.srv.Store().UserByID(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "active" {
		t.Fatal("the administrator disabled their own account")
	}
}

func TestDisablingAnAccountEvictsItsSessions(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)
	victim := h.user("other@example.com", backend.RoleReseller)

	victimSession := h.login("other@example.com")
	if rec := h.get(victimSession, "/customers"); rec.Code != http.StatusOK {
		t.Fatalf("setup: victim cannot reach /customers (%d)", rec.Code)
	}

	adminSession := h.login("admin@example.com")
	h.post(adminSession, "/users/"+strconv.FormatInt(victim.ID, 10)+"/status",
		url.Values{"status": {"disabled"}})

	// Disabling must evict, not merely prevent the next sign-in.
	rec := h.get(victimSession, "/customers")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the disabled account's session still works (%d)", rec.Code)
	}
}

func TestUserCreationRejectsCustomerRole(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)
	s := h.login("admin@example.com")

	rec := h.post(s, "/users", url.Values{
		"email": {"x@example.com"}, "password": {testPassword}, "role": {"customer"},
	})
	if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "m=err") {
		t.Fatal("a customer account was created from the operator page")
	}
}

// ---- rendering ----

func TestStoredValuesAreEscaped(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)

	c, err := h.srv.Store().CreateCustomer("x@example.com",
		`<script>alert(1)</script>`, "", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Policy().CreateTenant("xssroute", `<img src=x onerror=alert(1)>`,
		time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	h.srv.Store().AttachTenant("xssroute", c.ID)
	h.srv.Policy().Reload()

	s := h.login("admin@example.com")
	for _, path := range []string{"/customers", "/customers/" + strconv.FormatInt(c.ID, 10), "/tenants/xssroute"} {
		body := h.get(s, path).Body.String()
		if strings.Contains(body, "<script>alert(1)</script>") ||
			strings.Contains(body, "<img src=x onerror=") {
			t.Errorf("%s rendered a stored value unescaped", path)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	rec := h.get(nil, "/login")

	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	// The dashboard is an operator tool; search engines should never hold a
	// copy of a page listing customers.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("CSP permits unsafe script execution: %s", csp)
	}
}

func TestOverviewRendersForAnAdmin(t *testing.T) {
	h := newHarness(t)
	admin := h.user("admin@example.com", backend.RoleAdmin)
	h.customerOf(admin.ID, "acme", "acmeroute")

	rec := h.get(h.login("admin@example.com"), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("overview = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Active tenants", "Customers", "Expiring this week"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview is missing %q", want)
		}
	}
}

func TestResolverStatusDegradesWhenUnreachable(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)

	// With resolver_admin unset, the page must still render and say so rather
	// than failing — an operator investigating an outage needs this page most.
	rec := h.get(h.login("admin@example.com"), "/system")
	if rec.Code != http.StatusOK {
		t.Fatalf("system = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Not answering") {
		t.Fatal("the system page does not report the resolver as unreachable")
	}
}

func TestStaticAssetsAreEmbedded(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/static/admin.css", "/static/admin.js", "/static/icon.svg"} {
		if rec := h.get(nil, path); rec.Code != http.StatusOK {
			t.Errorf("%s = %d", path, rec.Code)
		}
	}
}

func TestMetricsParsing(t *testing.T) {
	body := `# HELP privatedns_queries_total Queries received.
# TYPE privatedns_queries_total counter
privatedns_queries_total 12345
privatedns_blocked_total 678
malformed line here
privatedns_uptime_seconds 3600
`
	got := parseMetrics(body)
	if got["privatedns_queries_total"] != 12345 {
		t.Errorf("queries = %d", got["privatedns_queries_total"])
	}
	if got["privatedns_blocked_total"] != 678 {
		t.Errorf("blocked = %d", got["privatedns_blocked_total"])
	}
	if _, ok := got["malformed"]; ok {
		t.Error("a malformed line produced a metric")
	}
}

// revealsToken reports whether a page is showing a full, freshly created API
// token. The 12-character prefix in the listing table is shown by design and
// is not a secret, so matching on "pdns_" alone would be the wrong signal.
func revealsToken(body string) bool {
	return strings.Contains(body, "Copy this now")
}

// TestTokenNeverAppearsInAURL guards a real defect found in review.
//
// The creation handler used to redirect to /tokens?new=<plaintext>. A secret in
// a query string is written to browser history, sent in the Referer header on
// any outbound link, and recorded verbatim in nginx access logs and every proxy
// between the operator and the server.
func TestTokenNeverAppearsInAURL(t *testing.T) {
	h := newHarness(t)
	h.user("admin@example.com", backend.RoleAdmin)
	s := h.login("admin@example.com")

	rec := h.post(s, "/tokens", url.Values{
		"name": {"integration"}, "scopes": {"tenants:read"},
	})

	location := rec.Header().Get("Location")
	if strings.Contains(location, "pdns_") || strings.Contains(location, "new=") {
		t.Fatalf("the token was placed in the redirect URL: %s", location)
	}

	// It must still reach the page exactly once.
	if !revealsToken(h.get(s, "/tokens").Body.String()) {
		t.Fatal("the token was not shown after creation")
	}

	// And not a second time. "Copy this now, it cannot be shown again" has to
	// be true, or an operator leaves the tab open as somewhere to find it.
	if revealsToken(h.get(s, "/tokens").Body.String()) {
		t.Fatal("the token was shown again on reload")
	}
}

// TestStashedTokenIsScopedToItsSession stops one operator collecting another's
// freshly created credential.
func TestStashedTokenIsScopedToItsSession(t *testing.T) {
	h := newHarness(t)
	h.user("a@example.com", backend.RoleAdmin)
	h.user("b@example.com", backend.RoleAdmin)

	sessionA := h.login("a@example.com")
	sessionB := h.login("b@example.com")

	h.post(sessionA, "/tokens", url.Values{
		"name": {"a-token"}, "scopes": {"tenants:read"},
	})

	if revealsToken(h.get(sessionB, "/tokens").Body.String()) {
		t.Fatal("another operator's session was shown the new token")
	}
	if !revealsToken(h.get(sessionA, "/tokens").Body.String()) {
		t.Fatal("the creating session did not receive its own token")
	}
}
