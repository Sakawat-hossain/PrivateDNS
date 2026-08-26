package backend

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	cfg.SecureCookies = false // the test client speaks plain HTTP
	cfg.RateLimitQPS = 0      // rate limiting has its own tests
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

// session is an authenticated caller.
type session struct {
	cookie *http.Cookie
	csrf   string
	userID int64
}

func (h *harness) createUser(email string, role Role) *User {
	h.t.Helper()
	u, err := h.srv.Store().CreateUser(email, email, "correct-horse-battery", role)
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *harness) login(email string) *session {
	h.t.Helper()

	body, _ := json.Marshal(map[string]string{"email": email, "password": "correct-horse-battery"})
	req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		h.t.Fatalf("login for %s failed: %d %s", email, rec.Code, rec.Body.String())
	}

	var out struct {
		CSRF string `json:"csrf_token"`
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		h.t.Fatal(err)
	}

	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return &session{cookie: c, csrf: out.CSRF, userID: out.User.ID}
		}
	}
	h.t.Fatal("no session cookie was set")
	return nil
}

// do issues a request as a session, attaching the CSRF token.
func (h *harness) do(s *session, method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()

	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if s != nil {
		req.AddCookie(s.cookie)
		req.Header.Set(csrfHeader, s.csrf)
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// doToken issues a request authenticated by bearer token.
func (h *harness) doToken(token, method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()

	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
}

// ---- password hashing ----

func TestPasswordHashingRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hash, "correct-horse") {
		t.Fatal("the hash contains the password")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if err := VerifyPassword("correct-horse-battery", hash); err != nil {
		t.Fatalf("verifying the correct password failed: %v", err)
	}
	if err := VerifyPassword("wrong-horse-battery", hash); err == nil {
		t.Fatal("an incorrect password verified")
	}
}

func TestPasswordHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("correct-horse-battery")
	b, _ := HashPassword("correct-horse-battery")
	// Identical passwords must not produce identical hashes, or a database
	// disclosure reveals which accounts share a password.
	if a == b {
		t.Fatal("two hashes of the same password are identical: the salt is not random")
	}
}

func TestShortPasswordsRejected(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrPasswordTooShort {
		t.Fatalf("err = %v, want ErrPasswordTooShort", err)
	}
}

// ---- API tokens ----

func TestAPITokensAreStoredHashed(t *testing.T) {
	token, prefix, hash, err := NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, APITokenPrefix) {
		t.Fatalf("token %q lacks the identifying prefix", token)
	}
	if strings.Contains(hash, token) || hash == token {
		t.Fatal("the stored hash contains the token itself")
	}
	if prefix != token[:prefixLen] {
		t.Fatal("prefix does not match the token")
	}
}

// ---- authentication ----

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t)

	protected := []struct{ method, path string }{
		{"GET", "/v1/customers"},
		{"POST", "/v1/customers"},
		{"POST", "/v1/tenants"},
		{"GET", "/v1/users"},
		{"GET", "/v1/audit"},
		{"GET", "/v1/system/status"},
		{"POST", "/v1/overrides"},
	}

	for _, p := range protected {
		rec := h.do(nil, p.method, p.path, map[string]string{})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", p.method, p.path, rec.Code)
		}
	}
}

func TestLoginDoesNotRevealWhetherAnAccountExists(t *testing.T) {
	h := newHarness(t)
	h.createUser("real@example.com", RoleAdmin)

	wrongPassword := h.do(nil, "POST", "/v1/auth/login",
		map[string]string{"email": "real@example.com", "password": "not-the-password"})
	noSuchAccount := h.do(nil, "POST", "/v1/auth/login",
		map[string]string{"email": "ghost@example.com", "password": "not-the-password"})

	if wrongPassword.Code != noSuchAccount.Code {
		t.Fatalf("status codes differ: %d vs %d — this enumerates accounts",
			wrongPassword.Code, noSuchAccount.Code)
	}
	if wrongPassword.Body.String() != noSuchAccount.Body.String() {
		t.Fatalf("bodies differ:\n  %s\n  %s", wrongPassword.Body.String(), noSuchAccount.Body.String())
	}
}

func TestDisabledAccountCannotSignIn(t *testing.T) {
	h := newHarness(t)
	u := h.createUser("admin@example.com", RoleAdmin)

	if err := h.srv.Store().SetUserStatus(u.ID, "disabled"); err != nil {
		t.Fatal(err)
	}

	rec := h.do(nil, "POST", "/v1/auth/login",
		map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a disabled account", rec.Code)
	}
}

func TestLoginThrottling(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)

	for i := 0; i < h.srv.cfg.MaxLoginFailures; i++ {
		h.do(nil, "POST", "/v1/auth/login",
			map[string]string{"email": "admin@example.com", "password": "wrong"})
	}

	// Even the correct password must be refused once throttled, or the
	// throttle would only slow down attackers who never guess right.
	rec := h.do(nil, "POST", "/v1/auth/login",
		map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after repeated failures", rec.Code)
	}
}

// ---- CSRF ----

func TestMutatingSessionRequestNeedsCSRFToken(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	body, _ := json.Marshal(map[string]string{"name": "Test Customer"})
	req := httptest.NewRequest("POST", "/v1/customers", bytes.NewReader(body))
	req.AddCookie(s.cookie)
	// Deliberately omit the CSRF header.
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without a CSRF token", rec.Code)
	}
}

func TestReadsDoNotNeedCSRFToken(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	req := httptest.NewRequest("GET", "/v1/customers", nil)
	req.AddCookie(s.cookie)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a safe method should not need CSRF", rec.Code)
	}
}

func TestBearerTokensDoNotNeedCSRF(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	rec := h.do(s, "POST", "/v1/tokens", map[string]any{
		"name": "ci", "scopes": []string{"customers:write"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating a token failed: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Token string `json:"token"`
	}
	decode(t, rec, &out)

	// A browser never attaches Authorization cross-site, so there is nothing
	// for CSRF to protect against here.
	rec = h.doToken(out.Token, "POST", "/v1/customers", map[string]string{"name": "Via Token"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("token request = %d %s, want 201 without CSRF", rec.Code, rec.Body.String())
	}
}

// ---- tenant isolation, the boundary that matters commercially ----

func TestResellerCannotSeeAnotherResellersCustomers(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	h.createUser("alice@example.com", RoleReseller)
	h.createUser("bob@example.com", RoleReseller)

	alice := h.login("alice@example.com")
	bob := h.login("bob@example.com")

	rec := h.do(alice, "POST", "/v1/customers", map[string]string{"name": "Alice's Customer"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("alice could not create a customer: %d %s", rec.Code, rec.Body.String())
	}
	var created Customer
	decode(t, rec, &created)

	// Bob must not see it in a listing.
	rec = h.do(bob, "GET", "/v1/customers", nil)
	if strings.Contains(rec.Body.String(), "Alice's Customer") {
		t.Fatal("bob's customer listing contains alice's customer")
	}

	// Nor fetch it directly, and the status must be 404 rather than 403 —
	// a 403 would confirm the record exists.
	rec = h.do(bob, "GET", "/v1/customers/"+itoa(created.ID), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 so existence is not disclosed", rec.Code)
	}

	// Nor modify it.
	rec = h.do(bob, "PATCH", "/v1/customers/"+itoa(created.ID),
		map[string]string{"name": "Hijacked", "status": "active"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 on a cross-reseller update", rec.Code)
	}
}

func TestResellerCannotTouchAnotherResellersTenant(t *testing.T) {
	h := newHarness(t)
	h.createUser("alice@example.com", RoleReseller)
	h.createUser("bob@example.com", RoleReseller)

	alice := h.login("alice@example.com")
	bob := h.login("bob@example.com")

	rec := h.do(alice, "POST", "/v1/customers", map[string]string{"name": "Alice Co"})
	var cust Customer
	decode(t, rec, &cust)

	rec = h.do(alice, "POST", "/v1/tenants", map[string]any{
		"customer_id": cust.ID, "label": "phone", "days": 30,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("tenant creation failed: %d %s", rec.Code, rec.Body.String())
	}
	var tenant struct {
		RouteID string `json:"route_id"`
	}
	decode(t, rec, &tenant)

	// Every tenant route must refuse Bob identically.
	for _, probe := range []struct{ method, path string }{
		{"GET", "/v1/tenants/" + tenant.RouteID},
		{"POST", "/v1/tenants/" + tenant.RouteID + "/revoke"},
		{"POST", "/v1/tenants/" + tenant.RouteID + "/extend"},
		{"POST", "/v1/tenants/" + tenant.RouteID + "/pause"},
		{"GET", "/v1/tenants/" + tenant.RouteID + "/usage"},
		{"POST", "/v1/tenants/" + tenant.RouteID + "/ips"},
		{"POST", "/v1/tenants/" + tenant.RouteID + "/allow"},
	} {
		rec := h.do(bob, probe.method, probe.path, map[string]any{"days": 30, "domain": "x.example.com"})
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 for another reseller's tenant",
				probe.method, probe.path, rec.Code)
		}
	}

	// And Alice must still be able to use it — proving the check is scoped,
	// not simply broken.
	rec = h.do(alice, "GET", "/v1/tenants/"+tenant.RouteID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice = %d, want 200 on her own tenant", rec.Code)
	}
}

func TestUnattachedTenantIsAdminOnly(t *testing.T) {
	h := newHarness(t)
	h.createUser("alice@example.com", RoleReseller)
	alice := h.login("alice@example.com")

	// A tenant created directly in the policy store has no owner recorded.
	if err := h.srv.Policy().CreateTenant("orphan01", "", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	h.srv.Policy().Reload()

	rec := h.do(alice, "GET", "/v1/tenants/orphan01", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: an unowned tenant must not be visible to a reseller", rec.Code)
	}
}

// ---- RBAC ----

func TestResellerCannotReachAdminRoutes(t *testing.T) {
	h := newHarness(t)
	h.createUser("alice@example.com", RoleReseller)
	alice := h.login("alice@example.com")

	forbidden := []struct{ method, path string }{
		{"GET", "/v1/users"},
		{"POST", "/v1/users"},
		{"GET", "/v1/audit"},
		{"POST", "/v1/plans"},
		{"POST", "/v1/overrides"},
	}
	for _, p := range forbidden {
		rec := h.do(alice, p.method, p.path, map[string]any{"name": "x", "code": "y", "days": 1})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403 for a reseller", p.method, p.path, rec.Code)
		}
	}
}

func TestTokenCannotExceedItsOwnersRole(t *testing.T) {
	h := newHarness(t)
	h.createUser("alice@example.com", RoleReseller)
	alice := h.login("alice@example.com")

	// audit:read is admin-only, so a reseller must not be able to mint it.
	rec := h.do(alice, "POST", "/v1/tokens", map[string]any{
		"name": "sneaky", "scopes": []string{"audit:read"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when requesting a scope above the role", rec.Code)
	}
}

func TestDemotingAUserNarrowsExistingTokens(t *testing.T) {
	h := newHarness(t)
	admin := h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	rec := h.do(s, "POST", "/v1/tokens", map[string]any{
		"name": "wide", "scopes": []string{"audit:read"},
	})
	var out struct {
		Token string `json:"token"`
	}
	decode(t, rec, &out)

	if rec := h.doToken(out.Token, "GET", "/v1/audit", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin token = %d, want 200 before demotion", rec.Code)
	}

	// Demote in place. The token still carries audit:read, but the role no
	// longer permits it, and the check happens per request.
	if _, err := h.srv.Store().DB().Exec(`UPDATE users SET role='reseller' WHERE id=?`, admin.ID); err != nil {
		t.Fatal(err)
	}

	if rec := h.doToken(out.Token, "GET", "/v1/audit", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 once the role no longer allows the scope", rec.Code)
	}
}

func TestRevokedTokenStopsWorking(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	rec := h.do(s, "POST", "/v1/tokens", map[string]any{
		"name": "temp", "scopes": []string{"customers:read"},
	})
	var out struct {
		Token string `json:"token"`
		ID    int64  `json:"id"`
	}
	decode(t, rec, &out)

	if rec := h.doToken(out.Token, "GET", "/v1/customers", nil); rec.Code != http.StatusOK {
		t.Fatalf("token = %d, want 200 before revocation", rec.Code)
	}

	if rec := h.do(s, "DELETE", "/v1/tokens/"+itoa(out.ID), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rec.Code)
	}

	if rec := h.doToken(out.Token, "GET", "/v1/customers", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 after revocation", rec.Code)
	}
}

func TestTokensCannotBeCreatedFromATokenSession(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	rec := h.do(s, "POST", "/v1/tokens", map[string]any{
		"name": "first", "scopes": []string{"customers:read"},
	})
	var out struct {
		Token string `json:"token"`
	}
	decode(t, rec, &out)

	// Otherwise a stolen token could mint a replacement and outlive revocation.
	rec = h.doToken(out.Token, "POST", "/v1/tokens", map[string]any{
		"name": "second", "scopes": []string{"customers:read"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a token must not mint another token", rec.Code)
	}
}

// ---- password change ----

func TestPasswordChangeInvalidatesOtherSessions(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)

	first := h.login("admin@example.com")
	second := h.login("admin@example.com")

	rec := h.do(second, "POST", "/v1/auth/password", map[string]string{
		"current_password": "correct-horse-battery",
		"new_password":     "a-completely-new-password",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("password change = %d %s", rec.Code, rec.Body.String())
	}

	// Changing a password is how someone reacts to a compromise; it must
	// evict the intruder, not merely block future sign-ins.
	if rec := h.do(first, "GET", "/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the older session returned %d, want 401", rec.Code)
	}
}

func TestPasswordChangeRequiresCurrentPassword(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	rec := h.do(s, "POST", "/v1/auth/password", map[string]string{
		"current_password": "not-the-current-one",
		"new_password":     "a-completely-new-password",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without the current password", rec.Code)
	}
}

// ---- input validation ----

func TestDomainValidationRejectsHostileInput(t *testing.T) {
	bad := []string{
		"", "com", ".", "..", "a..b",
		"exa mple.com", "example.com/../etc", "*.example.com",
		"example.com\x00", "-example.com", "example-.com",
		"'; DROP TABLE tenants; --",
	}
	for _, d := range bad {
		if _, ok := normalizeDomainInput(d); ok {
			t.Errorf("normalizeDomainInput(%q) accepted a hostile value", d)
		}
	}

	good := map[string]string{
		"Example.COM":      "example.com",
		"api.example.com.": "api.example.com",
		"  example.com  ":  "example.com",
	}
	for in, want := range good {
		got, ok := normalizeDomainInput(in)
		if !ok || got != want {
			t.Errorf("normalizeDomainInput(%q) = %q,%v; want %q,true", in, got, ok, want)
		}
	}
}

func TestSQLInjectionInAuditFiltersIsInert(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	// If any filter were concatenated into SQL, this would error or drop data.
	rec := h.do(s, "GET", "/v1/audit?action=%27%3B+DROP+TABLE+audit_log%3B+--", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the value should be an inert parameter", rec.Code)
	}

	if _, err := h.srv.Store().CountAudit(); err != nil {
		t.Fatalf("the audit table is damaged: %v", err)
	}
}

func TestUnknownJSONFieldsAreRejected(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	// A typo should fail loudly rather than being silently ignored.
	rec := h.do(s, "POST", "/v1/customers", map[string]any{
		"name": "Test", "nmae": "typo",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field", rec.Code)
	}
}

// ---- audit ----

func TestMutationsAreAudited(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	h.do(s, "POST", "/v1/customers", map[string]string{"name": "Audited Co"})

	entries, err := h.srv.Store().ListAudit(AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}

	var sawLogin, sawCreate bool
	for _, e := range entries {
		switch e.Action {
		case ActionLogin:
			sawLogin = true
		case ActionCustomerCreate:
			sawCreate = true
			if e.ActorLabel != "admin@example.com" {
				t.Errorf("actor = %q, want the acting user's email", e.ActorLabel)
			}
		}
	}
	if !sawLogin {
		t.Error("the sign-in was not audited")
	}
	if !sawCreate {
		t.Error("the customer creation was not audited")
	}
}

func TestAuditNeverRecordsPasswords(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	s := h.login("admin@example.com")

	h.do(s, "POST", "/v1/auth/password", map[string]string{
		"current_password": "correct-horse-battery",
		"new_password":     "a-very-distinctive-password",
	})

	entries, _ := h.srv.Store().ListAudit(AuditQuery{Limit: 100})
	for _, e := range entries {
		blob := e.Detail + e.ActorLabel + e.TargetID
		if strings.Contains(blob, "a-very-distinctive-password") ||
			strings.Contains(blob, "correct-horse-battery") {
			t.Fatalf("a password reached the audit log: %+v", e)
		}
	}
}

// ---- security headers ----

func TestSecurityHeadersArePresent(t *testing.T) {
	h := newHarness(t)
	rec := h.do(nil, "GET", "/health", nil)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy is missing")
	}
}

func TestCORSDoesNotReflectArbitraryOrigins(t *testing.T) {
	h := newHarness(t) // no origins configured

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)

	// Reflecting the Origin while allowing credentials would make every site
	// on the internet a trusted origin for this API.
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty for an unlisted origin", got)
	}
}

// ---- customer self-service ----

func TestCustomerCanOnlyBindItsOwnAddress(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	admin := h.login("admin@example.com")

	rec := h.do(admin, "POST", "/v1/customers", map[string]string{"name": "Self Serve"})
	var cust Customer
	decode(t, rec, &cust)

	rec = h.do(admin, "POST", "/v1/tenants", map[string]any{
		"customer_id": cust.ID, "days": 30,
	})
	var tenant struct {
		RouteID string `json:"route_id"`
	}
	decode(t, rec, &tenant)

	// The login is explicitly linked to the customer record it represents.
	if _, err := h.srv.Store().CreateCustomerUser(
		"cust@example.com", "Cust", "correct-horse-battery", cust.ID); err != nil {
		t.Fatal(err)
	}
	customer := h.login("cust@example.com")

	// A customer nominating someone else's address would let them authorise a
	// stranger's connection through the proxy.
	rec = h.do(customer, "POST", "/v1/tenants/"+tenant.RouteID+"/ips",
		map[string]string{"ip": "203.0.113.99"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}

	var out struct {
		IP string `json:"ip"`
	}
	decode(t, rec, &out)
	if out.IP == "203.0.113.99" {
		t.Fatal("a customer bound an arbitrary address instead of its own")
	}
}

// ---- OpenAPI ----

func TestOpenAPIDocumentsEveryRoute(t *testing.T) {
	h := newHarness(t)
	rec := h.do(nil, "GET", "/openapi.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	decode(t, rec, &doc)

	if doc.OpenAPI == "" {
		t.Fatal("no openapi version declared")
	}
	for _, rt := range routeCatalog {
		methods, ok := doc.Paths[rt.Path]
		if !ok {
			t.Errorf("path %s is missing from the spec", rt.Path)
			continue
		}
		if _, ok := methods[strings.ToLower(rt.Method)]; !ok {
			t.Errorf("%s %s is missing from the spec", rt.Method, rt.Path)
		}
	}
}

// TestCustomerIDIsNotConflatedWithUserID pins a bug this suite caught during
// development.
//
// Users and customers live in separate tables with independent id sequences.
// The ownership check originally compared a users.id against a customers.id, so
// a customer-role login with user id 7 gained access to customer 7's tenants
// with no relationship between them. The link is now explicit.
func TestCustomerIDIsNotConflatedWithUserID(t *testing.T) {
	h := newHarness(t)
	h.createUser("admin@example.com", RoleAdmin)
	admin := h.login("admin@example.com")

	// Two customers. The second is the one our login will be linked to.
	rec := h.do(admin, "POST", "/v1/customers", map[string]string{"name": "Customer One"})
	var one Customer
	decode(t, rec, &one)

	rec = h.do(admin, "POST", "/v1/customers", map[string]string{"name": "Customer Two"})
	var two Customer
	decode(t, rec, &two)

	rec = h.do(admin, "POST", "/v1/tenants", map[string]any{"customer_id": one.ID, "days": 30})
	var tenantOfOne struct {
		RouteID string `json:"route_id"`
	}
	decode(t, rec, &tenantOfOne)

	user, err := h.srv.Store().CreateCustomerUser(
		"two@example.com", "Two", "correct-horse-battery", two.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Construct the collision the old code was vulnerable to: a login whose
	// user id equals a different customer's id.
	if user.ID != one.ID {
		if _, err := h.srv.Store().DB().Exec(
			`UPDATE users SET id=? WHERE id=?`, one.ID+1000, user.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := h.srv.Store().DB().Exec(
			`UPDATE users SET id=? WHERE id=?`, one.ID, one.ID+1000); err != nil {
			t.Skip("could not construct the id collision on this database")
		}
	}

	customer := h.login("two@example.com")

	// Customer Two must not reach Customer One's tenant, even though the
	// numbers now line up.
	rec = h.do(customer, "GET", "/v1/tenants/"+tenantOfOne.RouteID, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: a user id must never be read as a customer id", rec.Code)
	}

	// And must not read Customer One's record.
	rec = h.do(customer, "GET", "/v1/customers/"+itoa(one.ID), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 on another customer's record", rec.Code)
	}
}
