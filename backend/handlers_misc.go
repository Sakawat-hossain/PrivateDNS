package backend

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---- users ----

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	role := Role(in.Role)
	if !role.Valid() {
		writeError(w, http.StatusBadRequest, "role must be admin, reseller or customer")
		return
	}

	user, err := s.store.CreateUser(in.Email, in.Name, in.Password, role)
	switch {
	case errors.Is(err, ErrDuplicate):
		writeError(w, http.StatusConflict, "an account with that email already exists")
		return
	case errors.Is(err, ErrPasswordTooShort):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	s.audit(r, ActionUserCreate, "user", strconv.FormatInt(user.ID, 10),
		map[string]any{"email": user.Email, "role": string(role)})
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleSetUserStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var in struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if in.Status != "active" && in.Status != "disabled" {
		writeError(w, http.StatusBadRequest, "status must be active or disabled")
		return
	}

	p := PrincipalFrom(r.Context())
	if p.UserID == id && in.Status == "disabled" {
		// Locking yourself out of the only admin account is unrecoverable
		// without database surgery.
		writeError(w, http.StatusBadRequest, "you cannot disable your own account")
		return
	}

	if err := s.store.SetUserStatus(id, in.Status); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	if in.Status == "disabled" {
		// Disabling must evict, not just prevent future sign-in.
		_ = s.store.DeleteUserSessions(id)
	}

	s.audit(r, ActionUserUpdate, "user", strconv.FormatInt(id, 10),
		map[string]any{"status": in.Status})
	writeJSON(w, http.StatusOK, map[string]string{"status": in.Status})
}

// ---- customers ----

func (s *Server) handleListCustomers(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	customers, err := s.store.ListCustomers(p, limit, offset)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"customers": customers})
}

func (s *Server) handleCreateCustomer(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())

	var in struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Phone   string `json:"phone"`
		OwnerID int64  `json:"owner_id"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// A reseller always owns what it creates. Honouring a supplied owner_id
	// would let one reseller plant customers under another.
	owner := p.UserID
	if p.IsAdmin() && in.OwnerID != 0 {
		owner = in.OwnerID
	}

	c, err := s.store.CreateCustomer(in.Email, in.Name, in.Phone, owner)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	s.audit(r, ActionCustomerCreate, "customer", strconv.FormatInt(c.ID, 10),
		map[string]any{"name": c.Name, "owner_id": owner})
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) handleGetCustomer(w http.ResponseWriter, r *http.Request) {
	id, ok := s.customerFromPath(w, r)
	if !ok {
		return
	}

	c, err := s.store.CustomerByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "customer not found")
		return
	}
	tenants, _ := s.store.TenantsForCustomer(id)

	writeJSON(w, http.StatusOK, map[string]any{"customer": c, "tenants": tenants})
}

func (s *Server) handleUpdateCustomer(w http.ResponseWriter, r *http.Request) {
	id, ok := s.customerFromPath(w, r)
	if !ok {
		return
	}

	var in struct {
		Name   string `json:"name"`
		Phone  string `json:"phone"`
		Notes  string `json:"notes"`
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if in.Status == "" {
		in.Status = "active"
	}
	if in.Status != "active" && in.Status != "disabled" {
		writeError(w, http.StatusBadRequest, "status must be active or disabled")
		return
	}

	if err := s.store.UpdateCustomer(id, in.Name, in.Phone, in.Notes, in.Status); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	s.audit(r, ActionCustomerUpdate, "customer", strconv.FormatInt(id, 10),
		map[string]any{"status": in.Status})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// customerFromPath resolves and authorises a customer, returning the same 404
// whether the record is missing or simply not the caller's.
func (s *Server) customerFromPath(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid customer id")
		return 0, false
	}

	p := PrincipalFrom(r.Context())
	ok, err := s.store.CanAccessCustomer(p, id)
	if errors.Is(err, ErrNotFound) || (err == nil && !ok) {
		writeError(w, http.StatusNotFound, "customer not found")
		return 0, false
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return 0, false
	}
	return id, true
}

// ---- policy ----

func (s *Server) handleAddAllow(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	var in struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	domain, ok := normalizeDomainInput(in.Domain)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}

	if err := s.policy.AddAllow(routeID, domain); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionAllowAdd, "tenant", routeID, map[string]any{"domain": domain})
	writeJSON(w, http.StatusOK, map[string]any{"route_id": routeID, "domain": domain})
}

func (s *Server) handleRemoveAllow(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	raw, err := url.PathUnescape(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	domain, ok := normalizeDomainInput(raw)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}

	if err := s.policy.RemoveAllow(routeID, domain); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionAllowRemove, "tenant", routeID, map[string]any{"domain": domain})
	w.WriteHeader(http.StatusNoContent)
}

// handleSetOverride writes an answer override.
//
// Overrides are administrator-only. A global override redirects a domain for
// every tenant, and a tenant-scoped one silently changes where a customer's
// traffic goes — neither is something a reseller should be able to do
// unilaterally.
func (s *Server) handleSetOverride(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if !p.IsAdmin() {
		writeError(w, http.StatusForbidden, "administrator role required to set overrides")
		return
	}

	var in struct {
		RouteID string `json:"route_id"`
		Domain  string `json:"domain"`
		Answer  string `json:"answer"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	domain, ok := normalizeDomainInput(in.Domain)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(in.Answer))
	if err != nil {
		writeError(w, http.StatusBadRequest, "answer must be an IP address")
		return
	}

	scope := in.RouteID
	if scope == "" {
		scope = "*"
	}

	if err := s.policy.SetOverride(scope, domain, addr.String()); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionOverrideSet, "override", domain,
		map[string]any{"answer": addr.String(), "scope": scope})
	writeJSON(w, http.StatusOK, map[string]any{
		"domain": domain, "answer": addr.String(), "scope": scope,
	})
}

func (s *Server) handleRemoveOverride(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if !p.IsAdmin() {
		writeError(w, http.StatusForbidden, "administrator role required")
		return
	}

	raw, err := url.PathUnescape(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	domain, ok := normalizeDomainInput(raw)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}

	scope := r.URL.Query().Get("route_id")
	if scope == "" {
		scope = "*"
	}

	if err := s.policy.RemoveOverride(scope, domain); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionOverrideRemove, "override", domain, map[string]any{"scope": scope})
	w.WriteHeader(http.StatusNoContent)
}

// normalizeDomainInput validates a caller-supplied domain.
//
// These values reach the resolver's policy tables and are matched against every
// query, so a name containing a wildcard, a slash or whitespace could produce a
// rule that matches far more than intended.
func normalizeDomainInput(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ".")))
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return "", false
		}
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
	}
	return s, true
}

// ---- API tokens ----

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tokens, err := s.store.ListAPITokens(p.UserID, p.IsAdmin())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Issuing a long-lived credential from a stolen API token would let an
	// attacker outlive the token they compromised.
	if p.Kind != "session" {
		writeError(w, http.StatusForbidden, "tokens may only be created from a signed-in session")
		return
	}

	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		Days   int      `json:"days"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(in.Scopes) == 0 {
		writeError(w, http.StatusBadRequest, "at least one scope is required")
		return
	}

	// A token can never exceed its owner's role. Requesting more is an error
	// rather than a silent trim, so the caller learns their token is narrower
	// than they asked for.
	scopes := map[Scope]bool{}
	for _, raw := range in.Scopes {
		sc := Scope(strings.TrimSpace(raw))
		if !ValidScope(sc) {
			writeError(w, http.StatusBadRequest, "unknown scope: "+raw)
			return
		}
		if !RoleHasScope(p.Role, sc) {
			writeError(w, http.StatusForbidden, "your role cannot grant scope: "+raw)
			return
		}
		scopes[sc] = true
	}

	var ttl time.Duration
	if in.Days > 0 {
		ttl = time.Duration(in.Days) * 24 * time.Hour
	}

	plaintext, tok, err := s.store.CreateAPIToken(p.UserID, in.Name, scopes, ttl)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	s.audit(r, ActionTokenCreate, "token", strconv.FormatInt(tok.ID, 10),
		map[string]any{"name": in.Name, "scopes": tok.Scopes})

	writeJSON(w, http.StatusCreated, map[string]any{
		// The only time the value is ever returned. Only its hash is stored,
		// so it cannot be recovered later.
		"token":   plaintext,
		"warning": "store this now; it cannot be shown again",
		"id":      tok.ID, "prefix": tok.Prefix, "name": tok.Name,
		"scopes": tok.Scopes, "expires_at": tok.ExpiresAt,
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}

	err = s.store.RevokeAPIToken(id, p.UserID, p.IsAdmin())
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrForbidden):
		writeError(w, http.StatusNotFound, "token not found")
		return
	case err != nil:
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	s.audit(r, ActionTokenRevoke, "token", strconv.FormatInt(id, 10), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- system and audit ----

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	schema, _ := s.policy.SchemaVersion()
	auditCount, _ := s.store.CountAudit()

	writeJSON(w, http.StatusOK, map[string]any{
		"version":        Version,
		"schema_version": schema,
		"uptime":         time.Since(s.started).Truncate(time.Second).String(),
		"tenants":        s.policy.TenantCount(),
		"audit_entries":  auditCount,
		"base_domain":    s.cfg.BaseDomain,
	})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	until, _ := strconv.ParseInt(q.Get("until"), 10, 64)

	entries, err := s.store.ListAudit(AuditQuery{
		Action:     q.Get("action"),
		ActorID:    q.Get("actor_id"),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
		Since:      since, Until: until,
		Limit: limit, Offset: offset,
	})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// ---- health ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 2*time.Second)
	defer cancel()

	if err := s.policy.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "checks": []map[string]any{
				{"name": "database", "ok": false, "detail": "unreachable"},
			},
		})
		return
	}

	schema, err := s.policy.SchemaVersion()
	schemaOK := err == nil && schema == resolverSchemaVersion()

	writeJSON(w, statusFor(schemaOK), map[string]any{
		"ok": schemaOK,
		"checks": []map[string]any{
			{"name": "database", "ok": true, "detail": "reachable"},
			{"name": "schema", "ok": schemaOK, "detail": "version " + strconv.Itoa(schema)},
		},
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": Version,
		"uptime":  time.Since(s.started).Truncate(time.Second).String(),
	})
}

func statusFor(ok bool) int {
	if ok {
		return http.StatusOK
	}
	return http.StatusServiceUnavailable
}
