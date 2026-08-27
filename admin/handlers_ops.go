package admin

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"net/http"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
	"github.com/Sakawat-hossain/PrivateDNS/resolver"
)

// ---- tenants ----

// tenantAccess resolves the tenant in the path and checks the operator may act
// on it. As elsewhere, "not yours" and "does not exist" answer identically.
func (s *Server) tenantAccess(w http.ResponseWriter, r *http.Request, sess *opSession) (string, bool) {
	routeID := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if routeID == "" || len(routeID) > 64 {
		s.renderError(w, r, http.StatusBadRequest, "Invalid tenant id.")
		return "", false
	}

	ok, err := s.store.CanAccessTenant(sess.principal(), routeID)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Something went wrong.")
		return "", false
	}
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Tenant not found.")
		return "", false
	}
	return routeID, true
}

func (s *Server) handleTenantIssue(w http.ResponseWriter, r *http.Request, sess *opSession) {
	customerID, ok := s.customerAccess(w, r, sess)
	if !ok {
		return
	}
	back := "/customers/" + strconv.FormatInt(customerID, 10)

	var d time.Duration
	if code := strings.TrimSpace(r.PostFormValue("plan_code")); code != "" {
		plan, err := s.store.PlanByCode(code)
		if err != nil || !plan.Active {
			redirect(w, r, back, "err")
			return
		}
		d = plan.Duration()
	} else {
		days, _ := strconv.Atoi(r.PostFormValue("days"))
		d = time.Duration(days) * 24 * time.Hour
	}
	if d <= 0 {
		redirect(w, r, back, "err")
		return
	}

	routeID, err := resolver.NewRouteID()
	if err != nil {
		redirect(w, r, back, "err")
		return
	}
	expires := time.Now().Add(d).Unix()

	if err := s.policy.CreateTenant(routeID, strings.TrimSpace(r.PostFormValue("label")), expires); err != nil {
		s.log.Error("tenant create failed", "err", err)
		redirect(w, r, back, "err")
		return
	}
	if err := s.store.AttachTenant(routeID, customerID); err != nil {
		s.log.Error("tenant attach failed", "err", err)
		redirect(w, r, back, "err")
		return
	}
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionTenantCreate, "tenant", routeID,
		map[string]any{"customer_id": customerID, "expires_at": expires})
	redirect(w, r, back, "created")
}

type tenantDetail struct {
	RouteID    string
	Hostname   string
	Label      string
	Status     string
	Active     bool
	Filtering  bool
	ExpiresAt  int64
	PausedTill int64
	CustomerID int64
	Queries    int64
	Blocked    int64
	Overridden int64
	Throttled  int64
	LastSeen   int64
	Allowlist  []string
	BoundIPs   []string
}

func (s *Server) handleTenantDetail(w http.ResponseWriter, r *http.Request, sess *opSession) {
	routeID, ok := s.tenantAccess(w, r, sess)
	if !ok {
		return
	}

	t := s.policy.Tenant(routeID)
	if t == nil {
		s.renderError(w, r, http.StatusNotFound, "Tenant not found.")
		return
	}

	now := time.Now().Unix()
	d := &tenantDetail{
		RouteID: routeID, Hostname: routeID + "." + s.cfg.BaseDomain,
		Label: t.Label, Status: t.Status,
		Active: t.Active(now), Filtering: t.Filtering(now),
		ExpiresAt: t.ExpiresAt, PausedTill: t.PausedUntil,
	}
	d.CustomerID, _ = s.store.TenantOwner(routeID)

	if u, ok := s.policy.Usage(routeID); ok {
		d.Queries, d.Blocked = u.Queries, u.Blocked
		d.Overridden, d.Throttled, d.LastSeen = u.Overridden, u.Throttled, u.LastSeen
	}
	d.Allowlist, _ = s.policy.ListAllow(routeID)
	d.BoundIPs, _ = s.policy.ListIPs(routeID)

	p := page{Title: routeID, Nav: "customers", Tenant: d}
	p.Flash, p.FlashKind = flash(r)
	p.Plans, _ = s.store.ListPlans(sess.isAdmin())
	s.render(w, r, "tenant.html", p)
}

func (s *Server) handleTenantRevoke(w http.ResponseWriter, r *http.Request, sess *opSession) {
	routeID, ok := s.tenantAccess(w, r, sess)
	if !ok {
		return
	}
	if err := s.policy.SetStatus(routeID, "suspended"); err != nil {
		redirect(w, r, "/tenants/"+routeID, "err")
		return
	}
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionTenantRevoke, "tenant", routeID, nil)
	redirect(w, r, "/tenants/"+routeID, "revoked")
}

func (s *Server) handleTenantExtend(w http.ResponseWriter, r *http.Request, sess *opSession) {
	routeID, ok := s.tenantAccess(w, r, sess)
	if !ok {
		return
	}

	var d time.Duration
	if code := strings.TrimSpace(r.PostFormValue("plan_code")); code != "" {
		plan, err := s.store.PlanByCode(code)
		if err != nil {
			redirect(w, r, "/tenants/"+routeID, "err")
			return
		}
		d = plan.Duration()
	} else {
		days, _ := strconv.Atoi(r.PostFormValue("days"))
		d = time.Duration(days) * 24 * time.Hour
	}
	if d <= 0 {
		redirect(w, r, "/tenants/"+routeID, "err")
		return
	}

	// Renew from the existing expiry when it is still ahead, so renewing early
	// does not cost the customer their remaining time.
	base := time.Now()
	if t := s.policy.Tenant(routeID); t != nil && t.ExpiresAt > base.Unix() {
		base = time.Unix(t.ExpiresAt, 0)
	}
	expires := base.Add(d).Unix()

	if err := s.policy.Extend(routeID, expires); err != nil {
		redirect(w, r, "/tenants/"+routeID, "err")
		return
	}
	_ = s.policy.SetStatus(routeID, "active")
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionTenantExtend, "tenant", routeID,
		map[string]any{"expires_at": expires})
	redirect(w, r, "/tenants/"+routeID, "extended")
}

// ---- allowlist ----

func (s *Server) handleAllowAdd(w http.ResponseWriter, r *http.Request, sess *opSession) {
	routeID, ok := s.tenantAccess(w, r, sess)
	if !ok {
		return
	}

	domain, valid := validDomain(r.PostFormValue("domain"))
	if !valid {
		redirect(w, r, "/tenants/"+routeID, "err")
		return
	}

	if err := s.policy.AddAllow(routeID, domain); err != nil {
		redirect(w, r, "/tenants/"+routeID, "err")
		return
	}
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionAllowAdd, "tenant", routeID, map[string]any{"domain": domain})
	redirect(w, r, "/tenants/"+routeID, "allowed")
}

func (s *Server) handleAllowRemove(w http.ResponseWriter, r *http.Request, sess *opSession) {
	routeID, ok := s.tenantAccess(w, r, sess)
	if !ok {
		return
	}

	domain, valid := validDomain(r.PostFormValue("domain"))
	if !valid {
		redirect(w, r, "/tenants/"+routeID, "err")
		return
	}

	if err := s.policy.RemoveAllow(routeID, domain); err != nil {
		redirect(w, r, "/tenants/"+routeID, "err")
		return
	}
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionAllowRemove, "tenant", routeID, map[string]any{"domain": domain})
	redirect(w, r, "/tenants/"+routeID, "removed")
}

// ---- overrides, administrators only ----

type overrideRow struct {
	Scope  string
	Domain string
	Answer string
}

func (s *Server) handlePolicyPage(w http.ResponseWriter, r *http.Request, sess *opSession) {
	p := page{Title: "Routing", Nav: "policy"}
	p.Flash, p.FlashKind = flash(r)

	rows, err := s.policy.ListOverrides()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load overrides.")
		return
	}
	for _, o := range rows {
		p.Overrides = append(p.Overrides, overrideRow{Scope: o.RouteID, Domain: o.Domain, Answer: o.Answer})
	}

	s.render(w, r, "policy.html", p)
}

// handleOverrideSet writes an answer override.
//
// Administrators only. A global override silently changes where every
// customer's traffic for a domain goes, which is not a reseller's decision to
// make.
func (s *Server) handleOverrideSet(w http.ResponseWriter, r *http.Request, sess *opSession) {
	domain, ok := validDomain(r.PostFormValue("domain"))
	if !ok {
		redirect(w, r, "/policy", "err")
		return
	}
	answer, ok := validAddr(r.PostFormValue("answer"))
	if !ok {
		redirect(w, r, "/policy", "err")
		return
	}

	scope := strings.TrimSpace(r.PostFormValue("route_id"))
	if scope == "" {
		scope = "*"
	}

	if err := s.policy.SetOverride(scope, domain, answer); err != nil {
		redirect(w, r, "/policy", "err")
		return
	}
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionOverrideSet, "override", domain,
		map[string]any{"answer": answer, "scope": scope})
	redirect(w, r, "/policy", "override")
}

func (s *Server) handleOverrideRemove(w http.ResponseWriter, r *http.Request, sess *opSession) {
	domain, ok := validDomain(r.PostFormValue("domain"))
	if !ok {
		redirect(w, r, "/policy", "err")
		return
	}
	scope := strings.TrimSpace(r.PostFormValue("route_id"))
	if scope == "" {
		scope = "*"
	}

	if err := s.policy.RemoveOverride(scope, domain); err != nil {
		redirect(w, r, "/policy", "err")
		return
	}
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionOverrideRemove, "override", domain, map[string]any{"scope": scope})
	redirect(w, r, "/policy", "removed")
}

// ---- false-positive triage ----

type triageRow struct {
	RouteID  string
	Hostname string
	Customer string
	PausedAt int64
	Pauses   int64
}

// handleTriage lists tenants that recently paused filtering.
//
// A customer reaching for the pause button is the clearest signal available
// that something legitimate is being blocked — they were trying to use a site
// and could not. Surfacing those here turns an invisible frustration into a
// queue someone can work through and fix with an allowlist entry.
func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request, sess *opSession) {
	p := page{Title: "Triage", Nav: "triage"}
	p.Flash, p.FlashKind = flash(r)

	entries, err := s.store.ListAudit(backend.AuditQuery{
		Action: backend.ActionTenantPause,
		Since:  time.Now().Add(-7 * 24 * time.Hour).Unix(),
		Limit:  200,
	})
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load the triage queue.")
		return
	}

	seen := map[string]*triageRow{}
	var order []string

	for _, e := range entries {
		if e.TargetType != "tenant" || e.TargetID == "" {
			continue
		}
		// Row-level visibility: a reseller sees only its own customers' pauses.
		if ok, err := s.store.CanAccessTenant(sess.principal(), e.TargetID); err != nil || !ok {
			continue
		}

		row, exists := seen[e.TargetID]
		if !exists {
			row = &triageRow{
				RouteID:  e.TargetID,
				Hostname: e.TargetID + "." + s.cfg.BaseDomain,
				PausedAt: e.At,
			}
			if cid, err := s.store.TenantOwner(e.TargetID); err == nil {
				if c, err := s.store.CustomerByID(cid); err == nil {
					row.Customer = c.Name
				}
			}
			seen[e.TargetID] = row
			order = append(order, e.TargetID)
		}
		row.Pauses++
	}

	for _, id := range order {
		p.Triage = append(p.Triage, *seen[id])
	}

	s.render(w, r, "triage.html", p)
}

func (s *Server) handleTriageAllow(w http.ResponseWriter, r *http.Request, sess *opSession) {
	routeID := strings.ToLower(strings.TrimSpace(r.PostFormValue("route_id")))
	ok, err := s.store.CanAccessTenant(sess.principal(), routeID)
	if err != nil || !ok {
		redirect(w, r, "/triage", "err")
		return
	}

	domain, valid := validDomain(r.PostFormValue("domain"))
	if !valid {
		redirect(w, r, "/triage", "err")
		return
	}

	// Global by default: a false positive affects everyone, so fixing it for
	// one customer leaves the same complaint waiting from the rest.
	scope := routeID
	if r.PostFormValue("global") == "on" && sess.isAdmin() {
		scope = "*"
	}

	if err := s.policy.AddAllow(scope, domain); err != nil {
		redirect(w, r, "/triage", "err")
		return
	}
	_ = s.policy.Reload()

	s.audit(r, sess, backend.ActionAllowAdd, "tenant", routeID,
		map[string]any{"domain": domain, "scope": scope, "source": "triage"})
	redirect(w, r, "/triage", "allowed")
}

// ---- system, administrators only ----

type systemView struct {
	Resolver      *resolverStatus
	SchemaVersion int
	Uptime        string
	AuditEntries  int64
	Users         int
	BaseDomain    string
	Upstreams     []string
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request, sess *opSession) {
	schema, _ := s.policy.SchemaVersion()
	auditCount, _ := s.store.CountAudit()
	users, _ := s.store.CountUsers()

	p := page{Title: "System", Nav: "system", System: &systemView{
		Resolver:      s.resolverStatus(),
		SchemaVersion: schema,
		Uptime:        time.Since(s.started).Truncate(time.Second).String(),
		AuditEntries:  auditCount,
		Users:         users,
		BaseDomain:    s.cfg.BaseDomain,
	}}
	p.Flash, p.FlashKind = flash(r)
	s.render(w, r, "system.html", p)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, sess *opSession) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	entries, err := s.store.ListAudit(backend.AuditQuery{
		Action:     q.Get("action"),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
		Limit:      limit, Offset: offset,
	})
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load the audit log.")
		return
	}

	p := page{Title: "Audit", Nav: "audit", Audit: entries, Query: map[string]string{
		"action": q.Get("action"), "target_id": q.Get("target_id"),
	}}
	s.render(w, r, "audit.html", p)
}

// ---- API tokens ----

func (s *Server) handleTokenList(w http.ResponseWriter, r *http.Request, sess *opSession) {
	tokens, err := s.store.ListAPITokens(sess.user.ID, sess.isAdmin())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load tokens.")
		return
	}

	p := page{Title: "API tokens", Nav: "tokens", Tokens: tokens}
	p.Flash, p.FlashKind = flash(r)
	// Shown exactly once, immediately after creation, then never again.
	// Reading removes it, so a refresh does not show it a second time.
	p.NewToken = s.tokens.take(sess.token)
	s.render(w, r, "tokens.html", p)
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request, sess *opSession) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		redirect(w, r, "/tokens", "err")
		return
	}

	scopes := map[backend.Scope]bool{}
	for _, raw := range r.PostForm["scopes"] {
		sc := backend.Scope(strings.TrimSpace(raw))
		if !backend.ValidScope(sc) {
			redirect(w, r, "/tokens", "err")
			return
		}
		// A token can never exceed its owner's role.
		if !backend.RoleHasScope(sess.user.Role, sc) {
			redirect(w, r, "/tokens", "err")
			return
		}
		scopes[sc] = true
	}
	if len(scopes) == 0 {
		redirect(w, r, "/tokens", "err")
		return
	}

	var ttl time.Duration
	if days, _ := strconv.Atoi(r.PostFormValue("days")); days > 0 {
		ttl = time.Duration(days) * 24 * time.Hour
	}

	plaintext, tok, err := s.store.CreateAPIToken(sess.user.ID, name, scopes, ttl)
	if err != nil {
		redirect(w, r, "/tokens", "err")
		return
	}

	s.audit(r, sess, backend.ActionTokenCreate, "token",
		strconv.FormatInt(tok.ID, 10), map[string]any{"name": name, "scopes": tok.Scopes})

	// Held server-side for one redirect rather than placed in the URL. A
	// query string reaches browser history, Referer headers and every access
	// log between here and the operator.
	s.tokens.put(sess.token, plaintext)
	redirect(w, r, "/tokens", "created")
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request, sess *opSession) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		redirect(w, r, "/tokens", "err")
		return
	}

	err = s.store.RevokeAPIToken(id, sess.user.ID, sess.isAdmin())
	if errors.Is(err, backend.ErrNotFound) || errors.Is(err, backend.ErrForbidden) {
		redirect(w, r, "/tokens", "err")
		return
	}
	if err != nil {
		redirect(w, r, "/tokens", "err")
		return
	}

	s.audit(r, sess, backend.ActionTokenRevoke, "token", strconv.FormatInt(id, 10), nil)
	redirect(w, r, "/tokens", "revoked")
}

// ---- users, administrators only ----

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request, sess *opSession) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load accounts.")
		return
	}
	p := page{Title: "Accounts", Nav: "users", Users: users}
	p.Flash, p.FlashKind = flash(r)
	s.render(w, r, "users.html", p)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request, sess *opSession) {
	role := backend.Role(r.PostFormValue("role"))
	if role != backend.RoleAdmin && role != backend.RoleReseller {
		// Customer accounts are created alongside a customer record, not here.
		redirect(w, r, "/users", "err")
		return
	}

	user, err := s.store.CreateUser(
		strings.TrimSpace(r.PostFormValue("email")),
		strings.TrimSpace(r.PostFormValue("name")),
		r.PostFormValue("password"), role)
	if err != nil {
		s.log.Warn("operator account create failed", "err", err)
		redirect(w, r, "/users", "err")
		return
	}

	s.audit(r, sess, backend.ActionUserCreate, "user",
		strconv.FormatInt(user.ID, 10), map[string]any{"role": string(role)})
	redirect(w, r, "/users", "created")
}

func (s *Server) handleUserStatus(w http.ResponseWriter, r *http.Request, sess *opSession) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		redirect(w, r, "/users", "err")
		return
	}

	status := r.PostFormValue("status")
	if status != "active" && status != "disabled" {
		redirect(w, r, "/users", "err")
		return
	}
	if id == sess.user.ID && status == "disabled" {
		// Locking yourself out of the only administrator account is
		// unrecoverable without database surgery.
		redirect(w, r, "/users", "err")
		return
	}

	if err := s.store.SetUserStatus(id, status); err != nil {
		redirect(w, r, "/users", "err")
		return
	}
	if status == "disabled" {
		// Disabling must evict, not merely prevent the next sign-in.
		_ = s.store.DeleteUserSessions(id)
	}

	s.audit(r, sess, backend.ActionUserUpdate, "user",
		strconv.FormatInt(id, 10), map[string]any{"status": status})
	redirect(w, r, "/users", "updated")
}
