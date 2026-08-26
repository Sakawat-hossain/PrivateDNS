package backend

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/resolver"
)

// requireTenantAccess resolves the tenant in the path and checks the caller may
// act on it.
//
// Every tenant route goes through here. Returning the same 404 for "does not
// exist" and "not yours" is deliberate: a reseller must not be able to discover
// a competitor's tenant identifiers by probing for a different status code.
func (s *Server) requireTenantAccess(w http.ResponseWriter, r *http.Request) (string, bool) {
	routeID := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if routeID == "" || len(routeID) > 64 {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return "", false
	}

	p := PrincipalFrom(r.Context())
	ok, err := s.store.CanAccessTenant(p, routeID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return "", false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "tenant not found")
		return "", false
	}
	return routeID, true
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())

	var in struct {
		CustomerID int64  `json:"customer_id"`
		Label      string `json:"label"`
		PlanCode   string `json:"plan_code"`
		Days       int    `json:"days"`
		Minutes    int    `json:"minutes"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if in.CustomerID == 0 {
		writeError(w, http.StatusBadRequest, "customer_id is required")
		return
	}
	allowed, err := s.store.CanAccessCustomer(p, in.CustomerID)
	if errors.Is(err, ErrNotFound) || (err == nil && !allowed) {
		writeError(w, http.StatusNotFound, "customer not found")
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	// A plan is the normal path; explicit days/minutes exist for trials and
	// manual adjustments.
	var d time.Duration
	if in.PlanCode != "" {
		plan, err := s.store.PlanByCode(in.PlanCode)
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusBadRequest, "unknown plan_code")
			return
		}
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "internal error", err)
			return
		}
		if !plan.Active {
			writeError(w, http.StatusBadRequest, "plan is not active")
			return
		}
		d = plan.Duration()
	} else {
		d = time.Duration(in.Days)*24*time.Hour + time.Duration(in.Minutes)*time.Minute
	}
	if d <= 0 {
		writeError(w, http.StatusBadRequest, "a plan_code, days or minutes is required")
		return
	}

	routeID, err := resolver.NewRouteID()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	expires := time.Now().Add(d).Unix()

	if err := s.policy.CreateTenant(routeID, in.Label, expires); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	if err := s.store.AttachTenant(routeID, in.CustomerID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionTenantCreate, "tenant", routeID, map[string]any{
		"customer_id": in.CustomerID, "expires_at": expires, "plan": in.PlanCode,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"route_id":    routeID,
		"hostname":    routeID + "." + s.cfg.BaseDomain,
		"customer_id": in.CustomerID,
		"expires_at":  expires,
	})
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	t := s.policy.Tenant(routeID)
	if t == nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}

	now := time.Now().Unix()
	customerID, _ := s.store.TenantOwner(routeID)

	writeJSON(w, http.StatusOK, map[string]any{
		"route_id":    t.RouteID,
		"hostname":    t.RouteID + "." + s.cfg.BaseDomain,
		"label":       t.Label,
		"status":      t.Status,
		"expires_at":  t.ExpiresAt,
		"active":      t.Active(now),
		"filtering":   t.Filtering(now),
		"customer_id": customerID,
	})
}

func (s *Server) handleRevokeTenant(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	if err := s.policy.SetStatus(routeID, "suspended"); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionTenantRevoke, "tenant", routeID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "suspended"})
}

func (s *Server) handleExtendTenant(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	var in struct {
		PlanCode string `json:"plan_code"`
		Days     int    `json:"days"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var d time.Duration
	if in.PlanCode != "" {
		plan, err := s.store.PlanByCode(in.PlanCode)
		if err != nil {
			writeError(w, http.StatusBadRequest, "unknown plan_code")
			return
		}
		d = plan.Duration()
	} else {
		d = time.Duration(in.Days) * 24 * time.Hour
	}
	if d <= 0 {
		writeError(w, http.StatusBadRequest, "a plan_code or days is required")
		return
	}

	// Extend from the existing expiry when it is still in the future, so
	// renewing early does not cost the customer the remaining time.
	base := time.Now()
	if t := s.policy.Tenant(routeID); t != nil && t.ExpiresAt > base.Unix() {
		base = time.Unix(t.ExpiresAt, 0)
	}
	expires := base.Add(d).Unix()

	if err := s.policy.Extend(routeID, expires); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.SetStatus(routeID, "active")
	_ = s.policy.Reload()

	s.audit(r, ActionTenantExtend, "tenant", routeID, map[string]any{"expires_at": expires})
	writeJSON(w, http.StatusOK, map[string]any{"expires_at": expires, "status": "active"})
}

func (s *Server) handlePauseTenant(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	var in struct {
		Minutes int `json:"minutes"`
	}
	_ = decodeJSON(r, &in)
	if in.Minutes <= 0 {
		in.Minutes = 5
	}
	// Bounded so "pause filtering" cannot become "disable filtering forever"
	// through the customer-facing control.
	if in.Minutes > 240 {
		in.Minutes = 240
	}

	until := time.Now().Add(time.Duration(in.Minutes) * time.Minute).Unix()
	if err := s.policy.PauseFiltering(routeID, until); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionTenantPause, "tenant", routeID, map[string]any{"minutes": in.Minutes})
	writeJSON(w, http.StatusOK, map[string]any{"paused_until": until})
}

func (s *Server) handleTenantUsage(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	u, found := s.policy.Usage(routeID)
	if !found {
		u = resolver.Usage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"route_id": routeID, "queries": u.Queries, "blocked": u.Blocked,
		"overridden": u.Overridden, "throttled": u.Throttled, "last_seen": u.LastSeen,
	})
}

// ---- source-IP binding ----

func (s *Server) handleRegisterIP(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	var in struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// An empty ip means "the address I am calling from", which is what the
	// customer portal's one-tap control sends. It is also the only form a
	// customer should be able to use: letting them nominate an arbitrary
	// address would let one customer authorise someone else's connection.
	ip := strings.TrimSpace(in.IP)
	p := PrincipalFrom(r.Context())
	if ip == "" || p.Role == RoleCustomer {
		ip = clientIP(r)
	}
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}

	if err := s.policy.RegisterIP(routeID, ip); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionIPRegister, "tenant", routeID, map[string]any{"ip": ip})
	writeJSON(w, http.StatusOK, map[string]any{"route_id": routeID, "ip": ip})
}

func (s *Server) handleReleaseIP(w http.ResponseWriter, r *http.Request) {
	routeID, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}

	ip, err := url.PathUnescape(r.PathValue("ip"))
	if err != nil || net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}

	if err := s.policy.ReleaseIP(ip); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	_ = s.policy.Reload()

	s.audit(r, ActionIPRelease, "tenant", routeID, map[string]any{"ip": ip})
	w.WriteHeader(http.StatusNoContent)
}

// ---- plans ----

func (s *Server) handleListPlans(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	plans, err := s.store.ListPlans(p.IsAdmin())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": plans})
}

func (s *Server) handleCreatePlan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code       string `json:"code"`
		Name       string `json:"name"`
		Days       int    `json:"days"`
		Minutes    int    `json:"minutes"`
		PriceMinor int64  `json:"price_minor"`
		Currency   string `json:"currency"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if in.Code == "" || in.Name == "" {
		writeError(w, http.StatusBadRequest, "code and name are required")
		return
	}
	if in.Days <= 0 && in.Minutes <= 0 {
		writeError(w, http.StatusBadRequest, "a plan must grant some duration")
		return
	}

	plan, err := s.store.CreatePlan(in.Code, in.Name, in.Days, in.Minutes, in.PriceMinor, in.Currency)
	if errors.Is(err, ErrDuplicate) {
		writeError(w, http.StatusConflict, "a plan with that code already exists")
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
		return
	}

	s.audit(r, ActionPlanCreate, "plan", in.Code, map[string]any{"days": in.Days})
	writeJSON(w, http.StatusCreated, plan)
}

// audit records a state change against the calling principal.
func (s *Server) audit(r *http.Request, action, targetType, targetID string, detail map[string]any) {
	p := PrincipalFrom(r.Context())
	e := AuditEntry{
		ActorType: "anonymous",
		Action:    action, TargetType: targetType, TargetID: targetID,
		Detail: AuditDetail(detail), IP: clientIP(r),
		RequestID: RequestIDFrom(r.Context()),
	}
	if p != nil {
		e.ActorType = p.Kind
		e.ActorID = strconv.FormatInt(p.UserID, 10)
		e.ActorLabel = p.Label()
	}
	s.store.Record(e)
}
