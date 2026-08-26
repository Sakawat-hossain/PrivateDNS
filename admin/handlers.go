package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Sakawat-hossain/PrivateDNS/backend"
)

func fsSub(f fs.FS, dir string) (fs.FS, error) { return fs.Sub(f, dir) }

// page is what every template receives.
type page struct {
	Title     string
	Brand     string
	Version   string
	CSRF      string
	Flash     string
	FlashKind string
	SignedIn  bool
	IsAdmin   bool
	Email     string
	Nav       string

	Overview   *overview
	Customers  []customerRow
	Customer   *customerDetail
	Tenant     *tenantDetail
	Overrides  []overrideRow
	Triage     []triageRow
	System     *systemView
	Audit      []*backend.AuditEntry
	Tokens     []*backend.APIToken
	Users      []*backend.User
	NewToken   string
	Plans      []*backend.Plan
	BaseDomain string
	Query      map[string]string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, tmpl string, p page) {
	if sess := s.sessionFrom(r); sess != nil {
		p.SignedIn = true
		p.IsAdmin = sess.isAdmin()
		p.Email = sess.user.Email
		if p.CSRF == "" {
			p.CSRF = sess.csrf
		}
	}
	p.Brand = s.cfg.BrandName
	p.Version = Version
	p.BaseDomain = s.cfg.BaseDomain

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, tmpl, p); err != nil {
		s.log.Error("template render failed", "template", tmpl, "err", err)
	}
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	w.WriteHeader(code)
	s.render(w, r, "error.html", page{Title: "Error", Flash: msg, FlashKind: "error"})
}

// redirect sends the operator back with a short outcome code, so a refresh
// does not resubmit the form.
func redirect(w http.ResponseWriter, r *http.Request, path, msg string) {
	if msg != "" {
		path += "?m=" + msg
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func flash(r *http.Request) (string, string) {
	switch r.URL.Query().Get("m") {
	case "created":
		return "Created.", "ok"
	case "updated":
		return "Saved.", "ok"
	case "revoked":
		return "Revoked. The change takes effect within a second.", "ok"
	case "extended":
		return "Renewed.", "ok"
	case "allowed":
		return "Allowlist updated.", "ok"
	case "override":
		return "Override saved. Remember the proxy tier needs a matching route.", "ok"
	case "removed":
		return "Removed.", "ok"
	case "err":
		return "That did not work. Check the values and try again.", "error"
	}
	return "", ""
}

// ---- authentication ----

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.sessionFrom(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login.html", page{Title: "Sign in"})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form submission.")
		return
	}

	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	ip := backend.ClientIP(r)

	byEmail, byIP, err := s.store.RecentFailures(email, ip, s.cfg.LoginWindow)
	if err != nil {
		s.render(w, r, "login.html", page{Title: "Sign in",
			Flash: "Something went wrong.", FlashKind: "error"})
		return
	}
	if byEmail >= s.cfg.MaxLoginFailures || byIP >= s.cfg.MaxLoginFailures*3 {
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, r, "login.html", page{Title: "Sign in",
			Flash: "Too many attempts. Wait a few minutes.", FlashKind: "error"})
		return
	}

	user, err := s.store.UserByEmail(email)
	ok := err == nil && user.Active() &&
		(user.Role == backend.RoleAdmin || user.Role == backend.RoleReseller) &&
		s.store.VerifyUserPassword(user, password) == nil

	if !ok {
		if err != nil {
			s.store.BurnPasswordTime(password)
		}
		s.store.RecordLoginAttempt(email, ip, false)
		s.store.Record(backend.AuditEntry{
			ActorType: "anonymous", ActorLabel: email,
			Action: backend.ActionLoginFailed, IP: ip,
			RequestID: backend.RequestIDFrom(r.Context()),
		})
		w.WriteHeader(http.StatusUnauthorized)
		// One message for every failure mode: no account enumeration.
		s.render(w, r, "login.html", page{Title: "Sign in",
			Flash: "Incorrect email or password.", FlashKind: "error"})
		return
	}

	token, sess, err := s.store.CreateSession(user.ID, s.cfg.SessionTTL, ip, r.UserAgent())
	if err != nil {
		s.render(w, r, "login.html", page{Title: "Sign in",
			Flash: "Something went wrong.", FlashKind: "error"})
		return
	}

	s.store.RecordLoginAttempt(email, ip, true)
	s.store.Record(backend.AuditEntry{
		ActorType: "user", ActorID: strconv.FormatInt(user.ID, 10), ActorLabel: user.Email,
		Action: backend.ActionLogin, IP: ip, RequestID: backend.RequestIDFrom(r.Context()),
	})

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode, Expires: time.Unix(sess.ExpiresAt, 0),
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

// ---- overview ----

type overview struct {
	Tenants      int
	ActiveTenant int
	Customers    int
	ExpiringSoon int
	Queries      int64
	Blocked      int64
	BlockRate    float64
	Resolver     *resolverStatus
	Recent       []*backend.AuditEntry
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, sess *opSession) {
	p := page{Title: "Overview", Nav: "overview"}
	p.Flash, p.FlashKind = flash(r)

	customers, err := s.store.ListCustomers(sess.principal(), 500, 0)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load customers.")
		return
	}

	ov := &overview{Customers: len(customers)}
	now := time.Now().Unix()
	weekOut := now + 7*24*3600

	// Counting through the customers the caller can see, so a reseller's
	// overview reflects its own book rather than the whole system.
	for _, c := range customers {
		ids, _ := s.store.TenantsForCustomer(c.ID)
		for _, id := range ids {
			ov.Tenants++
			t := s.policy.Tenant(id)
			if t == nil {
				continue
			}
			if t.Active(now) {
				ov.ActiveTenant++
				if t.ExpiresAt < weekOut {
					ov.ExpiringSoon++
				}
			}
			if u, ok := s.policy.Usage(id); ok {
				ov.Queries += u.Queries
				ov.Blocked += u.Blocked
			}
		}
	}
	if ov.Queries > 0 {
		ov.BlockRate = float64(ov.Blocked) / float64(ov.Queries) * 100
	}

	if sess.isAdmin() {
		ov.Resolver = s.resolverStatus()
		ov.Recent, _ = s.store.ListAudit(backend.AuditQuery{Limit: 8})
	}

	p.Overview = ov
	s.render(w, r, "overview.html", p)
}

// ---- customers ----

type customerRow struct {
	*backend.Customer
	TenantCount int
	ActiveCount int
}

func (s *Server) handleCustomerList(w http.ResponseWriter, r *http.Request, sess *opSession) {
	p := page{Title: "Customers", Nav: "customers"}
	p.Flash, p.FlashKind = flash(r)

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	customers, err := s.store.ListCustomers(sess.principal(), limit, offset)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load customers.")
		return
	}

	now := time.Now().Unix()
	for _, c := range customers {
		row := customerRow{Customer: c}
		ids, _ := s.store.TenantsForCustomer(c.ID)
		row.TenantCount = len(ids)
		for _, id := range ids {
			if t := s.policy.Tenant(id); t.Active(now) {
				row.ActiveCount++
			}
		}
		p.Customers = append(p.Customers, row)
	}

	s.render(w, r, "customers.html", p)
}

func (s *Server) handleCustomerCreate(w http.ResponseWriter, r *http.Request, sess *opSession) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		redirect(w, r, "/customers", "err")
		return
	}

	// A reseller always owns what it creates. Accepting an owner from the form
	// would let one reseller plant customers under another.
	owner := sess.user.ID
	if sess.isAdmin() {
		if id, err := strconv.ParseInt(r.PostFormValue("owner_id"), 10, 64); err == nil && id > 0 {
			owner = id
		}
	}

	c, err := s.store.CreateCustomer(
		strings.TrimSpace(r.PostFormValue("email")), name,
		strings.TrimSpace(r.PostFormValue("phone")), owner)
	if err != nil {
		s.log.Error("customer create failed", "err", err)
		redirect(w, r, "/customers", "err")
		return
	}

	s.audit(r, sess, backend.ActionCustomerCreate, "customer",
		strconv.FormatInt(c.ID, 10), map[string]any{"name": name, "owner_id": owner})
	redirect(w, r, "/customers/"+strconv.FormatInt(c.ID, 10), "created")
}

type customerDetail struct {
	*backend.Customer
	Tenants []tenantRow
}

type tenantRow struct {
	RouteID   string
	Hostname  string
	Label     string
	Status    string
	Active    bool
	Filtering bool
	ExpiresAt int64
	Queries   int64
	Blocked   int64
}

func (s *Server) handleCustomerDetail(w http.ResponseWriter, r *http.Request, sess *opSession) {
	id, ok := s.customerAccess(w, r, sess)
	if !ok {
		return
	}

	c, err := s.store.CustomerByID(id)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "Customer not found.")
		return
	}

	p := page{Title: c.Name, Nav: "customers"}
	p.Flash, p.FlashKind = flash(r)

	detail := &customerDetail{Customer: c}
	ids, _ := s.store.TenantsForCustomer(id)
	now := time.Now().Unix()

	for _, rid := range ids {
		row := tenantRow{RouteID: rid, Hostname: rid + "." + s.cfg.BaseDomain}
		if t := s.policy.Tenant(rid); t != nil {
			row.Label, row.Status = t.Label, t.Status
			row.Active, row.Filtering = t.Active(now), t.Filtering(now)
			row.ExpiresAt = t.ExpiresAt
		}
		if u, ok := s.policy.Usage(rid); ok {
			row.Queries, row.Blocked = u.Queries, u.Blocked
		}
		detail.Tenants = append(detail.Tenants, row)
	}

	p.Customer = detail
	p.Plans, _ = s.store.ListPlans(sess.isAdmin())
	s.render(w, r, "customer.html", p)
}

func (s *Server) handleCustomerUpdate(w http.ResponseWriter, r *http.Request, sess *opSession) {
	id, ok := s.customerAccess(w, r, sess)
	if !ok {
		return
	}

	status := r.PostFormValue("status")
	if status != "active" && status != "disabled" {
		status = "active"
	}

	if err := s.store.UpdateCustomer(id,
		strings.TrimSpace(r.PostFormValue("name")),
		strings.TrimSpace(r.PostFormValue("phone")),
		strings.TrimSpace(r.PostFormValue("notes")),
		status); err != nil {
		redirect(w, r, "/customers/"+strconv.FormatInt(id, 10), "err")
		return
	}

	s.audit(r, sess, backend.ActionCustomerUpdate, "customer",
		strconv.FormatInt(id, 10), map[string]any{"status": status})
	redirect(w, r, "/customers/"+strconv.FormatInt(id, 10), "updated")
}

// customerAccess resolves the customer in the path and checks visibility,
// answering 404 for both "missing" and "not yours" so probing cannot map
// another reseller's book.
func (s *Server) customerAccess(w http.ResponseWriter, r *http.Request, sess *opSession) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid customer id.")
		return 0, false
	}

	allowed, err := s.store.CanAccessCustomer(sess.principal(), id)
	if errors.Is(err, backend.ErrNotFound) || (err == nil && !allowed) {
		s.renderError(w, r, http.StatusNotFound, "Customer not found.")
		return 0, false
	}
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Something went wrong.")
		return 0, false
	}
	return id, true
}

func (s *Server) audit(r *http.Request, sess *opSession, action, targetType, targetID string, detail map[string]any) {
	s.store.Record(backend.AuditEntry{
		ActorType: "user", ActorID: strconv.FormatInt(sess.user.ID, 10),
		ActorLabel: sess.user.Email, Action: action,
		TargetType: targetType, TargetID: targetID,
		Detail: backend.AuditDetail(detail), IP: backend.ClientIP(r),
		RequestID: backend.RequestIDFrom(r.Context()),
	})
}

// ---- helpers used by templates ----

func formatTime(unix int64) string {
	if unix <= 0 {
		return "—"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04")
}

func humanSince(unix int64) string {
	if unix <= 0 {
		return "never"
	}
	d := time.Since(time.Unix(unix, 0))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func humanUntil(unix int64) string {
	if unix <= 0 {
		return "—"
	}
	d := time.Until(time.Unix(unix, 0))
	if d <= 0 {
		return "expired"
	}
	if days := int(d.Hours() / 24); days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dh", int(d.Hours())+1)
}

func comma(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func percent(f float64) string { return fmt.Sprintf("%.1f%%", f) }

// ---- resolver status ----

type resolverStatus struct {
	Reachable     bool
	Version       string
	Uptime        string
	Tenants       int64
	BlocklistSize int64
	CacheEntries  int64
	Queries       int64
	Blocked       int64
	Refused       int64
	Throttled     int64
	UpstreamErr   int64
}

// resolverStatus scrapes the resolver's Prometheus endpoint.
//
// Parsing the metrics we already expose avoids a second status API that would
// have to be kept in step with them.
func (s *Server) resolverStatus() *resolverStatus {
	out := &resolverStatus{}
	if s.cfg.ResolverAdmin == "" {
		return out
	}

	base := strings.TrimRight(s.cfg.ResolverAdmin, "/")
	client := &http.Client{Timeout: 2 * time.Second}

	req, err := http.NewRequest(http.MethodGet, base+"/metrics", nil)
	if err != nil {
		return out
	}
	if s.cfg.ResolverToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.ResolverToken)
	}

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return out
	}
	defer resp.Body.Close()

	buf := make([]byte, 64<<10)
	n, _ := resp.Body.Read(buf)
	metrics := parseMetrics(string(buf[:n]))

	out.Reachable = true
	out.Tenants = metrics["privatedns_tenants"]
	out.BlocklistSize = metrics["privatedns_blocklist_size"]
	out.CacheEntries = metrics["privatedns_cache_entries"]
	out.Queries = metrics["privatedns_queries_total"]
	out.Blocked = metrics["privatedns_blocked_total"]
	out.Refused = metrics["privatedns_refused_total"]
	out.Throttled = metrics["privatedns_throttled_total"]
	out.UpstreamErr = metrics["privatedns_upstream_errors_total"]
	if up := metrics["privatedns_uptime_seconds"]; up > 0 {
		out.Uptime = (time.Duration(up) * time.Second).Truncate(time.Minute).String()
	}

	if vreq, err := http.NewRequest(http.MethodGet, base+"/version", nil); err == nil {
		if s.cfg.ResolverToken != "" {
			vreq.Header.Set("Authorization", "Bearer "+s.cfg.ResolverToken)
		}
		if vresp, err := client.Do(vreq); err == nil {
			defer vresp.Body.Close()
			var v struct {
				Version string `json:"version"`
			}
			if json.NewDecoder(vresp.Body).Decode(&v) == nil {
				out.Version = v.Version
			}
		}
	}

	return out
}

func parseMetrics(body string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		name, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			out[name] = n
		}
	}
	return out
}

// validDomain guards operator-supplied domains before they reach policy tables.
func validDomain(s string) (string, bool) {
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

func validAddr(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return a.String(), true
}
