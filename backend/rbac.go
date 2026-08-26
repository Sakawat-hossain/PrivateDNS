package backend

import "strings"

// Role determines what a principal may do.
type Role string

const (
	// RoleAdmin operates the whole system.
	RoleAdmin Role = "admin"

	// RoleReseller manages only the customers it owns. This is the role that
	// makes tenant isolation a real requirement rather than a theoretical one:
	// resellers are commercial rivals of one another.
	RoleReseller Role = "reseller"

	// RoleCustomer manages its own tenants and nothing else.
	RoleCustomer Role = "customer"
)

func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleReseller, RoleCustomer:
		return true
	}
	return false
}

// Scope is a capability an API token may carry. Tokens are scoped so an
// integration that only needs to provision does not also gain the ability to
// read the audit log or change system configuration.
type Scope string

const (
	ScopeTenantsRead  Scope = "tenants:read"
	ScopeTenantsWrite Scope = "tenants:write"

	// ScopeTenantsBindIP is deliberately separate from tenants:write. Binding a
	// source address is the customer-facing "update my IP" control and must be
	// available to customers; issuing or extending a subscription must not be.
	ScopeTenantsBindIP  Scope = "tenants:bind_ip"
	ScopeCustomersRead  Scope = "customers:read"
	ScopeCustomersWrite Scope = "customers:write"
	ScopePolicyRead     Scope = "policy:read"
	ScopePolicyWrite    Scope = "policy:write"
	ScopeStatsRead      Scope = "stats:read"
	ScopeSystemRead     Scope = "system:read"
	ScopeSystemWrite    Scope = "system:write"
	ScopeAuditRead      Scope = "audit:read"
)

// AllScopes is every scope that may be granted, used to validate a request.
var AllScopes = []Scope{
	ScopeTenantsRead, ScopeTenantsWrite, ScopeTenantsBindIP,
	ScopeCustomersRead, ScopeCustomersWrite,
	ScopePolicyRead, ScopePolicyWrite,
	ScopeStatsRead,
	ScopeSystemRead, ScopeSystemWrite,
	ScopeAuditRead,
}

func ValidScope(s Scope) bool {
	for _, v := range AllScopes {
		if v == s {
			return true
		}
	}
	return false
}

// roleScopes is the ceiling for each role. A token can never carry a scope its
// owner's role does not have, so revoking a role narrows every token it issued.
var roleScopes = map[Role]map[Scope]bool{
	RoleAdmin: scopeSet(AllScopes...),

	// A reseller manages its own customers and their tenants. It gets no
	// system write access and no audit access: the audit log spans every
	// reseller, and one must not read another's activity.
	RoleReseller: scopeSet(
		ScopeTenantsRead, ScopeTenantsWrite, ScopeTenantsBindIP,
		ScopeCustomersRead, ScopeCustomersWrite,
		ScopePolicyRead, ScopePolicyWrite,
		ScopeStatsRead,
	),

	// A customer sees its own tenants and usage, and may adjust its own
	// policy. Nothing else.
	RoleCustomer: scopeSet(
		ScopeTenantsRead, ScopeTenantsBindIP,
		ScopePolicyRead, ScopePolicyWrite,
		ScopeStatsRead,
	),
}

func scopeSet(scopes ...Scope) map[Scope]bool {
	out := make(map[Scope]bool, len(scopes))
	for _, s := range scopes {
		out[s] = true
	}
	return out
}

// RoleHasScope reports whether a role may ever hold this scope.
func RoleHasScope(r Role, s Scope) bool {
	return roleScopes[r][s]
}

// ScopesForRole returns everything a role may be granted.
func ScopesForRole(r Role) []Scope {
	out := make([]Scope, 0, len(roleScopes[r]))
	for _, s := range AllScopes {
		if roleScopes[r][s] {
			out = append(out, s)
		}
	}
	return out
}

// Principal is whoever is making a request, however they authenticated.
type Principal struct {
	Kind   string // "session" or "token"
	UserID int64
	Email  string
	Role   Role

	// Scopes is what this particular credential carries. For a session it is
	// everything the role allows; for a token it is the intersection of the
	// token's grant and the role's ceiling.
	Scopes map[Scope]bool

	// CustomerID is the customer record a customer-role principal represents.
	// Zero for administrators and resellers. It is NOT the same number as
	// UserID: users and customers are separate tables with independent
	// sequences, and comparing one against the other would grant access across
	// unrelated accounts whose ids happened to collide.
	CustomerID int64

	TokenID int64
}

// Can reports whether the principal may exercise a scope.
//
// Both conditions must hold: the credential carries the scope, and the role
// still permits it. Checking the role at request time is what makes a
// demotion take effect immediately on tokens issued earlier.
func (p *Principal) Can(s Scope) bool {
	if p == nil {
		return false
	}
	if !RoleHasScope(p.Role, s) {
		return false
	}
	return p.Scopes[s]
}

func (p *Principal) IsAdmin() bool { return p != nil && p.Role == RoleAdmin }

// Label is a human-readable identifier for the audit log.
func (p *Principal) Label() string {
	if p == nil {
		return "anonymous"
	}
	if p.Email != "" {
		return p.Email
	}
	return string(p.Role)
}

// ParseScopes turns a stored comma-separated list into a set, dropping
// anything unrecognised rather than failing — an unknown scope grants nothing,
// so silently ignoring it is safe and keeps old tokens working across upgrades.
func ParseScopes(s string) map[Scope]bool {
	out := map[Scope]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if sc := Scope(part); ValidScope(sc) {
			out[sc] = true
		}
	}
	return out
}

// FormatScopes renders a scope set for storage, in a stable order.
func FormatScopes(set map[Scope]bool) string {
	parts := make([]string, 0, len(set))
	for _, s := range AllScopes {
		if set[s] {
			parts = append(parts, string(s))
		}
	}
	return strings.Join(parts, ",")
}
