package backend

import (
	"net/http"
	"sync"
)

// The OpenAPI document is generated from the same route list the router is
// built from, so it cannot drift out of date the way a hand-written spec does.
// It is served unauthenticated because it describes shapes, not data.

type apiRoute struct {
	Method  string
	Path    string
	Summary string
	Scope   Scope
	Admin   bool
}

// routeCatalog documents every endpoint. Adding a route to the router without
// adding it here shows up as a gap in the generated spec.
var routeCatalog = []apiRoute{
	{"GET", "/health", "Liveness. Always 200 while the process runs.", "", false},
	{"GET", "/ready", "Readiness. Verifies the database and schema version.", "", false},
	{"GET", "/version", "Build version and uptime.", "", false},

	{"POST", "/v1/auth/login", "Sign in and receive a session cookie plus a CSRF token.", "", false},
	{"POST", "/v1/auth/logout", "Destroy the current session.", "", false},
	{"GET", "/v1/auth/me", "The authenticated principal and its effective scopes.", "", false},
	{"POST", "/v1/auth/password", "Change your password. Signs out every other session.", "", false},

	{"GET", "/v1/users", "List operator accounts.", "", true},
	{"POST", "/v1/users", "Create an operator account.", "", true},
	{"POST", "/v1/users/{id}/status", "Enable or disable an account.", "", true},

	{"GET", "/v1/customers", "List customers visible to you.", ScopeCustomersRead, false},
	{"POST", "/v1/customers", "Create a customer.", ScopeCustomersWrite, false},
	{"GET", "/v1/customers/{id}", "Fetch a customer and its tenants.", ScopeCustomersRead, false},
	{"PATCH", "/v1/customers/{id}", "Update a customer.", ScopeCustomersWrite, false},

	{"POST", "/v1/tenants", "Issue a tenant for a customer.", ScopeTenantsWrite, false},
	{"GET", "/v1/tenants/{id}", "Fetch a tenant's state.", ScopeTenantsRead, false},
	{"POST", "/v1/tenants/{id}/revoke", "Suspend a tenant. Effective within a second.", ScopeTenantsWrite, false},
	{"POST", "/v1/tenants/{id}/extend", "Renew a tenant, from its current expiry if still future.", ScopeTenantsWrite, false},
	{"POST", "/v1/tenants/{id}/pause", "Pause filtering temporarily, up to 240 minutes.", ScopePolicyWrite, false},
	{"GET", "/v1/tenants/{id}/usage", "Aggregate counters. No per-domain history exists.", ScopeStatsRead, false},

	{"POST", "/v1/tenants/{id}/ips", "Bind a source address. Customers may only bind their own.", ScopeTenantsBindIP, false},
	{"DELETE", "/v1/tenants/{id}/ips/{ip}", "Unbind a source address.", ScopeTenantsBindIP, false},

	{"POST", "/v1/tenants/{id}/allow", "Add an allowlist entry.", ScopePolicyWrite, false},
	{"DELETE", "/v1/tenants/{id}/allow/{domain}", "Remove an allowlist entry.", ScopePolicyWrite, false},
	{"POST", "/v1/overrides", "Set an answer override. Administrators only.", ScopePolicyWrite, true},
	{"DELETE", "/v1/overrides/{domain}", "Remove an answer override. Administrators only.", ScopePolicyWrite, true},

	{"GET", "/v1/plans", "List plans.", ScopeTenantsRead, false},
	{"POST", "/v1/plans", "Create a plan.", "", true},

	{"GET", "/v1/tokens", "List API tokens you own.", "", false},
	{"POST", "/v1/tokens", "Create an API token. Session authentication only.", "", false},
	{"DELETE", "/v1/tokens/{id}", "Revoke an API token.", "", false},

	{"GET", "/v1/system/status", "System status.", ScopeSystemRead, false},
	{"GET", "/v1/audit", "Query the audit log.", ScopeAuditRead, false},
}

var (
	openAPIOnce sync.Once
	openAPIDoc  map[string]any
)

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	openAPIOnce.Do(func() { openAPIDoc = buildOpenAPI() })
	writeJSON(w, http.StatusOK, openAPIDoc)
}

func buildOpenAPI() map[string]any {
	paths := map[string]any{}

	for _, rt := range routeCatalog {
		op := map[string]any{
			"summary":   rt.Summary,
			"responses": defaultResponses(rt),
		}

		switch {
		case rt.Admin:
			op["security"] = []any{map[string]any{"sessionCookie": []string{}}, map[string]any{"bearerToken": []string{}}}
			op["description"] = "Requires the administrator role."
		case rt.Scope != "":
			op["security"] = []any{map[string]any{"sessionCookie": []string{}}, map[string]any{"bearerToken": []string{string(rt.Scope)}}}
			op["description"] = "Requires scope `" + string(rt.Scope) + "`."
		default:
			op["description"] = "No scope required."
		}

		entry, ok := paths[rt.Path].(map[string]any)
		if !ok {
			entry = map[string]any{}
			paths[rt.Path] = entry
		}
		entry[lowerMethod(rt.Method)] = op
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "PrivateDNS Backend API",
			"version": Version,
			"description": "Administration and provisioning API for PrivateDNS.\n\n" +
				"Authenticate either with a session cookie (browser clients, which must " +
				"also send the CSRF token in the " + csrfHeader + " header on mutating " +
				"requests) or a bearer token (machine clients, which do not need CSRF " +
				"because browsers never attach an Authorization header cross-site).",
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"sessionCookie": map[string]any{
					"type": "apiKey", "in": "cookie", "name": sessionCookie,
				},
				"bearerToken": map[string]any{
					"type": "http", "scheme": "bearer",
					"description": "An API token, prefixed " + APITokenPrefix +
						". Shown once at creation and stored only as a hash.",
				},
			},
		},
		"paths": paths,
	}
}

func defaultResponses(rt apiRoute) map[string]any {
	out := map[string]any{
		"200": map[string]any{"description": "Success"},
		"400": map[string]any{"description": "Invalid request"},
		"429": map[string]any{"description": "Rate limit exceeded"},
	}
	if rt.Scope != "" || rt.Admin {
		out["401"] = map[string]any{"description": "Authentication required"}
		out["403"] = map[string]any{"description": "Insufficient role or scope"}
		// Access denied is reported as 404 on tenant and customer routes, so
		// probing cannot distinguish "not yours" from "does not exist".
		out["404"] = map[string]any{"description": "Not found, or not visible to you"}
	}
	return out
}

func lowerMethod(m string) string {
	b := []byte(m)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
