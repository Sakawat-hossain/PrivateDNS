# Backend

Not yet implemented.

The backend will provide the authenticated API consumed by the admin dashboard
and the customer portal: authentication and RBAC, customer and tenant
management, DNS profiles, allowlists, blocklists, overrides, subscriptions,
usage statistics, API tokens and the audit log.

Until it exists, provisioning goes through the resolver's own admin API — see
the API table in the [top-level README](../README.md). That endpoint binds to
localhost and is intended for machine access, not for people.
