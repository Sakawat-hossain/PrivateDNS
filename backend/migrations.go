package backend

import "github.com/Sakawat-hossain/PrivateDNS/resolver"

// Backend migrations occupy version 100 and upward. The resolver owns 1-99.
// Both write to the same database and share one ordered history — see
// resolver.RegisterMigrations for why.
func init() {
	resolver.RegisterMigrations(
		resolver.Migration{
			Version: 100,
			Name:    "accounts and authentication",
			SQL: `
-- Operators of the system: administrators and resellers.
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  last_login_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Sessions store only a hash of the cookie value. A database disclosure must
-- not hand the attacker a set of usable sessions.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL,
  csrf_token  TEXT NOT NULL,
  user_agent  TEXT NOT NULL DEFAULT '',
  ip          TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

-- API tokens likewise store a hash. The prefix is kept in clear so a token can
-- be located for verification and shown in a list without revealing it.
CREATE TABLE IF NOT EXISTS api_tokens (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix       TEXT NOT NULL UNIQUE,
  token_hash   TEXT NOT NULL,
  name         TEXT NOT NULL DEFAULT '',
  user_id      INTEGER NOT NULL,
  scopes       TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL DEFAULT 0,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  revoked_at   INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id);

-- Failed sign-in attempts, used to throttle credential stuffing.
CREATE TABLE IF NOT EXISTS login_attempts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT NOT NULL,
  ip         TEXT NOT NULL,
  succeeded  INTEGER NOT NULL,
  at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_email ON login_attempts(email, at);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip, at);
`,
		},
		resolver.Migration{
			Version: 101,
			Name:    "customers and plans",
			SQL: `
-- A customer is the person who pays. A tenant is the DNS identity they use.
-- They are separate because one customer may hold several tenants, and because
-- a tenant can be revoked and reissued without touching the account.
CREATE TABLE IF NOT EXISTS customers (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  email       TEXT NOT NULL DEFAULT '',
  name        TEXT NOT NULL DEFAULT '',
  phone       TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  owner_id    INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'active',
  notes       TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customers_owner ON customers(owner_id);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);

-- Which customer a resolver tenant belongs to. The resolver owns the tenants
-- table and knows nothing about customers; this is the join.
CREATE TABLE IF NOT EXISTS customer_tenants (
  route_id    TEXT PRIMARY KEY,
  customer_id INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_customer_tenants_customer ON customer_tenants(customer_id);

CREATE TABLE IF NOT EXISTS plans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  code        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  days        INTEGER NOT NULL DEFAULT 0,
  minutes     INTEGER NOT NULL DEFAULT 0,
  price_minor INTEGER NOT NULL DEFAULT 0,
  currency    TEXT NOT NULL DEFAULT 'BDT',
  active      INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL
);
`,
		},
		resolver.Migration{
			Version: 103,
			Name:    "link customer logins to customer records",
			SQL: `
-- A customer-role login must point at the customer record it represents.
--
-- Without this the ownership check compared a users.id against a customers.id.
-- Those are separate sequences, so user 7 would have matched customer 7 with no
-- relationship between them -- a cross-tenant read for any customer whose
-- account id happened to collide.
ALTER TABLE users ADD COLUMN customer_id INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_users_customer ON users(customer_id);
`,
		},
		resolver.Migration{
			Version: 102,
			Name:    "audit log",
			SQL: `
-- Append-only record of every state change. Rows are never updated or deleted
-- by the application: an audit log that can be edited from the same API it
-- audits is not evidence of anything.
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  at          INTEGER NOT NULL,
  actor_type  TEXT NOT NULL,
  actor_id    TEXT NOT NULL DEFAULT '',
  actor_label TEXT NOT NULL DEFAULT '',
  action      TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT '',
  target_id   TEXT NOT NULL DEFAULT '',
  detail      TEXT NOT NULL DEFAULT '',
  ip          TEXT NOT NULL DEFAULT '',
  request_id  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_type, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);
`,
		},
	)
}
