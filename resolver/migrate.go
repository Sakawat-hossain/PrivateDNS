package resolver

import (
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Migration is one forward schema step. Migrations are applied in Version
// order inside a transaction and recorded, so a given version runs exactly
// once against a database.
//
// Never edit a migration that has shipped. Anyone already running it will not
// re-apply the changed version, so their schema silently diverges. Add a new
// migration instead.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// RegisterMigrations adds schema steps owned by another package.
//
// The resolver and the backend share one SQLite database, and one database can
// only have one ordered migration history -- two independent trackers against
// the same file would race and diverge. So each package owns its own
// migrations and registers them here, where they are merged into a single
// ordered sequence.
//
// Version ranges are partitioned by owner to keep them from colliding:
// 1-99 belongs to the resolver, 100+ to the backend.
func RegisterMigrations(extra ...Migration) {
	migrationsMu.Lock()
	defer migrationsMu.Unlock()
	migrations = append(migrations, extra...)
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
}

var migrationsMu sync.Mutex

// migrations is the ordered schema history.
var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial schema",
		SQL: `
CREATE TABLE IF NOT EXISTS tenants (
  route_id     TEXT PRIMARY KEY,
  label        TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'active',
  expires_at   INTEGER NOT NULL,
  block_ads    INTEGER NOT NULL DEFAULT 1,
  paused_until INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);

-- Source-IP authorisation, used by the plain :53 listener and the proxy tier.
CREATE TABLE IF NOT EXISTS tenant_ips (
  ip       TEXT PRIMARY KEY,
  route_id TEXT NOT NULL,
  added_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenant_ips_route ON tenant_ips(route_id);

-- Per-tenant allowlist. route_id '*' applies globally.
CREATE TABLE IF NOT EXISTS allowlist (
  route_id TEXT NOT NULL,
  domain   TEXT NOT NULL,
  PRIMARY KEY (route_id, domain)
);

-- Answer overrides: return our own address instead of the real one.
-- This is the smart-DNS mechanism. route_id '*' applies globally.
CREATE TABLE IF NOT EXISTS overrides (
  route_id TEXT NOT NULL,
  domain   TEXT NOT NULL,
  answer   TEXT NOT NULL,
  PRIMARY KEY (route_id, domain)
);
`,
	},
	{
		Version: 2,
		Name:    "per-tenant usage counters",
		SQL: `
-- Aggregate counters only. Full query history is deliberately not recorded:
-- it is the strongest privacy claim available, and it keeps storage flat.
CREATE TABLE IF NOT EXISTS tenant_usage (
  route_id     TEXT PRIMARY KEY,
  queries      INTEGER NOT NULL DEFAULT 0,
  blocked      INTEGER NOT NULL DEFAULT 0,
  overridden   INTEGER NOT NULL DEFAULT 0,
  throttled    INTEGER NOT NULL DEFAULT 0,
  last_seen    INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL DEFAULT 0
);
`,
	},
	{
		Version: 3,
		Name:    "tenant lookup indexes",
		SQL: `
CREATE INDEX IF NOT EXISTS idx_tenants_status_expiry ON tenants(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_overrides_route ON overrides(route_id);
CREATE INDEX IF NOT EXISTS idx_allowlist_route ON allowlist(route_id);
`,
	},
}

// SchemaVersion is the version a freshly migrated database ends at.
func SchemaVersion() int {
	migrationsMu.Lock()
	defer migrationsMu.Unlock()
	if len(migrations) == 0 {
		return 0
	}
	return migrations[len(migrations)-1].Version
}

// migrate brings db up to the latest schema version, applying only migrations
// it has not already recorded. Each runs in its own transaction, so a failure
// leaves the database at the last good version rather than half-applied.
func migrate(db *sql.DB) (applied int, err error) {
	migrationsMu.Lock()
	pending := make([]Migration, len(migrations))
	copy(pending, migrations)
	migrationsMu.Unlock()

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
		  version    INTEGER PRIMARY KEY,
		  name       TEXT NOT NULL,
		  applied_at INTEGER NOT NULL
		)`); err != nil {
		return 0, fmt.Errorf("create schema_migrations: %w", err)
	}

	done := map[int]bool{}
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return 0, fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return 0, err
		}
		done[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, m := range pending {
		if done[m.Version] {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return applied, fmt.Errorf("begin migration %d: %w", m.Version, err)
		}
		if _, err := tx.Exec(m.SQL); err != nil {
			tx.Rollback()
			return applied, fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?,?,?)`,
			m.Version, m.Name, time.Now().Unix(),
		); err != nil {
			tx.Rollback()
			return applied, fmt.Errorf("record migration %d: %w", m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return applied, fmt.Errorf("commit migration %d: %w", m.Version, err)
		}
		applied++
	}

	return applied, nil
}

// currentSchemaVersion reports the highest migration recorded against db.
func currentSchemaVersion(db *sql.DB) (int, error) {
	var v sql.NullInt64
	err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}
