package resolver

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the policy interface the resolver depends on. SQLiteStore is the
// only implementation today; the interface exists so a PostgreSQL backend can
// be added later without touching the query path.
type Store interface {
	// Read path — called on every query, must be cheap and non-blocking.
	Tenant(routeID string) *Tenant
	TenantByIP(ip string) *Tenant
	Allowed(routeID, name string) bool
	Override(routeID, name string) (netip.Addr, bool)
	TenantCount() int

	// Write path — provisioning, called by the admin API.
	CreateTenant(routeID, label string, expiresAt int64) error
	SetStatus(routeID, status string) error
	Extend(routeID string, expiresAt int64) error
	PauseFiltering(routeID string, until int64) error
	RegisterIP(routeID, ip string) error
	ReleaseIP(ip string) error
	AddAllow(routeID, domain string) error
	RemoveAllow(routeID, domain string) error
	SetOverride(routeID, domain, answer string) error
	RemoveOverride(routeID, domain string) error

	// Usage accounting — aggregates only, never per-query history.
	RecordUsage(counts map[string]UsageDelta) error
	Usage(routeID string) (Usage, bool)

	// Listing, for the operator dashboard. These read the database directly
	// rather than the serving snapshot: an operator wants the committed truth,
	// not what the resolver happens to have cached this second.
	ListAllow(routeID string) ([]string, error)
	ListIPs(routeID string) ([]string, error)
	ListOverrides() ([]OverrideRow, error)

	// Lifecycle.
	Reload() error
	WatchReload(every time.Duration, onErr func(error))
	Ping(ctx context.Context) error
	SchemaVersion() (int, error)
	Close() error
}

// compile-time assertion that the implementation satisfies the interface
var _ Store = (*SQLiteStore)(nil)

type Tenant struct {
	RouteID     string
	Label       string
	Status      string
	ExpiresAt   int64
	BlockAds    bool
	PausedUntil int64
}

func (t *Tenant) Active(now int64) bool {
	return t != nil && t.Status == "active" && t.ExpiresAt > now
}

// Filtering reports whether blocklists should apply right now. A tenant can
// pause filtering temporarily, which is how a false positive gets unblocked
// without a support ticket.
func (t *Tenant) Filtering(now int64) bool {
	return t != nil && t.BlockAds && t.PausedUntil <= now
}

// Usage holds a tenant's cumulative counters.
type Usage struct {
	Queries    int64
	Blocked    int64
	Overridden int64
	Throttled  int64
	LastSeen   int64
}

// UsageDelta is an increment to apply to a tenant's counters.
type UsageDelta struct {
	Queries    int64
	Blocked    int64
	Overridden int64
	Throttled  int64
	LastSeen   int64
}

type snapshot struct {
	tenants map[string]*Tenant
	byIP    map[string]string

	// allow[routeID][domain] and over[routeID][domain]; routeID "*" is global.
	allow map[string]map[string]bool
	over  map[string]map[string]netip.Addr
}

// SQLiteStore keeps policy in SQLite and serves reads from an in-memory
// snapshot that is rebuilt on a timer. Queries never touch the database.
type SQLiteStore struct {
	db   *sql.DB
	snap atomic.Pointer[snapshot]
}

func OpenStore(path string) (*SQLiteStore, error) {
	// WAL keeps the reload query from blocking provisioning writes.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if _, err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	s := &SQLiteStore{db: db}
	if err := s.Reload(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *SQLiteStore) SchemaVersion() (int, error) { return currentSchemaVersion(s.db) }

// Reload rebuilds the in-memory snapshot. Called on a one-second timer, which
// is what bounds revocation latency.
func (s *SQLiteStore) Reload() error {
	snap := &snapshot{
		tenants: map[string]*Tenant{},
		byIP:    map[string]string{},
		allow:   map[string]map[string]bool{},
		over:    map[string]map[string]netip.Addr{},
	}

	rows, err := s.db.Query(`SELECT route_id,label,status,expires_at,block_ads,paused_until FROM tenants`)
	if err != nil {
		return fmt.Errorf("load tenants: %w", err)
	}
	for rows.Next() {
		var t Tenant
		var blockAds int
		if err := rows.Scan(&t.RouteID, &t.Label, &t.Status, &t.ExpiresAt, &blockAds, &t.PausedUntil); err != nil {
			rows.Close()
			return err
		}
		t.BlockAds = blockAds != 0
		snap.tenants[strings.ToLower(t.RouteID)] = &t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = s.db.Query(`SELECT ip,route_id FROM tenant_ips`)
	if err != nil {
		return fmt.Errorf("load ips: %w", err)
	}
	for rows.Next() {
		var ip, rid string
		if err := rows.Scan(&ip, &rid); err != nil {
			rows.Close()
			return err
		}
		snap.byIP[ip] = strings.ToLower(rid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = s.db.Query(`SELECT route_id,domain FROM allowlist`)
	if err != nil {
		return fmt.Errorf("load allowlist: %w", err)
	}
	for rows.Next() {
		var rid, dom string
		if err := rows.Scan(&rid, &dom); err != nil {
			rows.Close()
			return err
		}
		rid = strings.ToLower(rid)
		if snap.allow[rid] == nil {
			snap.allow[rid] = map[string]bool{}
		}
		snap.allow[rid][normalizeDomain(dom)] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = s.db.Query(`SELECT route_id,domain,answer FROM overrides`)
	if err != nil {
		return fmt.Errorf("load overrides: %w", err)
	}
	for rows.Next() {
		var rid, dom, ans string
		if err := rows.Scan(&rid, &dom, &ans); err != nil {
			rows.Close()
			return err
		}
		addr, err := netip.ParseAddr(ans)
		if err != nil {
			continue // skip a malformed row rather than failing the whole reload
		}
		rid = strings.ToLower(rid)
		if snap.over[rid] == nil {
			snap.over[rid] = map[string]netip.Addr{}
		}
		snap.over[rid][normalizeDomain(dom)] = addr
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	s.snap.Store(snap)
	return nil
}

func (s *SQLiteStore) WatchReload(every time.Duration, onErr func(error)) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			if err := s.Reload(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}()
}

func (s *SQLiteStore) Tenant(routeID string) *Tenant {
	return s.snap.Load().tenants[strings.ToLower(routeID)]
}

func (s *SQLiteStore) TenantByIP(ip string) *Tenant {
	snap := s.snap.Load()
	rid, ok := snap.byIP[ip]
	if !ok {
		return nil
	}
	return snap.tenants[rid]
}

// Allowed reports whether the name (or a parent of it) is on the tenant's
// allowlist or the global one. Allowlist beats both blocklist and override.
func (s *SQLiteStore) Allowed(routeID, name string) bool {
	snap := s.snap.Load()
	rid := strings.ToLower(routeID)
	for _, suffix := range domainSuffixes(name) {
		if snap.allow[rid][suffix] || snap.allow["*"][suffix] {
			return true
		}
	}
	return false
}

// Override returns the address to answer with, if this name or any parent of
// it has an override. Tenant-specific rules beat global ones.
func (s *SQLiteStore) Override(routeID, name string) (netip.Addr, bool) {
	snap := s.snap.Load()
	rid := strings.ToLower(routeID)
	for _, suffix := range domainSuffixes(name) {
		if a, ok := snap.over[rid][suffix]; ok {
			return a, true
		}
		if a, ok := snap.over["*"][suffix]; ok {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func (s *SQLiteStore) TenantCount() int { return len(s.snap.Load().tenants) }

// ---- write paths, used by the admin API ----

func (s *SQLiteStore) CreateTenant(routeID, label string, expiresAt int64) error {
	_, err := s.db.Exec(
		`INSERT INTO tenants (route_id,label,status,expires_at,block_ads,paused_until,created_at)
		 VALUES (?,?,'active',?,1,0,?)
		 ON CONFLICT(route_id) DO UPDATE SET label=excluded.label, expires_at=excluded.expires_at, status='active'`,
		strings.ToLower(routeID), label, expiresAt, time.Now().Unix())
	return err
}

func (s *SQLiteStore) SetStatus(routeID, status string) error {
	_, err := s.db.Exec(`UPDATE tenants SET status=? WHERE route_id=?`, status, strings.ToLower(routeID))
	return err
}

func (s *SQLiteStore) Extend(routeID string, expiresAt int64) error {
	_, err := s.db.Exec(`UPDATE tenants SET expires_at=? WHERE route_id=?`, expiresAt, strings.ToLower(routeID))
	return err
}

func (s *SQLiteStore) PauseFiltering(routeID string, until int64) error {
	_, err := s.db.Exec(`UPDATE tenants SET paused_until=? WHERE route_id=?`, until, strings.ToLower(routeID))
	return err
}

// RegisterIP binds a source address to a tenant. This is what the "update my
// IP" control in the dashboard calls, and it is the most-used action in the
// product for customers on mobile networks.
func (s *SQLiteStore) RegisterIP(routeID, ip string) error {
	_, err := s.db.Exec(
		`INSERT INTO tenant_ips (ip,route_id,added_at) VALUES (?,?,?)
		 ON CONFLICT(ip) DO UPDATE SET route_id=excluded.route_id, added_at=excluded.added_at`,
		ip, strings.ToLower(routeID), time.Now().Unix())
	return err
}

func (s *SQLiteStore) ReleaseIP(ip string) error {
	_, err := s.db.Exec(`DELETE FROM tenant_ips WHERE ip=?`, ip)
	return err
}

func (s *SQLiteStore) AddAllow(routeID, domain string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO allowlist (route_id,domain) VALUES (?,?)`,
		strings.ToLower(routeID), normalizeDomain(domain))
	return err
}

func (s *SQLiteStore) RemoveAllow(routeID, domain string) error {
	_, err := s.db.Exec(`DELETE FROM allowlist WHERE route_id=? AND domain=?`,
		strings.ToLower(routeID), normalizeDomain(domain))
	return err
}

func (s *SQLiteStore) SetOverride(routeID, domain, answer string) error {
	if _, err := netip.ParseAddr(answer); err != nil {
		return fmt.Errorf("answer must be an IP address: %w", err)
	}
	_, err := s.db.Exec(
		`INSERT INTO overrides (route_id,domain,answer) VALUES (?,?,?)
		 ON CONFLICT(route_id,domain) DO UPDATE SET answer=excluded.answer`,
		strings.ToLower(routeID), normalizeDomain(domain), answer)
	return err
}

func (s *SQLiteStore) RemoveOverride(routeID, domain string) error {
	_, err := s.db.Exec(`DELETE FROM overrides WHERE route_id=? AND domain=?`,
		strings.ToLower(routeID), normalizeDomain(domain))
	return err
}

// ---- usage accounting ----

// RecordUsage applies a batch of counter increments in one transaction.
// Counters are flushed periodically rather than written per query, so a busy
// resolver does not turn every lookup into a database write.
func (s *SQLiteStore) RecordUsage(counts map[string]UsageDelta) error {
	if len(counts) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO tenant_usage (route_id,queries,blocked,overridden,throttled,last_seen,updated_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(route_id) DO UPDATE SET
		  queries    = queries    + excluded.queries,
		  blocked    = blocked    + excluded.blocked,
		  overridden = overridden + excluded.overridden,
		  throttled  = throttled  + excluded.throttled,
		  last_seen  = MAX(last_seen, excluded.last_seen),
		  updated_at = excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for rid, d := range counts {
		if _, err := stmt.Exec(rid, d.Queries, d.Blocked, d.Overridden, d.Throttled, d.LastSeen, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) Usage(routeID string) (Usage, bool) {
	var u Usage
	err := s.db.QueryRow(
		`SELECT queries,blocked,overridden,throttled,last_seen FROM tenant_usage WHERE route_id=?`,
		strings.ToLower(routeID),
	).Scan(&u.Queries, &u.Blocked, &u.Overridden, &u.Throttled, &u.LastSeen)
	if err != nil {
		return Usage{}, false
	}
	return u, true
}

// OverrideRow is one answer-override rule as stored.
type OverrideRow struct {
	RouteID string
	Domain  string
	Answer  string
}

// ListAllow returns a tenant's allowlist entries.
func (s *SQLiteStore) ListAllow(routeID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT domain FROM allowlist WHERE route_id=? ORDER BY domain`,
		strings.ToLower(routeID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListIPs returns the source addresses bound to a tenant.
func (s *SQLiteStore) ListIPs(routeID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT ip FROM tenant_ips WHERE route_id=? ORDER BY added_at DESC`,
		strings.ToLower(routeID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// ListOverrides returns every override rule, global ones first.
func (s *SQLiteStore) ListOverrides() ([]OverrideRow, error) {
	rows, err := s.db.Query(
		`SELECT route_id, domain, answer FROM overrides
		 ORDER BY CASE route_id WHEN '*' THEN 0 ELSE 1 END, domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OverrideRow
	for rows.Next() {
		var o OverrideRow
		if err := rows.Scan(&o.RouteID, &o.Domain, &o.Answer); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// OpenStoreReadOnly opens the policy database without writing to it.
//
// The SNI proxy shares the resolver's database as one source of truth about
// who has paid, but it owns none of it: the resolver writes the schema and the
// rows, the proxy only asks which tenant a source address belongs to. Its
// systemd unit mounts /var/lib/private-dns read-only to enforce that.
//
// OpenStore cannot be used there. It runs migrations, which write, so the proxy
// died on startup with "attempt to write a readonly database" -- a schema
// migration attempted by a process that is not allowed to have one, against a
// database whose schema was already correct.
//
// mode=ro makes SQLite itself refuse writes, so a future change that starts
// writing here fails at the query rather than silently diverging from the
// resolver's copy.
func OpenStoreReadOnly(path string) (*SQLiteStore, error) {
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db read-only: %w", err)
	}

	// No migrate() here. The schema belongs to the resolver; check it is a
	// version this build understands rather than trying to change it.
	v, err := currentSchemaVersion(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("read schema version (is this the resolver's policy.db?): %w", err)
	}
	if v == 0 {
		db.Close()
		return nil, fmt.Errorf("policy database at %s has no schema; copy it from the resolver", path)
	}

	s := &SQLiteStore{db: db}
	if err := s.Reload(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
