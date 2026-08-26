package resolver

import (
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
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
`

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

type snapshot struct {
	tenants map[string]*Tenant
	byIP    map[string]string

	// allow[routeID][domain] and over[routeID][domain]; routeID "*" is global.
	allow map[string]map[string]bool
	over  map[string]map[string]netip.Addr
}

type Store struct {
	db   *sql.DB
	snap atomic.Pointer[snapshot]
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	s := &Store{db: db}
	if err := s.Reload(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Reload rebuilds the in-memory snapshot. Called on a one-second timer, which
// is what bounds revocation latency.
func (s *Store) Reload() error {
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
			continue // skip malformed rows rather than failing the whole reload
		}
		rid = strings.ToLower(rid)
		if snap.over[rid] == nil {
			snap.over[rid] = map[string]netip.Addr{}
		}
		snap.over[rid][normalizeDomain(dom)] = addr
	}
	rows.Close()

	s.snap.Store(snap)
	return nil
}

func (s *Store) WatchReload(every time.Duration, onErr func(error)) {
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

func (s *Store) Tenant(routeID string) *Tenant {
	return s.snap.Load().tenants[strings.ToLower(routeID)]
}

func (s *Store) TenantByIP(ip string) *Tenant {
	snap := s.snap.Load()
	rid, ok := snap.byIP[ip]
	if !ok {
		return nil
	}
	return snap.tenants[rid]
}

// Allowed reports whether the name (or a parent of it) is on the tenant's
// allowlist or the global one. Allowlist beats both blocklist and override.
func (s *Store) Allowed(routeID, name string) bool {
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
func (s *Store) Override(routeID, name string) (netip.Addr, bool) {
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

func (s *Store) TenantCount() int { return len(s.snap.Load().tenants) }

// ---- write paths, used by the admin API ----

func (s *Store) CreateTenant(routeID, label string, expiresAt int64) error {
	_, err := s.db.Exec(
		`INSERT INTO tenants (route_id,label,status,expires_at,block_ads,paused_until,created_at)
		 VALUES (?,?,'active',?,1,0,?)
		 ON CONFLICT(route_id) DO UPDATE SET label=excluded.label, expires_at=excluded.expires_at, status='active'`,
		strings.ToLower(routeID), label, expiresAt, time.Now().Unix())
	return err
}

func (s *Store) SetStatus(routeID, status string) error {
	_, err := s.db.Exec(`UPDATE tenants SET status=? WHERE route_id=?`, status, strings.ToLower(routeID))
	return err
}

func (s *Store) Extend(routeID string, expiresAt int64) error {
	_, err := s.db.Exec(`UPDATE tenants SET expires_at=? WHERE route_id=?`, expiresAt, strings.ToLower(routeID))
	return err
}

func (s *Store) PauseFiltering(routeID string, until int64) error {
	_, err := s.db.Exec(`UPDATE tenants SET paused_until=? WHERE route_id=?`, until, strings.ToLower(routeID))
	return err
}

// RegisterIP binds a source address to a tenant. This is what the "update my
// IP" button in the dashboard calls, and it is the most-used control in the
// product for customers on mobile networks.
func (s *Store) RegisterIP(routeID, ip string) error {
	_, err := s.db.Exec(
		`INSERT INTO tenant_ips (ip,route_id,added_at) VALUES (?,?,?)
		 ON CONFLICT(ip) DO UPDATE SET route_id=excluded.route_id, added_at=excluded.added_at`,
		ip, strings.ToLower(routeID), time.Now().Unix())
	return err
}

func (s *Store) ReleaseIP(ip string) error {
	_, err := s.db.Exec(`DELETE FROM tenant_ips WHERE ip=?`, ip)
	return err
}

func (s *Store) AddAllow(routeID, domain string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO allowlist (route_id,domain) VALUES (?,?)`,
		strings.ToLower(routeID), normalizeDomain(domain))
	return err
}

func (s *Store) RemoveAllow(routeID, domain string) error {
	_, err := s.db.Exec(`DELETE FROM allowlist WHERE route_id=? AND domain=?`,
		strings.ToLower(routeID), normalizeDomain(domain))
	return err
}

func (s *Store) SetOverride(routeID, domain, answer string) error {
	if _, err := netip.ParseAddr(answer); err != nil {
		return fmt.Errorf("answer must be an IP address: %w", err)
	}
	_, err := s.db.Exec(
		`INSERT INTO overrides (route_id,domain,answer) VALUES (?,?,?)
		 ON CONFLICT(route_id,domain) DO UPDATE SET answer=excluded.answer`,
		strings.ToLower(routeID), normalizeDomain(domain), answer)
	return err
}

func (s *Store) RemoveOverride(routeID, domain string) error {
	_, err := s.db.Exec(`DELETE FROM overrides WHERE route_id=? AND domain=?`,
		strings.ToLower(routeID), normalizeDomain(domain))
	return err
}
