package resolver

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRouteIDFromSNI(t *testing.T) {
	const base = "dns.example.com"

	cases := []struct {
		sni  string
		want string
	}{
		{"a1b2c3.dns.example.com", "a1b2c3"},
		{"A1B2C3.DNS.EXAMPLE.COM", "a1b2c3"},  // case-insensitive
		{"a1b2c3.dns.example.com.", "a1b2c3"}, // trailing dot
		{"dns.example.com", ""},               // bare base: no tenant
		{"", ""},
		{"evil.com", ""},
		{"a.b.dns.example.com", ""},         // deeper than one label
		{"a1b2c3.dns.example.com.evil", ""}, // suffix must match exactly
		{"xdns.example.com", ""},            // must be a real label boundary
	}

	for _, c := range cases {
		if got := routeIDFromSNI(c.sni, base); got != c.want {
			t.Errorf("routeIDFromSNI(%q) = %q, want %q", c.sni, got, c.want)
		}
	}
}

func TestDomainSuffixes(t *testing.T) {
	got := domainSuffixes("ads.tracking.example.com")
	want := []string{"ads.tracking.example.com", "tracking.example.com", "example.com", "com"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestBlocklistMatchesParents(t *testing.T) {
	dir := t.TempDir()
	list := "# comment\n0.0.0.0 tracker.example\nads.example\n\n"
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}

	b := NewBlocklist(dir)
	n, err := b.Load()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("loaded %d domains, want 2", n)
	}

	for _, name := range []string{"ads.example", "sub.ads.example", "tracker.example"} {
		if !b.Blocked(name) {
			t.Errorf("%s should be blocked", name)
		}
	}
	for _, name := range []string{"example", "notads.example", "example.com"} {
		if b.Blocked(name) {
			t.Errorf("%s should not be blocked", name)
		}
	}
}

// newTestResolver builds a resolver backed by a temporary database, with no
// reachable upstream — every test below asserts on a decision made before the
// query would be forwarded.
func newTestResolver(t *testing.T) (*Resolver, *SQLiteStore) {
	t.Helper()

	store, err := OpenStore(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("ads.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	block := NewBlocklist(dir)
	if _, err := block.Load(); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Upstreams = []string{"127.0.0.1:1"} // deliberately dead
	return NewResolver(cfg, store, block, NewCache(), &Metrics{}), store
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestUnknownTenantIsRefused(t *testing.T) {
	r, _ := newTestResolver(t)

	reply := r.Resolve(query("example.com", dns.TypeA), identity{routeID: "nobody", via: "sni"})
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[reply.Rcode])
	}
}

func TestExpiredTenantIsRefused(t *testing.T) {
	r, store := newTestResolver(t)

	if err := store.CreateTenant("lapsed", "", time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	store.Reload()

	reply := r.Resolve(query("example.com", dns.TypeA), identity{routeID: "lapsed", via: "sni"})
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED for an expired tenant", dns.RcodeToString[reply.Rcode])
	}
}

func TestBlockedNameReturnsNXDomain(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.Reload()

	reply := r.Resolve(query("ads.example", dns.TypeA), identity{routeID: "live", via: "sni"})
	if reply.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[reply.Rcode])
	}
}

func TestAllowlistBeatsBlocklist(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.AddAllow("live", "ads.example")
	store.Reload()

	// The upstream is dead, so an allowlisted name should fail forwarding with
	// SERVFAIL rather than being answered NXDOMAIN by the filter.
	reply := r.Resolve(query("ads.example", dns.TypeA), identity{routeID: "live", via: "sni"})
	if reply.Rcode == dns.RcodeNameError {
		t.Fatal("allowlisted name was blocked")
	}
	if reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL (dead upstream)", dns.RcodeToString[reply.Rcode])
	}
}

func TestOverrideAnswersWithProxyAddress(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.SetOverride("*", "bkash.com", "203.0.113.10")
	store.Reload()

	// A subdomain must match the parent rule, the way a wildcard hijack does.
	reply := r.Resolve(query("api.bkash.com", dns.TypeA), identity{routeID: "live", via: "sni"})
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(reply.Answer))
	}
	a, ok := reply.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type %T, want *dns.A", reply.Answer[0])
	}
	if a.A.String() != "203.0.113.10" {
		t.Fatalf("answer = %s, want 203.0.113.10", a.A)
	}
}

// An IPv4 override must not leak a real AAAA record, or a dual-stack client
// would prefer IPv6 and route straight past the proxy.
func TestIPv4OverrideSuppressesAAAA(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.SetOverride("*", "bkash.com", "203.0.113.10")
	store.Reload()

	reply := r.Resolve(query("bkash.com", dns.TypeAAAA), identity{routeID: "live", via: "sni"})
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[reply.Rcode])
	}
	if len(reply.Answer) != 0 {
		t.Fatalf("got %d AAAA answers, want 0", len(reply.Answer))
	}
}

func TestSourceIPIdentification(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.RegisterIP("live", "198.51.100.7")
	store.Reload()

	reply := r.Resolve(query("ads.example", dns.TypeA), identity{ip: "198.51.100.7", via: "ip"})
	if reply.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN for a recognised IP", dns.RcodeToString[reply.Rcode])
	}

	reply = r.Resolve(query("ads.example", dns.TypeA), identity{ip: "198.51.100.8", via: "ip"})
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED for an unregistered IP", dns.RcodeToString[reply.Rcode])
	}
}

func TestPauseDisablesFiltering(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.PauseFiltering("live", time.Now().Add(5*time.Minute).Unix())
	store.Reload()

	reply := r.Resolve(query("ads.example", dns.TypeA), identity{routeID: "live", via: "sni"})
	if reply.Rcode == dns.RcodeNameError {
		t.Fatal("filtering was paused but the name was still blocked")
	}
}

func TestRevocationTakesEffectOnReload(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.Reload()

	if got := r.Resolve(query("ads.example", dns.TypeA), identity{routeID: "live", via: "sni"}); got.Rcode != dns.RcodeNameError {
		t.Fatalf("setup: rcode = %s", dns.RcodeToString[got.Rcode])
	}

	store.SetStatus("live", "suspended")
	store.Reload()

	reply := r.Resolve(query("ads.example", dns.TypeA), identity{routeID: "live", via: "sni"})
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED after suspension", dns.RcodeToString[reply.Rcode])
	}
}

func TestNewRouteIDAvoidsLookAlikeCharacters(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := NewRouteID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 10 {
			t.Fatalf("id %q has length %d, want 10", id, len(id))
		}
		for _, c := range id {
			switch c {
			case 'i', 'l', 'o', '0', '1':
				t.Fatalf("id %q contains an ambiguous character %q", id, c)
			}
		}
		if seen[id] {
			t.Fatalf("duplicate id %q after %d draws", id, i)
		}
		seen[id] = true
	}
}
