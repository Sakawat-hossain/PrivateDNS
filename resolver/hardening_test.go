package resolver

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---- rate limiting ----

func TestRateLimiterAllowsBurstThenThrottles(t *testing.T) {
	// 10/s sustained, burst of 5: the first five are free, the sixth is not.
	rl := NewRateLimiter(10, 5, 0)

	for i := 0; i < 5; i++ {
		if !rl.Allow("t1") {
			t.Fatalf("query %d should have been allowed within the burst", i+1)
		}
	}
	if rl.Allow("t1") {
		t.Fatal("the sixth query should have exceeded the burst")
	}
}

func TestRateLimiterRefills(t *testing.T) {
	rl := NewRateLimiter(100, 1, 0)

	if !rl.Allow("t1") {
		t.Fatal("first query should be allowed")
	}
	if rl.Allow("t1") {
		t.Fatal("second immediate query should be throttled")
	}

	// At 100/s a token is back in 10ms; allow generous slack for slow CI.
	time.Sleep(50 * time.Millisecond)
	if !rl.Allow("t1") {
		t.Fatal("a token should have refilled")
	}
}

func TestRateLimiterIsolatesTenants(t *testing.T) {
	rl := NewRateLimiter(10, 1, 0)

	if !rl.Allow("tenant-a") {
		t.Fatal("tenant-a first query should be allowed")
	}
	if rl.Allow("tenant-a") {
		t.Fatal("tenant-a should now be throttled")
	}
	// One tenant exhausting its bucket must not affect another.
	if !rl.Allow("tenant-b") {
		t.Fatal("tenant-b must have its own bucket")
	}
}

func TestNilRateLimiterAllowsEverything(t *testing.T) {
	var rl *RateLimiter // rate limiting disabled
	for i := 0; i < 100; i++ {
		if !rl.Allow("anyone") {
			t.Fatal("a nil limiter must allow every query")
		}
	}
	release, ok := rl.AcquireConn("anyone")
	if !ok {
		t.Fatal("a nil limiter must grant connections")
	}
	release()
}

func TestConnectionLimitPerTenant(t *testing.T) {
	rl := NewRateLimiter(10, 10, 2)

	r1, ok := rl.AcquireConn("t1")
	if !ok {
		t.Fatal("first connection should be granted")
	}
	r2, ok := rl.AcquireConn("t1")
	if !ok {
		t.Fatal("second connection should be granted")
	}
	if _, ok := rl.AcquireConn("t1"); ok {
		t.Fatal("third connection should exceed the limit")
	}

	// Releasing frees a slot, and a double release must not corrupt the count.
	r1()
	r1()
	if _, ok := rl.AcquireConn("t1"); !ok {
		t.Fatal("a slot should be free after release")
	}
	r2()
}

func TestThrottledTenantIsRefused(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.Reload()
	// 0.01 qps means a token takes 100s to refill, so the dead upstream's
	// multi-second timeout cannot replenish the bucket mid-test.
	r.WithRateLimiter(NewRateLimiter(0.01, 1, 0))

	first := r.Resolve(query("example.com", dns.TypeA), identity{routeID: "live", via: "sni"})
	if first.Rcode == dns.RcodeRefused {
		t.Fatal("the first query should not be throttled")
	}

	second := r.Resolve(query("example.com", dns.TypeA), identity{routeID: "live", via: "sni"})
	if second.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED once the bucket is empty", dns.RcodeToString[second.Rcode])
	}
	if got := r.m.Throttled.Load(); got != 1 {
		t.Fatalf("throttled counter = %d, want 1", got)
	}
}

// ---- malformed input ----

func TestMalformedQuestionsAreRejected(t *testing.T) {
	r, store := newTestResolver(t)
	store.CreateTenant("live", "", time.Now().Add(time.Hour).Unix())
	store.Reload()
	id := identity{routeID: "live", via: "sni"}

	t.Run("no question", func(t *testing.T) {
		m := new(dns.Msg)
		m.Id = dns.Id()
		if got := r.Resolve(m, id); got.Rcode != dns.RcodeFormatError {
			t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[got.Rcode])
		}
	})

	t.Run("multiple questions", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion("a.example.", dns.TypeA)
		m.Question = append(m.Question, dns.Question{
			Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		})
		if got := r.Resolve(m, id); got.Rcode != dns.RcodeFormatError {
			t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[got.Rcode])
		}
	})

	t.Run("non-internet class", func(t *testing.T) {
		// CHAOS queries are a fingerprinting tool, not something to serve.
		m := new(dns.Msg)
		m.SetQuestion("version.bind.", dns.TypeTXT)
		m.Question[0].Qclass = dns.ClassCHAOS
		if got := r.Resolve(m, id); got.Rcode != dns.RcodeFormatError {
			t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[got.Rcode])
		}
	})
}

// FuzzUnpackAndResolve feeds arbitrary bytes through the same parse-then-serve
// path a network client reaches. Any panic here is a remotely triggerable
// crash, so the assertion is simply that the resolver survives.
func FuzzUnpackAndResolve(f *testing.F) {
	seeds := [][]byte{}
	for _, name := range []string{"example.com.", "a.b.c.d.example.", "."} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		if b, err := m.Pack(); err == nil {
			seeds = append(seeds, b)
		}
	}
	edns := new(dns.Msg)
	edns.SetQuestion("example.com.", dns.TypeAAAA)
	edns.SetEdns0(4096, true)
	if b, err := edns.Pack(); err == nil {
		seeds = append(seeds, b)
	}
	seeds = append(seeds, []byte{}, []byte{0x00}, []byte{0xff, 0xff, 0xff, 0xff})

	for _, s := range seeds {
		f.Add(s)
	}

	store, err := OpenStore(filepath.Join(f.TempDir(), "fuzz.db"))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { store.Close() })
	store.CreateTenant("fuzz", "", time.Now().Add(time.Hour).Unix())
	store.SetOverride("*", "example.com", "203.0.113.5")
	store.Reload()

	cfg := DefaultConfig()
	cfg.Upstreams = []string{"127.0.0.1:1"} // never reachable; policy decides first
	res := NewResolver(cfg, store, NewBlocklist(f.TempDir()), NewCache(), &Metrics{})

	f.Fuzz(func(t *testing.T, data []byte) {
		req := new(dns.Msg)
		if err := req.Unpack(data); err != nil {
			return // rejected at the parser, which is the correct outcome
		}

		reply := res.Resolve(req, identity{routeID: "fuzz", via: "sni"})
		if reply == nil {
			t.Fatal("resolver returned a nil reply")
		}
		// Whatever came in, what goes out must be serialisable — otherwise the
		// listener cannot write it and the connection dies.
		if _, err := reply.Pack(); err != nil {
			t.Fatalf("reply could not be packed: %v", err)
		}
	})
}

// FuzzRouteIDFromSNI checks the tenant extractor against arbitrary server
// names, since the SNI is entirely attacker-controlled.
func FuzzRouteIDFromSNI(f *testing.F) {
	for _, s := range []string{
		"abc.dns.example.com", "dns.example.com", "", ".", "..",
		"a.b.dns.example.com", "ABC.DNS.EXAMPLE.COM",
		"abc.dns.example.com.evil.net", "\x00.dns.example.com",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, sni string) {
		got := routeIDFromSNI(sni, "dns.example.com")
		if got == "" {
			return
		}
		// A returned tenant must be exactly one label: never empty, never
		// dotted, or it would not correspond to a real hostname.
		if strings_Contains(got, ".") {
			t.Fatalf("routeIDFromSNI(%q) = %q, which contains a dot", sni, got)
		}
		if len(got) > 63 {
			t.Fatalf("routeIDFromSNI(%q) returned a %d-character label", sni, len(got))
		}
	})
}

// strings_Contains avoids importing strings solely for the fuzz assertion.
func strings_Contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---- EDNS handling ----

func TestStripECSRemovesClientSubnet(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(4096)
	ecs := &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: net.ParseIP("203.0.113.0"),
	}
	nsid := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}
	opt.Option = append(opt.Option, ecs, nsid)
	req.Extra = append(req.Extra, opt)

	out := prepareUpstream(req, true)

	outOpt := out.IsEdns0()
	if outOpt == nil {
		t.Fatal("EDNS0 record was dropped entirely")
	}
	for _, o := range outOpt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			t.Fatal("client subnet survived stripping")
		}
	}
	// Other options must be preserved; only ECS is a privacy problem.
	if len(outOpt.Option) != 1 {
		t.Fatalf("got %d options, want 1 (NSID kept)", len(outOpt.Option))
	}
}

func TestPrepareUpstreamClampsBufferSize(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(65535, false) // absurdly large, would fragment

	out := prepareUpstream(req, true)
	if got := out.IsEdns0().UDPSize(); got != maxUDPSize {
		t.Fatalf("advertised buffer = %d, want it clamped to %d", got, maxUDPSize)
	}
}

func TestPrepareUpstreamAddsEDNSWhenAbsent(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	out := prepareUpstream(req, true)
	opt := out.IsEdns0()
	if opt == nil {
		t.Fatal("EDNS0 should have been added")
	}
	if opt.Do() {
		// The client did not ask for DNSSEC records, so we must not either.
		t.Fatal("DO bit must not be set when the client did not request it")
	}
}

func TestSynthesizedAnswerNeverClaimsDNSSECValidation(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("blocked.example.", dns.TypeA)
	req.SetEdns0(4096, true) // client wants DNSSEC

	reply := blockedReply(req)
	reply.AuthenticatedData = true // simulate it being set upstream
	setSynthesizedEDNS(reply, req)

	if reply.AuthenticatedData {
		t.Fatal("AD must be cleared: a synthesized answer was never validated")
	}
	if opt := reply.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatal("the client's DO bit should be echoed back")
	}
}

// ---- health ----

func TestReadyFailsWhenUpstreamIsUnreachable(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := DefaultConfig()
	cfg.ListenDoT, cfg.ListenDoH = "", "" // skip the certificate check
	cfg.Upstreams = []string{"127.0.0.1:1"}

	h := NewHealth(cfg, store, NewBlocklist(t.TempDir()), "test")
	report := h.Ready(context.Background())

	if report.OK {
		t.Fatal("readiness should fail when no upstream answers")
	}

	var found bool
	for _, c := range report.Checks {
		if c.Name == "upstream" {
			found = true
			if c.OK {
				t.Fatal("the upstream check should have failed")
			}
		}
	}
	if !found {
		t.Fatal("no upstream check was reported")
	}
}

func TestReadyReportsSchemaVersion(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := DefaultConfig()
	cfg.ListenDoT, cfg.ListenDoH = "", ""

	h := NewHealth(cfg, store, NewBlocklist(t.TempDir()), "test")
	for _, c := range h.Ready(context.Background()).Checks {
		if c.Name == "schema" && !c.OK {
			t.Fatalf("schema check failed: %s", c.Detail)
		}
	}
}

func TestLivenessIsIndependentOfDependencies(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := DefaultConfig()
	cfg.Upstreams = []string{"127.0.0.1:1"}
	h := NewHealth(cfg, store, NewBlocklist(t.TempDir()), "test")

	// Liveness must stay true even with everything else broken, or an
	// orchestrator will kill a process that would have recovered.
	if !h.Live() {
		t.Fatal("liveness must not depend on external state")
	}
}

// ---- migrations ----

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")

	s1, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := s1.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()

	// Reopening must not re-run anything or fail.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopening a migrated database failed: %v", err)
	}
	defer s2.Close()

	v2, err := s2.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 || v2 != SchemaVersion() {
		t.Fatalf("schema version drifted: %d then %d, expected %d", v1, v2, SchemaVersion())
	}
}

func TestMigrationsPreserveData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")

	s1, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.CreateTenant("survivor", "before upgrade", time.Now().Add(time.Hour).Unix())
	s1.Close()

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if tn := s2.Tenant("survivor"); tn == nil {
		t.Fatal("tenant did not survive reopening")
	} else if tn.Label != "before upgrade" {
		t.Fatalf("label = %q, want %q", tn.Label, "before upgrade")
	}
}

// ---- usage accounting ----

func TestUsageCollectorAggregatesAndFlushes(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.CreateTenant("t1", "", time.Now().Add(time.Hour).Unix())

	u := NewUsageCollector(store)
	u.Record("t1", false, false, false)
	u.Record("t1", true, false, false)
	u.Record("t1", false, true, false)
	u.Record("t1", false, false, true)

	if got := u.PendingTenants(); got != 1 {
		t.Fatalf("pending tenants = %d, want 1", got)
	}
	if err := u.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := u.PendingTenants(); got != 0 {
		t.Fatalf("pending after flush = %d, want 0", got)
	}

	usage, ok := store.Usage("t1")
	if !ok {
		t.Fatal("no usage row was written")
	}
	if usage.Queries != 4 {
		t.Fatalf("queries = %d, want 4", usage.Queries)
	}
	if usage.Blocked != 1 || usage.Overridden != 1 || usage.Throttled != 1 {
		t.Fatalf("counters = blocked %d, overridden %d, throttled %d; want 1 each",
			usage.Blocked, usage.Overridden, usage.Throttled)
	}
}

func TestUsageAccumulatesAcrossFlushes(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.CreateTenant("t1", "", time.Now().Add(time.Hour).Unix())

	u := NewUsageCollector(store)
	u.Record("t1", false, false, false)
	u.Flush()
	u.Record("t1", false, false, false)
	u.Flush()

	usage, _ := store.Usage("t1")
	if usage.Queries != 2 {
		t.Fatalf("queries = %d, want 2 accumulated across flushes", usage.Queries)
	}
}

func TestNilUsageCollectorIsSafe(t *testing.T) {
	var u *UsageCollector
	u.Record("anyone", true, true, true)
	if err := u.Flush(); err != nil {
		t.Fatalf("flushing a nil collector should be a no-op, got %v", err)
	}
}

// ---- configuration ----

func TestConfigEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"base_domain":"file.example.com","upstreams":["1.1.1.1:53"],
	          "listen_dot":"","listen_doh":"","listen_plain":":53"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PRIVATEDNS_BASE_DOMAIN", "env.example.com")
	t.Setenv("PRIVATEDNS_UPSTREAMS", "9.9.9.9:53, 8.8.8.8:53")
	t.Setenv("PRIVATEDNS_RATE_LIMIT_QPS", "125")
	t.Setenv("PRIVATEDNS_STRIP_ECS", "false")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.BaseDomain != "env.example.com" {
		t.Fatalf("base_domain = %q, want the environment to win over the file", cfg.BaseDomain)
	}
	if len(cfg.Upstreams) != 2 || cfg.Upstreams[1] != "8.8.8.8:53" {
		t.Fatalf("upstreams = %v, want the comma-separated list parsed and trimmed", cfg.Upstreams)
	}
	if cfg.RateLimitQPS != 125 {
		t.Fatalf("rate_limit_qps = %v, want 125", cfg.RateLimitQPS)
	}
	if cfg.StripECS {
		t.Fatal("strip_ecs should have been overridden to false")
	}
}

func TestConfigYAMLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteSample(path); err != nil {
		t.Fatal(err)
	}

	// The sample must itself be valid, or a fresh install fails on first run.
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("the generated sample config does not load: %v", err)
	}
	if cfg.BaseDomain == "" {
		t.Fatal("base_domain was lost in the round trip")
	}

	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix file modes")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file carries admin tokens, so it must not be world-readable.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("sample config mode = %o, want no group or other access", perm)
	}
}

func TestConfigValidationRejectsBadInput(t *testing.T) {
	cases := map[string]func(*Config){
		"empty base domain":     func(c *Config) { c.BaseDomain = "" },
		"unqualified domain":    func(c *Config) { c.BaseDomain = "localhost" },
		"no upstreams":          func(c *Config) { c.Upstreams = nil },
		"no listeners":          func(c *Config) { c.ListenDoT, c.ListenDoH, c.ListenPlain = "", "", "" },
		"bad log level":         func(c *Config) { c.LogLevel = "verbose" },
		"zero burst with a qps": func(c *Config) { c.RateLimitBurst = 0 },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation to reject this configuration")
			}
		})
	}
}

func TestConfigDefaultsUpstreamPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstreams = []string{"9.9.9.9"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Upstreams[0] != "9.9.9.9:53" {
		t.Fatalf("upstream = %q, want the DNS port appended", cfg.Upstreams[0])
	}
}

// ---- logging ----

func TestRedactNameKeepsOnlyTheParentDomain(t *testing.T) {
	cases := map[string]string{
		"tracker.ads.example.com": "example.com",
		"example.com":             "example.com",
		"com":                     "(redacted)",
	}
	for in, want := range cases {
		if got := redactName(in); got != want {
			t.Errorf("redactName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A hosts file opens with the loopback preamble, and the parser reads
// "127.0.0.1 localhost" as an instruction to block localhost. StevenBlack's
// list -- one of the feeds fetch-blocklists.sh installs -- starts with exactly
// those lines, so this is not hypothetical.
func TestBlocklistIgnoresTheLoopbackPreamble(t *testing.T) {
	dir := t.TempDir()
	body := `# Title: a hosts-format feed
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 ip6-localhost
::1 ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net
`
	if err := os.WriteFile(filepath.Join(dir, "feed.txt"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	b := NewBlocklist(dir)
	if _, err := b.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, name := range []string{
		"localhost", "localhost.localdomain", "local",
		"broadcasthost", "ip6-localhost", "ip6-loopback",
		"ip6-localnet", "ip6-mcastprefix",
	} {
		if b.Blocked(name) {
			t.Errorf("%q is blocked; a feed's loopback preamble must never become a rule", name)
		}
	}

	for _, name := range []string{"ads.example.com", "tracker.example.net"} {
		if !b.Blocked(name) {
			t.Errorf("%q is not blocked; real entries must still load", name)
		}
	}
}

// The parser drops any line carrying a "*". Hagezi publishes a wildcard and a
// plain-domain edition under near-identical names, and choosing the wildcard
// one yields a feed that loads without error and blocks nothing at all.
func TestBlocklistSkipsWildcardEntries(t *testing.T) {
	dir := t.TempDir()
	body := "*.ads.example.com\n*.tracker.example.net\nreal.example.org\n"
	if err := os.WriteFile(filepath.Join(dir, "feed.txt"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	b := NewBlocklist(dir)
	n, err := b.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n != 1 {
		t.Fatalf("loaded %d entries, want 1 -- wildcard lines must be skipped", n)
	}
	if !b.Blocked("real.example.org") {
		t.Error("the one plain domain should be blocked")
	}
}

// A fresh install has no certificate. Refusing to start until one exists took
// down the admin endpoint too -- the very thing needed to see what was wrong --
// and systemd restarted the process every three seconds while the operator
// worked through setup. One real install reached restart 308.
func TestStartsWithoutACertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.BaseDomain = "dns.example.com"
	cfg.CertFile = filepath.Join(dir, "absent-fullchain.pem")
	cfg.KeyFile = filepath.Join(dir, "absent-privkey.pem")
	cfg.ListenDoT = ":8853"
	cfg.ListenDoH = ":8443"

	if HaveCert(cfg) {
		t.Fatal("HaveCert reports a certificate that is not there")
	}

	tlsCfg, err := LoadTLS(cfg)
	if err != nil {
		t.Fatalf("LoadTLS refused to build a config without a certificate: %v", err)
	}
	if tlsCfg == nil || tlsCfg.GetCertificate == nil {
		t.Fatal("LoadTLS returned an unusable config")
	}

	// Handshakes must fail while there is no certificate -- serving one that
	// does not exist is not the alternative being asked for here.
	if _, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Error("GetCertificate succeeded with no certificate on disk")
	}
}

// And once the certificate appears it must be picked up without a restart,
// which is the whole reason GetCertificate re-reads from disk.
func TestPicksUpACertificateWrittenAfterStartup(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.CertFile = filepath.Join(dir, "fullchain.pem")
	cfg.KeyFile = filepath.Join(dir, "privkey.pem")
	cfg.ListenDoT = ":8853"

	tlsCfg, err := LoadTLS(cfg)
	if err != nil {
		t.Fatalf("LoadTLS: %v", err)
	}
	if _, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("a certificate was served before one existed")
	}

	writeTestCert(t, cfg.CertFile, cfg.KeyFile)

	if !HaveCert(cfg) {
		t.Fatal("HaveCert does not see the certificate just written")
	}
	if _, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Errorf("certificate written after startup was not picked up: %v", err)
	}
}
