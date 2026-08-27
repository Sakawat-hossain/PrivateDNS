package resolver

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestPrivateTargetsAreRecognised(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", // cloud metadata, the highest-value target
		"100.64.0.1",      // carrier-grade NAT
		"0.0.0.0", "240.0.0.1",
		"::1", "fd00::1", "fe80::1",
	}
	for _, s := range private {
		if !isPrivateTarget(netip.MustParseAddr(s)) {
			t.Errorf("%s was not recognised as private", s)
		}
	}

	public := []string{"1.1.1.1", "8.8.8.8", "203.0.113.10", "2606:4700::1111"}
	for _, s := range public {
		if isPrivateTarget(netip.MustParseAddr(s)) {
			t.Errorf("%s was wrongly treated as private", s)
		}
	}

	if !isPrivateTarget(netip.Addr{}) {
		t.Error("an invalid address should be treated as unsafe")
	}
}

func answerWith(name string, addrs ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)

	for _, a := range addrs {
		ip := net.ParseIP(a)
		hdr := dns.RR_Header{Name: dns.Fqdn(name), Class: dns.ClassINET, Ttl: 60}
		if ip.To4() != nil {
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
		}
	}
	return m
}

// TestRebindingAnswerIsStripped is the attack this exists to stop: an
// attacker-controlled name answering with an address on the victim's own
// network, so their browser becomes a way in.
func TestRebindingAnswerIsStripped(t *testing.T) {
	p := rebindPolicy{enabled: true}

	msg := answerWith("evil.example", "192.168.1.1")
	removed := filterRebind(msg, "evil.example", p)

	if removed != 1 {
		t.Fatalf("removed %d records, want 1", removed)
	}
	if len(msg.Answer) != 0 {
		t.Fatalf("%d answers survived, want none", len(msg.Answer))
	}
}

// TestOnlyPrivateRecordsAreDropped covers the mixed case.
//
// Refusing the whole response would hand an attacker a denial-of-service: get
// a victim to look up any name, include one private record, and the name stops
// resolving entirely.
func TestOnlyPrivateRecordsAreDropped(t *testing.T) {
	p := rebindPolicy{enabled: true}

	msg := answerWith("mixed.example", "203.0.113.10", "10.0.0.1", "1.1.1.1")
	removed := filterRebind(msg, "mixed.example", p)

	if removed != 1 {
		t.Fatalf("removed %d, want 1", removed)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("%d public answers survived, want 2", len(msg.Answer))
	}
	for _, rr := range msg.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if addr, _ := netip.AddrFromSlice(a.A.To4()); isPrivateTarget(addr) {
			t.Fatalf("a private address survived: %s", a.A)
		}
	}
}

func TestPublicAnswersAreUntouched(t *testing.T) {
	p := rebindPolicy{enabled: true}

	msg := answerWith("example.com", "203.0.113.10", "2606:4700::1111")
	if removed := filterRebind(msg, "example.com", p); removed != 0 {
		t.Fatalf("removed %d records from a wholly public answer", removed)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("%d answers survived, want 2", len(msg.Answer))
	}
}

// TestSplitHorizonExemption keeps a real and common arrangement working: an
// internal name resolving to private space is correct on a corporate network.
func TestSplitHorizonExemption(t *testing.T) {
	p := rebindPolicy{enabled: true, allowedSuffixes: []string{"internal.example"}}

	msg := answerWith("nas.internal.example", "10.0.0.5")
	if removed := filterRebind(msg, "nas.internal.example", p); removed != 0 {
		t.Fatal("an exempt name had its private answer stripped")
	}

	// The exemption is by suffix on a label boundary, so a lookalike must not
	// inherit it.
	msg = answerWith("evil-internal.example", "10.0.0.5")
	if removed := filterRebind(msg, "evil-internal.example", p); removed != 1 {
		t.Fatal("a lookalike name inherited the exemption")
	}

	msg = answerWith("internal.example.evil.net", "10.0.0.5")
	if removed := filterRebind(msg, "internal.example.evil.net", p); removed != 1 {
		t.Fatal("a name merely containing the exempt suffix was exempted")
	}
}

func TestFilteringCanBeDisabled(t *testing.T) {
	p := rebindPolicy{enabled: false}

	msg := answerWith("lab.example", "192.168.1.1")
	if removed := filterRebind(msg, "lab.example", p); removed != 0 {
		t.Fatal("filtering ran while disabled")
	}
}

func TestNonAddressRecordsAreLeftAlone(t *testing.T) {
	p := rebindPolicy{enabled: true}

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeMX)
	m.Answer = append(m.Answer, &dns.MX{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
		Preference: 10, Mx: "mail.example.com.",
	})
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{"v=spf1 -all"},
	})

	// These carry no address to rebind to. A CNAME's target is resolved
	// separately and filtered on that lookup.
	if removed := filterRebind(m, "example.com", p); removed != 0 {
		t.Fatalf("removed %d non-address records", removed)
	}
	if len(m.Answer) != 2 {
		t.Fatalf("%d records survived, want 2", len(m.Answer))
	}
}

func TestRebindPolicyFromConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.BlockRebind {
		t.Fatal("rebinding protection should be on by default")
	}

	cfg.RebindAllowDomains = []string{"Internal.Example.", "  lab.test  "}
	p := newRebindPolicy(cfg)

	if !p.exempt("nas.internal.example") {
		t.Error("the exemption was not normalised to lower case")
	}
	if !p.exempt("box.lab.test") {
		t.Error("a whitespace-padded exemption was not trimmed")
	}
	if p.exempt("example.com") {
		t.Error("an unrelated name was exempted")
	}
}
