package resolver

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// DNS rebinding turns a resolver into a way through someone else's firewall.
//
// The attack: a page on evil.example resolves that name, gets the attacker's
// real address, and loads. The attacker's authoritative server then answers the
// same name with 192.168.1.1 on a short TTL. The victim's browser still
// considers the page same-origin, but the connection now goes to a device on
// the victim's home network — a router admin page, a printer, an unauthenticated
// service. The browser has become a proxy into a network the attacker cannot
// reach directly.
//
// The resolver is the right place to stop it, because it is the only component
// that sees the answer before anything acts on it. A public name has no
// legitimate reason to resolve to a private address, so those answers are
// stripped.

// rebindPolicy decides which answers are permitted.
type rebindPolicy struct {
	// enabled turns the protection off entirely. Off is wrong for a public
	// resolver and right for one serving a lab.
	enabled bool

	// allowedSuffixes are names permitted to resolve to private space.
	//
	// Split-horizon DNS is a real and common arrangement: an internal name
	// resolving to 10.x is exactly correct on a corporate network. Without an
	// exemption, protecting against rebinding would break it.
	allowedSuffixes []string
}

func newRebindPolicy(cfg Config) rebindPolicy {
	suffixes := make([]string, 0, len(cfg.RebindAllowDomains))
	for _, s := range cfg.RebindAllowDomains {
		if n := normalizeDomain(s); n != "" {
			suffixes = append(suffixes, n)
		}
	}
	return rebindPolicy{enabled: cfg.BlockRebind, allowedSuffixes: suffixes}
}

// exempt reports whether a name is allowed to resolve into private space.
func (p rebindPolicy) exempt(name string) bool {
	name = normalizeDomain(name)
	for _, suffix := range p.allowedSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// isPrivateTarget reports whether an address belongs to a range no public name
// should resolve to.
func isPrivateTarget(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsUnspecified():
		return true
	}

	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 100 && b[1]&0xC0 == 64: // 100.64.0.0/10, carrier-grade NAT
			return true
		case b[0] == 169 && b[1] == 254: // 169.254.0.0/16, cloud metadata
			return true
		case b[0] == 192 && b[1] == 0 && b[2] == 0: // 192.0.0.0/24
			return true
		case b[0] >= 240: // 240.0.0.0/4, reserved
			return true
		}
		return false
	}

	// IPv6 unique local, fc00::/7.
	if b := addr.As16(); b[0]&0xFE == 0xFC {
		return true
	}
	return false
}

// filterRebind removes private-space answers from an upstream reply.
//
// Records are dropped rather than the whole response refused. A name with one
// legitimate public address and one private one should still resolve — and an
// attacker who could turn a filtered answer into a total failure would have a
// way to deny service for any name they could get a victim to look up.
//
// Returns the number of records removed.
func filterRebind(msg *dns.Msg, name string, p rebindPolicy) int {
	if !p.enabled || msg == nil || len(msg.Answer) == 0 {
		return 0
	}
	if p.exempt(name) {
		return 0
	}

	kept := msg.Answer[:0]
	removed := 0

	for _, rr := range msg.Answer {
		var addr netip.Addr
		var ok bool

		switch v := rr.(type) {
		case *dns.A:
			addr, ok = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			addr, ok = netip.AddrFromSlice(v.AAAA.To16())
		default:
			// CNAME, MX, TXT and the rest carry no address to rebind to. The
			// name a CNAME points at is resolved separately and filtered then.
			kept = append(kept, rr)
			continue
		}

		if ok && isPrivateTarget(addr) {
			removed++
			continue
		}
		kept = append(kept, rr)
	}

	msg.Answer = kept
	return removed
}
