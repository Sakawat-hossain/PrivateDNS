package resolver

import "strings"

// normalizeDomain lowercases a name and strips the trailing dot so that
// database rows, blocklist entries and wire-format names all compare equal.
func normalizeDomain(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// domainSuffixes returns the name followed by each of its parent domains, so a
// single walk can match a rule written against any level.
//
//	"ads.tracking.example.com" ->
//	  ads.tracking.example.com, tracking.example.com, example.com, com
//
// Matching a parent is what makes a rule for "bkash.com" also cover
// "api.bkash.com" and every other label beneath it.
func domainSuffixes(name string) []string {
	name = normalizeDomain(name)
	if name == "" {
		return nil
	}
	out := []string{name}
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
		if name == "" {
			break
		}
		out = append(out, name)
	}
	return out
}

// routeIDFromSNI pulls the tenant identifier out of the TLS server name.
//
// With base "dns.example.com", a client connecting to "a1b2c3.dns.example.com"
// is tenant "a1b2c3". Connecting to the bare base returns "" — no tenant —
// which the resolver treats as unauthenticated.
func routeIDFromSNI(sni, base string) string {
	sni = normalizeDomain(sni)
	base = normalizeDomain(base)
	if sni == "" || base == "" || sni == base {
		return ""
	}
	if !strings.HasSuffix(sni, "."+base) {
		return ""
	}
	label := strings.TrimSuffix(sni, "."+base)
	// Only a single label identifies a tenant. Anything deeper is not ours.
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}
