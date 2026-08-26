package resolver

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// probeZone is the label under the base domain reserved for diagnostics. A
// lookup of "<nonce>.check.<base_domain>" is recorded rather than resolved.
const probeZone = "check"

// probeTTL is how long a recorded probe stays available to be read back. The
// diagnostic page polls within seconds; anything older is stale.
const probeTTL = 2 * time.Minute

// ProbeRecorder answers the question the diagnostic page needs: did this
// device's DNS query actually reach us, and as which tenant?
//
// The mechanism is the only one that genuinely works from a browser. A page
// cannot inspect the system resolver, but it can ask for a hostname nobody has
// ever looked up before. If that lookup arrives here, the device is using this
// resolver; if it does not, it is not. The tenant comes free, because the
// request is already identified by SNI.
//
// Probes are held in memory rather than the database. They are worthless after
// a couple of minutes, and writing one per diagnostic would put the query path
// on a disk write for a feature used once per customer.
type ProbeRecorder struct {
	mu     sync.Mutex
	seen   map[string]probeHit
	baseFQ string
}

type probeHit struct {
	RouteID string
	At      time.Time
	Proto   string
}

// ProbeResult is what a diagnostic lookup produced.
type ProbeResult struct {
	RouteID string
	At      time.Time
	Proto   string
	Found   bool
}

func NewProbeRecorder(baseDomain string) *ProbeRecorder {
	return &ProbeRecorder{
		seen:   make(map[string]probeHit),
		baseFQ: probeZone + "." + normalizeDomain(baseDomain),
	}
}

// nonceFor returns the probe nonce if name belongs to the diagnostic zone.
func (p *ProbeRecorder) nonceFor(name string) (string, bool) {
	if p == nil {
		return "", false
	}
	name = normalizeDomain(name)
	suffix := "." + p.baseFQ
	if !strings.HasSuffix(name, suffix) {
		return "", false
	}

	nonce := strings.TrimSuffix(name, suffix)
	// Exactly one label, and only characters a nonce generator produces.
	if nonce == "" || len(nonce) > 63 || strings.Contains(nonce, ".") {
		return "", false
	}
	for i := 0; i < len(nonce); i++ {
		c := nonce[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return "", false
		}
	}
	return nonce, true
}

// Record notes that a probe was seen. Older entries are swept opportunistically
// so the map cannot grow without bound.
func (p *ProbeRecorder) Record(nonce, routeID, proto string) {
	if p == nil {
		return
	}

	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.seen) > 1000 {
		for k, v := range p.seen {
			if now.Sub(v.At) > probeTTL {
				delete(p.seen, k)
			}
		}
	}
	p.seen[nonce] = probeHit{RouteID: routeID, At: now, Proto: proto}
}

// Lookup reads a probe back, once. Consuming the entry means a nonce cannot be
// replayed to make a second device look configured.
func (p *ProbeRecorder) Lookup(nonce string) ProbeResult {
	if p == nil {
		return ProbeResult{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	hit, ok := p.seen[nonce]
	if !ok || time.Since(hit.At) > probeTTL {
		delete(p.seen, nonce)
		return ProbeResult{}
	}
	delete(p.seen, nonce)

	return ProbeResult{RouteID: hit.RouteID, At: hit.At, Proto: hit.Proto, Found: true}
}

func (p *ProbeRecorder) Pending() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

// probeReply answers a diagnostic lookup.
//
// NXDOMAIN is deliberate: the name has no address and never will, and returning
// one would invite a client to connect somewhere. The lookup itself is the
// entire signal.
func probeReply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	m.Authoritative = true
	m.Ns = append(m.Ns, blockSOA(req.Question[0].Name))
	return m
}
