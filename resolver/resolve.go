package resolver

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Metrics are exposed in Prometheus text format on the admin listener.
type Metrics struct {
	Queries    atomic.Uint64
	Blocked    atomic.Uint64
	Overridden atomic.Uint64
	Allowed    atomic.Uint64
	Refused    atomic.Uint64
	CacheHits  atomic.Uint64
	Upstream   atomic.Uint64
	UpstreamNG atomic.Uint64
}

type Resolver struct {
	cfg   Config
	store *Store
	block *Blocklist
	cache *Cache
	m     *Metrics

	udpClient *dns.Client
	tcpClient *dns.Client
	nextUp    atomic.Uint32
}

func NewResolver(cfg Config, store *Store, block *Blocklist, cache *Cache, m *Metrics) *Resolver {
	return &Resolver{
		cfg:       cfg,
		store:     store,
		block:     block,
		cache:     cache,
		m:         m,
		udpClient: &dns.Client{Net: "udp", Timeout: 4 * time.Second},
		tcpClient: &dns.Client{Net: "tcp", Timeout: 6 * time.Second},
	}
}

// identity is how a query is attributed to a tenant. The tenant lookup happens
// per query rather than per connection, so revoking access takes effect on a
// long-lived DoT connection without waiting for the client to reconnect.
type identity struct {
	routeID string // set when identified from the TLS SNI
	ip      string // set when identified from the source address
	via     string // "sni" or "ip"
}

func (r *Resolver) tenantFor(id identity) *Tenant {
	if id.via == "ip" {
		return r.store.TenantByIP(id.ip)
	}
	return r.store.Tenant(id.routeID)
}

// Resolve runs one query through the policy pipeline and returns the reply.
// req must contain exactly one question, which is true of essentially all real
// DNS traffic.
func (r *Resolver) Resolve(req *dns.Msg, id identity) *dns.Msg {
	r.m.Queries.Add(1)

	if len(req.Question) != 1 {
		return errorReply(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	now := time.Now().Unix()

	// Unidentified or lapsed tenants get REFUSED rather than an answer. This is
	// the only thing stopping the resolver being an open amplifier.
	tenant := r.tenantFor(id)
	if !tenant.Active(now) {
		r.m.Refused.Add(1)
		return errorReply(req, dns.RcodeRefused)
	}

	name := normalizeDomain(q.Name)
	routeID := tenant.RouteID

	// Allowlist wins over everything. A customer who cannot reach their bank
	// needs a fix that beats both the blocklist and any override.
	allowed := r.store.Allowed(routeID, name)
	if allowed {
		r.m.Allowed.Add(1)
	}

	if !allowed {
		// Overrides come next: answer with our own address so the connection
		// lands on the proxy tier instead of the real destination.
		if addr, ok := r.store.Override(routeID, name); ok {
			if reply, handled := overrideReply(req, q, addr); handled {
				r.m.Overridden.Add(1)
				return reply
			}
		}

		if tenant.Filtering(now) && r.block.Blocked(name) {
			r.m.Blocked.Add(1)
			return blockedReply(req)
		}
	}

	if cached, ok := r.cache.Get(q); ok {
		r.m.CacheHits.Add(1)
		cached.Id = req.Id
		cached.Question = req.Question
		return cached
	}

	reply, err := r.forward(req)
	if err != nil {
		r.m.UpstreamNG.Add(1)
		return errorReply(req, dns.RcodeServerFailure)
	}
	r.m.Upstream.Add(1)
	r.cache.Put(q, reply)

	reply.Id = req.Id
	return reply
}

// forward sends the query upstream, trying each configured resolver in turn.
func (r *Resolver) forward(req *dns.Msg) (*dns.Msg, error) {
	ups := r.cfg.Upstreams
	if len(ups) == 0 {
		return nil, errors.New("no upstreams configured")
	}

	// Start at a rotating offset so load spreads across upstreams.
	start := int(r.nextUp.Add(1)) % len(ups)

	out := req.Copy()
	out.Id = dns.Id()

	var lastErr error
	for i := 0; i < len(ups); i++ {
		addr := ups[(start+i)%len(ups)]

		reply, _, err := r.udpClient.Exchange(out, addr)
		if err == nil && reply != nil && reply.Truncated {
			reply, _, err = r.tcpClient.Exchange(out, addr)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if reply == nil {
			lastErr = errors.New("empty reply from upstream")
			continue
		}
		return reply, nil
	}
	return nil, lastErr
}

// overrideReply synthesises an answer pointing at our own address. It only
// handles A and AAAA; anything else falls through to the normal path so we do
// not accidentally break MX, TXT or SRV lookups for an overridden domain.
func overrideReply(req *dns.Msg, q dns.Question, addr netip.Addr) (*dns.Msg, bool) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	const overrideTTL = 60
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: overrideTTL}

	switch q.Qtype {
	case dns.TypeA:
		if !addr.Is4() {
			// An IPv6 override cannot answer an A query. Return an empty
			// NOERROR so the client falls back to AAAA rather than leaking
			// the real address.
			return m, true
		}
		m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(addr.AsSlice())})
		return m, true

	case dns.TypeAAAA:
		if !addr.Is6() || addr.Is4In6() {
			// Likewise: an IPv4 override must not answer AAAA, or the client
			// would prefer IPv6 and bypass the proxy entirely.
			return m, true
		}
		m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(addr.AsSlice())})
		return m, true

	case dns.TypeHTTPS, dns.TypeSVCB:
		// HTTPS/SVCB records carry their own address hints, which would route
		// around the override. Answer empty so the client uses A/AAAA.
		return m, true
	}

	return nil, false
}

// blockedReply answers a filtered name with NXDOMAIN, which clients handle
// faster and more predictably than a null address.
func blockedReply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	m.Authoritative = true
	m.Ns = append(m.Ns, blockSOA(req.Question[0].Name))
	return m
}

// blockSOA gives the negative answer a short TTL so unblocking takes effect
// quickly when a customer hits the pause control.
func blockSOA(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "localhost.",
		Mbox:    "hostmaster.localhost.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}

func errorReply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return m
}
