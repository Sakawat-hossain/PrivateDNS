package resolver

import (
	"errors"
	"log/slog"
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
	Throttled  atomic.Uint64
	Malformed  atomic.Uint64
	CacheHits  atomic.Uint64
	Upstream   atomic.Uint64
	UpstreamNG atomic.Uint64
}

type Resolver struct {
	cfg     Config
	store   Store
	block   *Blocklist
	cache   *Cache
	m       *Metrics
	limiter *RateLimiter
	usage   *UsageCollector
	log     *slog.Logger

	udpClient *dns.Client
	tcpClient *dns.Client
	nextUp    atomic.Uint32
}

func NewResolver(cfg Config, store Store, block *Blocklist, cache *Cache, m *Metrics) *Resolver {
	return &Resolver{
		cfg:       cfg,
		store:     store,
		block:     block,
		cache:     cache,
		m:         m,
		log:       slog.Default(),
		udpClient: &dns.Client{Net: "udp", Timeout: 4 * time.Second, UDPSize: maxUDPSize},
		tcpClient: &dns.Client{Net: "tcp", Timeout: 6 * time.Second},
	}
}

// WithRateLimiter attaches a limiter. A nil limiter disables rate limiting.
func (r *Resolver) WithRateLimiter(l *RateLimiter) *Resolver { r.limiter = l; return r }

// WithUsage attaches the usage collector.
func (r *Resolver) WithUsage(u *UsageCollector) *Resolver { r.usage = u; return r }

// WithLogger attaches a structured logger.
func (r *Resolver) WithLogger(l *slog.Logger) *Resolver {
	if l != nil {
		r.log = l
	}
	return r
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
func (r *Resolver) Resolve(req *dns.Msg, id identity) *dns.Msg {
	r.m.Queries.Add(1)

	// A well-formed DNS query carries exactly one question. Anything else is
	// either broken or an attempt to confuse the parser, and is rejected
	// before it reaches policy or the upstream.
	if len(req.Question) != 1 {
		r.m.Malformed.Add(1)
		return errorReply(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	if !validQuestion(q) {
		r.m.Malformed.Add(1)
		return errorReply(req, dns.RcodeFormatError)
	}

	now := time.Now().Unix()

	// Unidentified or lapsed tenants get REFUSED rather than an answer. This is
	// the only thing stopping the resolver being an open amplifier.
	tenant := r.tenantFor(id)
	if !tenant.Active(now) {
		r.m.Refused.Add(1)
		return errorReply(req, dns.RcodeRefused)
	}
	routeID := tenant.RouteID

	// A tenant hostname travels in the SNI in cleartext and customers share
	// them. Rate limiting is what stops one leaked hostname being used to
	// flood the resolver on that tenant's behalf.
	if !r.limiter.Allow(routeID) {
		r.m.Throttled.Add(1)
		r.usage.Record(routeID, false, false, true)
		return errorReply(req, dns.RcodeRefused)
	}

	name := normalizeDomain(q.Name)

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
				r.usage.Record(routeID, false, true, false)
				setSynthesizedEDNS(reply, req)
				return reply
			}
		}

		if tenant.Filtering(now) && r.block.Blocked(name) {
			r.m.Blocked.Add(1)
			r.usage.Record(routeID, true, false, false)
			reply := blockedReply(req)
			setSynthesizedEDNS(reply, req)
			return reply
		}
	}

	r.usage.Record(routeID, false, false, false)

	if cached, ok := r.cache.Get(q); ok {
		r.m.CacheHits.Add(1)
		cached.Id = req.Id
		cached.Question = req.Question
		return cached
	}

	reply, err := r.forward(req)
	if err != nil {
		r.m.UpstreamNG.Add(1)
		r.log.Debug("upstream failure", "domain", redactName(name), "err", err)
		return errorReply(req, dns.RcodeServerFailure)
	}
	r.m.Upstream.Add(1)
	r.cache.Put(q, reply)

	reply.Id = req.Id
	return reply
}

// validQuestion rejects questions that cannot be legitimate, before they reach
// the policy engine or an upstream.
func validQuestion(q dns.Question) bool {
	if q.Name == "" || len(q.Name) > 255 {
		return false
	}
	// Only the internet class is served. CHAOS and HESIOD queries are used for
	// fingerprinting and have no place here.
	if q.Qclass != dns.ClassINET {
		return false
	}
	if _, ok := dns.IsDomainName(q.Name); !ok {
		return false
	}
	return true
}

// forward sends the query upstream, trying each configured resolver in turn.
func (r *Resolver) forward(req *dns.Msg) (*dns.Msg, error) {
	ups := r.cfg.Upstreams
	if len(ups) == 0 {
		return nil, errors.New("no upstreams configured")
	}

	// Start at a rotating offset so load spreads across upstreams.
	start := int(r.nextUp.Add(1)) % len(ups)

	out := prepareUpstream(req, r.cfg.StripECS)

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
