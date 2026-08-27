package resolver

import "github.com/miekg/dns"

// maxUDPSize is the EDNS0 buffer size we advertise upstream. 1232 is the value
// the DNS Flag Day 2020 guidance settled on: large enough to avoid needless
// truncation, small enough to stay under the smallest common path MTU and so
// avoid IP fragmentation, which firewalls frequently drop.
const maxUDPSize = 1232

// prepareUpstream returns a copy of req ready to send to an upstream resolver.
//
// The copy exists because the request belongs to the client connection; the
// upstream exchange needs its own message ID and its own EDNS options.
func prepareUpstream(req *dns.Msg, stripECS bool) *dns.Msg {
	out := req.Copy()
	out.Id = dns.Id()

	if opt := out.IsEdns0(); opt != nil {
		if stripECS {
			removeECS(opt)
		}
		// Clamp an over-large advertised buffer down to something that will
		// not fragment on the way back.
		if opt.UDPSize() > maxUDPSize {
			opt.SetUDPSize(maxUDPSize)
		}
		return out
	}

	// No EDNS0 on the request. Add one so upstreams may return larger
	// responses, and so DNSSEC-aware upstreams behave consistently. The DO bit
	// is left unset here: a client that did not ask for DNSSEC records should
	// not have them added to its answer.
	out.SetEdns0(maxUDPSize, false)
	return out
}

// removeECS strips the EDNS Client Subnet option.
//
// ECS tells the upstream which subnet the end user is on so it can return a
// geographically closer answer. That is a deliberate privacy leak: it hands a
// third-party resolver a per-customer location signal on every lookup. For a
// service whose selling point is privacy, sending it would contradict the
// product.
func removeECS(opt *dns.OPT) {
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			continue
		}
		kept = append(kept, o)
	}
	opt.Option = kept
}

// clientUDPSize reports the response size the client can accept, so replies on
// the plain listener can be truncated at the right threshold rather than a
// guess.
func clientUDPSize(req *dns.Msg) uint16 {
	if opt := req.IsEdns0(); opt != nil {
		if sz := opt.UDPSize(); sz >= dns.MinMsgSize {
			if sz > maxUDPSize {
				return maxUDPSize
			}
			return sz
		}
	}
	return dns.MinMsgSize
}

// setSynthesizedEDNS gives a locally generated answer (blocked, overridden, or
// refused) an EDNS0 record matching what the client asked for.
//
// The AD bit is explicitly cleared. AD means "this data was DNSSEC-validated",
// and a synthesized answer never was — claiming otherwise would be a lie a
// validating client might act on.
func setSynthesizedEDNS(reply *dns.Msg, req *dns.Msg) {
	reply.AuthenticatedData = false

	if opt := req.IsEdns0(); opt != nil {
		reply.SetEdns0(clientUDPSize(req), opt.Do())
	}
}
