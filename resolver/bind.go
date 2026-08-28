package resolver

import (
	"log/slog"
	"sync"
	"time"
)

// bindDebounce bounds how often the same tenant/address pair is written back.
// A phone makes thousands of queries an hour; the binding only needs to be
// recorded when it is new or has aged.
const bindDebounce = 5 * time.Minute

// ipBinder records the address a tenant is querying from, so the proxy tier can
// recognise the same customer when their app connects to it.
//
// Without this, a customer's address has to be registered by hand through the
// admin API, and re-registered every time their network gives them a new one --
// which on mobile is several times a day. The DNS query is the one moment the
// service reliably sees both the tenant (from the TLS SNI) and the address they
// are coming from, so it is the right place to capture the pair.
//
// Deliberately debounced rather than written per query: the writes are the
// expensive part, and the binding does not change between them.
type ipBinder struct {
	store Store
	log   *slog.Logger

	mu   sync.Mutex
	seen map[string]time.Time
}

func newIPBinder(store Store, log *slog.Logger) *ipBinder {
	return &ipBinder{store: store, log: log, seen: map[string]time.Time{}}
}

// observe records that routeID is querying from ip, at most once per
// bindDebounce. Safe to call on every query.
func (b *ipBinder) observe(routeID, ip string) {
	if b == nil || routeID == "" || ip == "" {
		return
	}

	key := routeID + "|" + ip
	now := time.Now()

	b.mu.Lock()
	last, ok := b.seen[key]
	if ok && now.Sub(last) < bindDebounce {
		b.mu.Unlock()
		return
	}
	b.seen[key] = now

	// Bound the map. A tenant that roams between many addresses must not grow
	// this without limit, and the entries are only an optimisation.
	if len(b.seen) > 10000 {
		for k, t := range b.seen {
			if now.Sub(t) > bindDebounce {
				delete(b.seen, k)
			}
		}
	}
	b.mu.Unlock()

	// Off the query path: a slow write must not delay an answer.
	go func() {
		if err := b.store.RegisterIP(routeID, ip); err != nil {
			b.log.Warn("could not bind client address", "tenant", routeID, "err", err)
		}
	}()
}
