package resolver

import (
	"sync"
	"time"
)

// UsageCollector accumulates per-tenant counters in memory and flushes them to
// the store periodically.
//
// Counting in the query path and writing in a background flush is deliberate:
// a per-query database write would turn a cheap in-memory lookup into a disk
// operation, and DNS query rates are high enough that it would dominate the
// cost of resolution.
//
// Note what is counted and what is not. These are aggregate totals per tenant.
// The names a customer looked up are never recorded — that is the strongest
// privacy claim the product has, and it also keeps storage flat regardless of
// traffic.
type UsageCollector struct {
	store Store

	mu      sync.Mutex
	pending map[string]UsageDelta
}

func NewUsageCollector(store Store) *UsageCollector {
	return &UsageCollector{
		store:   store,
		pending: make(map[string]UsageDelta),
	}
}

// Record adds one query's outcome to the pending totals.
func (u *UsageCollector) Record(routeID string, blocked, overridden, throttled bool) {
	if u == nil || routeID == "" {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	d := u.pending[routeID]
	d.Queries++
	if blocked {
		d.Blocked++
	}
	if overridden {
		d.Overridden++
	}
	if throttled {
		d.Throttled++
	}
	d.LastSeen = time.Now().Unix()
	u.pending[routeID] = d
}

// Flush writes pending counters to the store and clears them. Counters are
// taken under the lock and written outside it, so the query path is never
// blocked by a database write.
func (u *UsageCollector) Flush() error {
	if u == nil {
		return nil
	}

	u.mu.Lock()
	if len(u.pending) == 0 {
		u.mu.Unlock()
		return nil
	}
	batch := u.pending
	u.pending = make(map[string]UsageDelta, len(batch))
	u.mu.Unlock()

	if err := u.store.RecordUsage(batch); err != nil {
		// Put the counts back so a transient database error loses accounting
		// rather than silently discarding it.
		u.mu.Lock()
		for id, d := range batch {
			p := u.pending[id]
			p.Queries += d.Queries
			p.Blocked += d.Blocked
			p.Overridden += d.Overridden
			p.Throttled += d.Throttled
			if d.LastSeen > p.LastSeen {
				p.LastSeen = d.LastSeen
			}
			u.pending[id] = p
		}
		u.mu.Unlock()
		return err
	}
	return nil
}

// StartFlusher flushes on a timer until stop is closed, then flushes once more
// so a clean shutdown does not lose the final interval's counts.
func (u *UsageCollector) StartFlusher(every time.Duration, stop <-chan struct{}, onErr func(error)) {
	if u == nil {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				if err := u.Flush(); err != nil && onErr != nil {
					onErr(err)
				}
				return
			case <-t.C:
				if err := u.Flush(); err != nil && onErr != nil {
					onErr(err)
				}
			}
		}
	}()
}

// PendingTenants reports how many tenants have unflushed counters.
func (u *UsageCollector) PendingTenants() int {
	if u == nil {
		return 0
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.pending)
}
