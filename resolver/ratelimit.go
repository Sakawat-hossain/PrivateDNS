package resolver

import (
	"sync"
	"time"
)

// limiterIdleTTL is how long an unused tenant bucket is kept before being
// swept. Without this, a resolver that has seen many tenants would hold a
// bucket for each of them forever.
const limiterIdleTTL = 10 * time.Minute

// bucket is a token bucket refilled at a constant rate. Tokens are computed
// lazily on access rather than by a background ticker, so an idle tenant costs
// nothing.
type bucket struct {
	tokens   float64
	lastFill time.Time
	lastUsed time.Time
	conns    int
}

// RateLimiter caps how much traffic one tenant may generate.
//
// This matters because a tenant hostname is not a secret: it travels in the
// SNI in cleartext and a customer may share it, deliberately or not. Without a
// limit, one leaked hostname can be used to flood the resolver on that
// tenant's behalf.
type RateLimiter struct {
	qps      float64
	burst    float64
	maxConns int

	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewRateLimiter returns a limiter, or nil if qps is zero or negative, in
// which case rate limiting is disabled entirely. A nil *RateLimiter is safe to
// call — every method allows.
func NewRateLimiter(qps float64, burst, maxConns int) *RateLimiter {
	if qps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = int(qps)
	}
	return &RateLimiter{
		qps:      qps,
		burst:    float64(burst),
		maxConns: maxConns,
		buckets:  make(map[string]*bucket),
	}
}

// Allow reports whether a query from this tenant may proceed, consuming one
// token if so.
func (r *RateLimiter) Allow(routeID string) bool {
	if r == nil {
		return true
	}

	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[routeID]
	if !ok {
		// A new tenant starts with a full bucket so its first page load is
		// never throttled.
		b = &bucket{tokens: r.burst, lastFill: now}
		r.buckets[routeID] = b
	}

	// Refill for the time elapsed since the last look.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens += elapsed * r.qps
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.lastFill = now
	}
	b.lastUsed = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// AcquireConn reserves a concurrent-connection slot for a tenant. The returned
// release function must be called when the connection closes; it is safe to
// call on the failure path too.
func (r *RateLimiter) AcquireConn(routeID string) (release func(), ok bool) {
	if r == nil || r.maxConns <= 0 {
		return func() {}, true
	}

	now := time.Now()

	r.mu.Lock()
	b, exists := r.buckets[routeID]
	if !exists {
		b = &bucket{tokens: r.burst, lastFill: now}
		r.buckets[routeID] = b
	}
	if b.conns >= r.maxConns {
		r.mu.Unlock()
		return func() {}, false
	}
	b.conns++
	b.lastUsed = now
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			if b.conns > 0 {
				b.conns--
			}
			r.mu.Unlock()
		})
	}, true
}

// StartSweeper drops buckets for tenants that have gone quiet, so memory
// tracks active tenants rather than every tenant ever seen.
func (r *RateLimiter) StartSweeper(every time.Duration, stop <-chan struct{}) {
	if r == nil {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				r.mu.Lock()
				for id, b := range r.buckets {
					// Never evict a bucket with live connections; its counter
					// is the only record of them.
					if b.conns == 0 && now.Sub(b.lastUsed) > limiterIdleTTL {
						delete(r.buckets, id)
					}
				}
				r.mu.Unlock()
			}
		}
	}()
}

// Tracked reports how many tenant buckets are currently held.
func (r *RateLimiter) Tracked() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}
