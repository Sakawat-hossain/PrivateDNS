package resolver

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	minCacheTTL = 5 * time.Second
	maxCacheTTL = 6 * time.Hour
	// Negative answers are cached briefly so a burst of lookups for a name
	// that does not exist does not each cost an upstream round trip.
	negativeTTL = 30 * time.Second
)

type cacheEntry struct {
	msg      *dns.Msg
	storedAt time.Time
	expires  time.Time
}

// Cache is a shared, tenant-agnostic answer cache sitting in front of the
// upstreams. It holds only upstream answers — blocked, allowlisted and
// overridden results are decided per tenant and never cached here.
type Cache struct {
	shards [64]cacheShard
}

type cacheShard struct {
	mu sync.RWMutex
	m  map[string]cacheEntry
}

func NewCache() *Cache {
	c := &Cache{}
	for i := range c.shards {
		c.shards[i].m = make(map[string]cacheEntry)
	}
	return c
}

func cacheKey(q dns.Question) string {
	return normalizeDomain(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

func (c *Cache) shardFor(key string) *cacheShard {
	// FNV-1a, inlined to keep this off the allocation path.
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &c.shards[h%uint32(len(c.shards))]
}

func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	key := cacheKey(q)
	sh := c.shardFor(key)

	sh.mu.RLock()
	e, ok := sh.m[key]
	sh.mu.RUnlock()
	if !ok {
		return nil, false
	}

	now := time.Now()
	if now.After(e.expires) {
		sh.mu.Lock()
		delete(sh.m, key)
		sh.mu.Unlock()
		return nil, false
	}

	// Count down the TTLs we hand back by however long we have held the answer,
	// so downstream caches do not extend its life.
	elapsed := uint32(now.Sub(e.storedAt).Seconds())
	msg := e.msg.Copy()
	adjustTTL(msg.Answer, elapsed)
	adjustTTL(msg.Ns, elapsed)
	adjustTTL(msg.Extra, elapsed)
	return msg, true
}

func adjustTTL(rrs []dns.RR, elapsed uint32) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Ttl > elapsed {
			h.Ttl -= elapsed
		} else {
			h.Ttl = 1
		}
	}
}

func (c *Cache) Put(q dns.Question, msg *dns.Msg) {
	if msg == nil || msg.Truncated {
		return
	}

	ttl := minTTL(msg)
	if len(msg.Answer) == 0 {
		ttl = negativeTTL
	}
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}

	key := cacheKey(q)
	sh := c.shardFor(key)
	now := time.Now()

	sh.mu.Lock()
	sh.m[key] = cacheEntry{msg: msg.Copy(), storedAt: now, expires: now.Add(ttl)}
	sh.mu.Unlock()
}

func minTTL(msg *dns.Msg) time.Duration {
	best := uint32(0)
	first := true
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			t := rr.Header().Ttl
			if first || t < best {
				best, first = t, false
			}
		}
	}
	if first {
		return negativeTTL
	}
	return time.Duration(best) * time.Second
}

func (c *Cache) Len() int {
	n := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		n += len(c.shards[i].m)
		c.shards[i].mu.RUnlock()
	}
	return n
}

// StartSweeper drops expired entries so an idle cache does not grow forever.
func (c *Cache) StartSweeper(every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			for i := range c.shards {
				sh := &c.shards[i]
				sh.mu.Lock()
				for k, e := range sh.m {
					if now.After(e.expires) {
						delete(sh.m, k)
					}
				}
				sh.mu.Unlock()
			}
		}
	}()
}
