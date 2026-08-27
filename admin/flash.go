package admin

import (
	"sync"
	"time"
)

// A freshly minted API token has to survive exactly one redirect: the POST
// that creates it redirects to the listing, and the listing shows it once.
//
// It must not travel in the URL to get there. A query string is written to
// browser history, sent in the Referer header on any outbound link, and
// recorded verbatim in nginx access logs and every proxy in between — so a
// credential placed there is disclosed in several places at once, none of
// which the operator controls or would think to clear.
//
// Instead it is held here for a few seconds, keyed by session, and removed the
// first time it is read.

const tokenStashTTL = 30 * time.Second

type stashedToken struct {
	value string
	at    time.Time
}

type tokenStash struct {
	mu sync.Mutex
	m  map[string]stashedToken
}

func newTokenStash() *tokenStash {
	return &tokenStash{m: make(map[string]stashedToken)}
}

// put holds a token for the session that created it, replacing anything
// already there.
func (s *tokenStash) put(sessionToken, value string) {
	if sessionToken == "" || value == "" {
		return
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Opportunistic sweep, so an operator who creates a token and closes the
	// tab does not leave it sitting in memory.
	for k, v := range s.m {
		if now.Sub(v.at) > tokenStashTTL {
			delete(s.m, k)
		}
	}

	s.m[sessionToken] = stashedToken{value: value, at: now}
}

// take returns the stashed token and removes it.
//
// Read-once: refreshing the page after the token has been shown must not show
// it again, or "copy this now, it cannot be shown again" would be untrue and
// the value would linger in memory for as long as the operator left the tab
// open.
func (s *tokenStash) take(sessionToken string) string {
	if sessionToken == "" {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	v, ok := s.m[sessionToken]
	if !ok {
		return ""
	}
	delete(s.m, sessionToken)

	if time.Since(v.at) > tokenStashTTL {
		return ""
	}
	return v.value
}
