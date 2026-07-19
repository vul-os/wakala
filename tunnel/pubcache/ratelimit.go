package pubcache

import (
	"sync"
	"time"
)

// ratelimit.go — a small per-key token-bucket limiter, kept local so this
// package stays standalone and readable end-to-end by anyone implementing the
// role elsewhere (same rationale as tunnel/rendezvous/ratelimit.go).
//
// Reads here are ANONYMOUS by protocol requirement (§ 22.5.1), so there is no
// account to key a limit on: the only handles available are the client address
// and the aggregate. Both are used — the per-address bucket stops one client
// from monopolising the upstream budget, and the global bucket bounds what the
// role can cost the operator no matter how many addresses show up.

type bucket struct {
	tokens   float64
	last     time.Time
	lastUsed time.Time
}

type limiter struct {
	rate    float64
	burst   float64
	idleTTL time.Duration
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
	swept   time.Time
}

// newLimiter builds a limiter. ratePerSec<=0 or burst<=0 disables it (allow all),
// which is how an operator turns a limit off deliberately.
func newLimiter(ratePerSec, burst float64, idleTTL time.Duration, maxKeys int) *limiter {
	if ratePerSec <= 0 || burst <= 0 {
		return nil
	}
	if idleTTL <= 0 {
		idleTTL = 10 * time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &limiter{rate: ratePerSec, burst: burst, idleTTL: idleTTL, maxKeys: maxKeys, buckets: make(map[string]*bucket)}
}

// allow consumes one token for key. A nil limiter or empty key always allows.
//
// Note the key cap is FAIL-CLOSED: once maxKeys distinct keys are tracked, a new
// key is denied rather than admitted-and-untracked, so a flood of fresh source
// addresses cannot buy unlimited service by exhausting the bookkeeping.
func (l *limiter) allow(key string) bool {
	if l == nil || key == "" {
		return true
	}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)

	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxKeys {
			return false
		}
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now, lastUsed: now}
		return true
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	b.lastUsed = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *limiter) sweepLocked(now time.Time) {
	interval := l.idleTTL / 4
	if interval <= 0 {
		interval = time.Minute
	}
	if now.Sub(l.swept) < interval {
		return
	}
	l.swept = now
	for k, b := range l.buckets {
		if now.Sub(b.lastUsed) > l.idleTTL {
			delete(l.buckets, k)
		}
	}
}
