package rendezvous

import (
	"sync"
	"time"
)

// ratelimit.go — a small, self-contained per-key token-bucket limiter for the
// rendezvous surfaces. It mirrors the relay's ratelimit.go design but is kept local
// so this package stays standalone (a reference node others can read end-to-end
// without following into unexported server internals).
//
// Buckets are lazily created and evicted once idle; a hard key cap bounds memory
// against a flood of distinct keys. A nil/disabled limiter allows everything so a
// self-host operator who does not configure limits runs unchanged.

type bucket struct {
	tokens   float64
	last     time.Time
	lastUsed time.Time
}

// limiter is a set of per-key token buckets with idle eviction.
type limiter struct {
	rate    float64
	burst   float64
	idleTTL time.Duration
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
	swep    time.Time
}

// newLimiter builds a limiter. ratePerSec<=0 or burst<=0 disables it (allow all).
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
	if now.Sub(l.swep) < interval {
		return
	}
	l.swep = now
	for k, b := range l.buckets {
		if now.Sub(b.lastUsed) > l.idleTTL {
			delete(l.buckets, k)
		}
	}
}
