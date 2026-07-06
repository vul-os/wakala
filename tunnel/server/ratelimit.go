package server

import (
	"sync"
	"time"
)

// ratelimit.go — WAVE34-RELAY-HARDEN: per-key token-bucket rate limiting for the
// internet-facing relay.
//
// The public relay previously accepted control-connection attempts and proxied
// inbound public HTTP/WS with no per-IP / per-agent throttle and no 429 path. A
// single source could hammer the control endpoint (each attempt spends a WS
// upgrade + a CP entitlement round-trip) or flood one tunnel with public
// requests. This adds two cheap, memory-bounded token-bucket limiters:
//
//   - control-connection attempts, keyed by source IP (throttles auth/CP churn
//     before we spend an upgrade), and
//   - inbound public requests, keyed by agent/session name (caps per-tunnel
//     request rate), plus a global cap across all tunnels.
//
// Buckets are lazily created and evicted once idle, so a flood of distinct keys
// cannot grow memory without bound. Limits are configurable with safe defaults
// (see Config); a zero/disabled limiter is a no-op so self-host stays unchanged.
// These sit ALONGSIDE the existing hard caps (max-agents, streams/agent), which
// are untouched.

// tokenBucket is a classic token bucket: up to burst tokens, refilled at rate
// tokens/second. allow() consumes one token if available.
type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastUsed time.Time // for idle eviction
}

// rateLimiter is a set of per-key token buckets with idle eviction. A nil or
// disabled limiter allows everything (self-host / unconfigured path).
type rateLimiter struct {
	rate    float64       // tokens per second added to each bucket
	burst   float64       // bucket capacity (max burst)
	idleTTL time.Duration // evict a bucket unused for this long
	maxKeys int           // hard cap on distinct buckets (bounds memory)

	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	lastSwep time.Time
}

// newRateLimiter builds a limiter. ratePerSec<=0 or burst<=0 disables it (allow
// all). idleTTL/maxKeys get safe defaults when unset.
func newRateLimiter(ratePerSec, burst float64, idleTTL time.Duration, maxKeys int) *rateLimiter {
	if ratePerSec <= 0 || burst <= 0 {
		return nil // disabled
	}
	if idleTTL <= 0 {
		idleTTL = 10 * time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &rateLimiter{
		rate:    ratePerSec,
		burst:   burst,
		idleTTL: idleTTL,
		maxKeys: maxKeys,
		buckets: make(map[string]*tokenBucket),
	}
}

// allow reports whether the action for key may proceed, consuming one token. A
// nil limiter (disabled) always allows. Safe for concurrent use.
func (rl *rateLimiter) allow(key string) bool {
	if rl == nil || key == "" {
		return true
	}
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.sweepLocked(now)

	b := rl.buckets[key]
	if b == nil {
		// Bounded: if we are at the key cap and this is a NEW key, refuse rather
		// than grow memory. sweepLocked already dropped idle keys; a live flood of
		// distinct keys past the cap is itself abuse and is safe to reject.
		if len(rl.buckets) >= rl.maxKeys {
			return false
		}
		rl.buckets[key] = &tokenBucket{tokens: rl.burst - 1, last: now, lastUsed: now}
		return true
	}

	// Refill based on elapsed time, capped at burst.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
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

// sweepLocked evicts idle buckets. Runs at most ~once per idleTTL/4 to keep the
// hot path cheap. Caller must hold rl.mu.
func (rl *rateLimiter) sweepLocked(now time.Time) {
	interval := rl.idleTTL / 4
	if interval <= 0 {
		interval = time.Minute
	}
	if now.Sub(rl.lastSwep) < interval {
		return
	}
	rl.lastSwep = now
	for k, b := range rl.buckets {
		if now.Sub(b.lastUsed) > rl.idleTTL {
			delete(rl.buckets, k)
		}
	}
}

// globalRateLimiter is a single shared token bucket (not keyed) that caps the
// aggregate inbound public request rate across ALL tunnels. A nil limiter allows
// everything.
type globalRateLimiter struct {
	rate  float64
	burst float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newGlobalRateLimiter(ratePerSec, burst float64) *globalRateLimiter {
	if ratePerSec <= 0 || burst <= 0 {
		return nil // disabled
	}
	return &globalRateLimiter{rate: ratePerSec, burst: burst, tokens: burst, last: time.Now()}
}

func (g *globalRateLimiter) allow() bool {
	if g == nil {
		return true
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	elapsed := now.Sub(g.last).Seconds()
	if elapsed > 0 {
		g.tokens += elapsed * g.rate
		if g.tokens > g.burst {
			g.tokens = g.burst
		}
		g.last = now
	}
	if g.tokens >= 1 {
		g.tokens--
		return true
	}
	return false
}
