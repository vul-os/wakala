package rendezvous

import (
	"sync"
	"time"
)

// replay.go — freshness + replay protection for signed writes.
//
// Every signed write (announce, signal deposit, mailbox deposit, poll, ack)
// carries a unix timestamp and a random nonce. A request is accepted only if:
//
//   - its timestamp is within ±skew of the node's clock (bounds how long a captured
//     request stays replayable, and rejects far-future timestamps), AND
//   - its (key, nonce) pair has not been seen within the freshness window.
//
// The seen-set is bounded: entries expire after the skew window (a nonce older than
// that can no longer be replayed because the timestamp check already rejects it),
// and a hard cap evicts the oldest bucket if an attacker floods distinct nonces. So
// the guard cannot grow memory without bound.

// defaultClockSkew is how far a request timestamp may deviate from the node's clock
// in either direction. It also sets how long a nonce must be remembered.
const defaultClockSkew = 5 * time.Minute

// replayGuard tracks recently-seen (key,nonce) pairs to reject replays, and bounds
// its own memory. It is safe for concurrent use.
type replayGuard struct {
	skew    time.Duration
	maxKeys int

	mu   sync.Mutex
	seen map[string]time.Time // "key\x00nonce" -> expiry
	swep time.Time
}

// newReplayGuard builds a guard. skew<=0 => defaultClockSkew; maxKeys<=0 => 100k.
func newReplayGuard(skew time.Duration, maxKeys int) *replayGuard {
	if skew <= 0 {
		skew = defaultClockSkew
	}
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &replayGuard{skew: skew, maxKeys: maxKeys, seen: make(map[string]time.Time)}
}

// freshTimestamp reports whether unix-seconds ts is within ±skew of now. It rejects
// both stale (replayable) and far-future timestamps.
func (g *replayGuard) freshTimestamp(ts int64, now time.Time) bool {
	if ts <= 0 {
		return false
	}
	delta := now.Sub(time.Unix(ts, 0))
	if delta < 0 {
		delta = -delta
	}
	return delta <= g.skew
}

// checkAndRecord validates freshness and records the (key,nonce) as seen. It
// returns true if the request is fresh AND unique (accept), false if the timestamp
// is out of window or the nonce was already used (reject as replay). A nonce is
// remembered for the skew window; after that the timestamp check alone rejects it.
func (g *replayGuard) checkAndRecord(key, nonce string, ts int64, now time.Time) bool {
	if nonce == "" || !g.freshTimestamp(ts, now) {
		return false
	}
	id := key + "\x00" + nonce

	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)

	if exp, ok := g.seen[id]; ok && now.Before(exp) {
		return false // replay
	}
	// Bounded: if flooded past the cap with fresh nonces, refuse rather than grow.
	// sweepLocked already dropped expired entries; a live flood past the cap is
	// itself abuse and safe to reject (the caller's rate limiter also fires).
	if len(g.seen) >= g.maxKeys {
		if _, exists := g.seen[id]; !exists {
			return false
		}
	}
	g.seen[id] = now.Add(g.skew)
	return true
}

// sweepLocked drops expired nonces at most ~once per skew/4. Caller holds g.mu.
func (g *replayGuard) sweepLocked(now time.Time) {
	interval := g.skew / 4
	if interval <= 0 {
		interval = time.Minute
	}
	if now.Sub(g.swep) < interval {
		return
	}
	g.swep = now
	for k, exp := range g.seen {
		if !now.Before(exp) {
			delete(g.seen, k)
		}
	}
}
