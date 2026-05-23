// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"crypto/ed25519"
	"encoding/binary"
	"sync"
	"time"
)

// defaultSkew is the timestamp acceptance window half-width (spec/PEERING.md §7).
const defaultSkew = 5 * time.Minute

// ReplayGuard enforces spec §7 replay protection: a timestamp acceptance window
// plus per-(sender,nonce) dedup. It is safe for concurrent use.
type ReplayGuard struct {
	// Skew is the half-width of the timestamp acceptance window. Zero uses the
	// default (5 minutes).
	Skew time.Duration
	// Now, if non-nil, overrides the clock (tests).
	Now func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // key: sender||nonce -> first-seen timestamp
}

// NewReplayGuard creates a ReplayGuard with the default skew.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: make(map[string]time.Time)}
}

// Check accepts an envelope's (sender, nonce, timestamp) once. It returns
// ErrReplay if the timestamp is outside the acceptance window or if the
// (sender, nonce) pair has already been accepted within it. A successful Check
// records the pair.
func (g *ReplayGuard) Check(senderID ed25519.PublicKey, nonce []byte, ts time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]time.Time)
	}

	skew := g.Skew
	if skew <= 0 {
		skew = defaultSkew
	}
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	cur := now()

	// Timestamp window.
	if ts.Before(cur.Add(-skew)) || ts.After(cur.Add(skew)) {
		return ErrReplay
	}

	// Opportunistically evict entries that have aged out of any window.
	g.evict(cur, skew)

	key := guardKey(senderID, nonce)
	if _, dup := g.seen[key]; dup {
		return ErrReplay
	}
	g.seen[key] = ts
	return nil
}

// evict drops entries older than the acceptance window; once aged out the
// timestamp check alone rejects any re-presentation (spec §7).
func (g *ReplayGuard) evict(now time.Time, skew time.Duration) {
	cutoff := now.Add(-skew)
	for k, t := range g.seen {
		if t.Before(cutoff) {
			delete(g.seen, k)
		}
	}
}

func guardKey(senderID ed25519.PublicKey, nonce []byte) string {
	buf := make([]byte, 0, 2+len(senderID)+len(nonce))
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(senderID)))
	buf = append(buf, l[:]...)
	buf = append(buf, senderID...)
	buf = append(buf, nonce...)
	return string(buf)
}
