// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// repisolation.go — reputation isolation for warm-IP pool segments.
//
// Task: RISK-DELIV-01
//
// The single biggest existential risk for the relay is deliverability collapse:
// if one bad sender gets a warm-IP segment blocklisted, every customer's mail
// starts spam-foldering.  This file implements automatic reputation isolation —
// a per-segment circuit-breaker — so that one bad segment can't poison the whole
// pool.
//
// Mechanism:
//
//   - Per-pool-segment reputation tracking (blocklist hits, complaint rate,
//     bounce rate) accrued from the same delivery-outcome signals the send
//     pipeline already produces (reputation.SendState).
//   - A circuit-breaker: when a segment crosses a configurable threshold the
//     guard auto-quarantines it — new senders are no longer assigned to it and
//     existing traffic is drained off it (the underlying IPs are quarantined in
//     the pool so Pool.Select stops returning them).
//   - Auto-recovery: once a quarantined segment's reputation has stayed below
//     the recovery threshold for a cooldown window, the guard returns it to
//     service.
//
// Integration: the guard hooks into the EXISTING warm-IP pool in
// internal/sending via the small SegmentPool seam below.  In production wrap a
// *sending.Pool with NewSendingPoolAdapter; tests inject a fake.  Feed delivery
// outcomes in via RecordOutcome (called from the send pipeline next to the
// existing policy.RecordResult call) and feed blocklist detections in via
// RecordBlocklistHit (called from the BlocklistMonitor quarantine path).  Gate
// new-sender assignment with Assignable before calling Pool.Select.
package relay

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
)

// ─────────────────────────────────────────────────────────────────────────────
// SegmentPool seam
// ─────────────────────────────────────────────────────────────────────────────

// SegmentPool is the subset of the warm-IP pool that the reputation guard needs
// in order to drain and restore an entire segment.  It is satisfied by wrapping
// a *sending.Pool with NewSendingPoolAdapter; tests inject a fake to keep the
// guard decoupled from the concrete pool implementation (the same decoupling
// pattern used by reputation.BlocklistMonitor's IPPool seam).
type SegmentPool interface {
	// QuarantineSegment pulls every IP belonging to seg out of rotation so that
	// the pool's Select no longer hands them to any sender (drain).  reason is an
	// informational string recorded against each affected IP.
	QuarantineSegment(seg sending.SegmentName, reason string)

	// RestoreSegment returns every previously-guard-quarantined IP in seg to
	// active rotation.
	RestoreSegment(seg sending.SegmentName)
}

// sendingPoolAdapter adapts a *sending.Pool to the SegmentPool interface by
// translating whole-segment operations into the pool's per-IP Quarantine /
// Unquarantine calls.
type sendingPoolAdapter struct {
	pool *sending.Pool
}

// NewSendingPoolAdapter wraps a *sending.Pool so it can be driven by a
// SegmentReputationGuard.  Returns nil if pool is nil.
func NewSendingPoolAdapter(pool *sending.Pool) SegmentPool {
	if pool == nil {
		return nil
	}
	return &sendingPoolAdapter{pool: pool}
}

func (a *sendingPoolAdapter) QuarantineSegment(seg sending.SegmentName, reason string) {
	for _, e := range a.pool.Entries() {
		if e.Segment == seg {
			a.pool.Quarantine(e.IP, reason)
		}
	}
}

func (a *sendingPoolAdapter) RestoreSegment(seg sending.SegmentName) {
	for _, e := range a.pool.Entries() {
		if e.Segment == seg {
			a.pool.Unquarantine(e.IP)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

// IsolationConfig configures the circuit-breaker thresholds.  Zero-valued
// fields fall back to conservative defaults via the accessor methods.
type IsolationConfig struct {
	// MinSamples is the minimum number of recorded outcomes for a segment before
	// rate-based thresholds (complaint/bounce) are evaluated.  This prevents a
	// single early bounce from tripping the breaker on a cold segment.
	// Default: 50.
	MinSamples int

	// ComplaintRateThreshold trips the breaker when the segment's complaint rate
	// (complaints / outcomes) is at or above this value.  Complaints are the
	// strongest deliverability signal (a spam-button press), so the default is
	// deliberately low.  Default: 0.001 (0.1%).
	ComplaintRateThreshold float64

	// BounceRateThreshold trips the breaker when the segment's hard-bounce rate
	// (bounces / outcomes) is at or above this value.  Default: 0.10 (10%).
	BounceRateThreshold float64

	// BlocklistHitThreshold trips the breaker when the segment has accrued at
	// least this many distinct blocklist detections.  A single live-blocklist
	// hit on a warm-IP segment is already an emergency, so the default is 1.
	// Default: 1.
	BlocklistHitThreshold int

	// RecoveryComplaintRate is the complaint rate the segment must stay at or
	// below (over the cooldown window) to be eligible for auto-recovery.  It is
	// hysteresis below ComplaintRateThreshold to avoid flapping.
	// Default: ComplaintRateThreshold / 2.
	RecoveryComplaintRate float64

	// RecoveryBounceRate is the bounce rate the segment must stay at or below to
	// be eligible for auto-recovery.  Default: BounceRateThreshold / 2.
	RecoveryBounceRate float64

	// Cooldown is how long a quarantined segment must continuously satisfy the
	// recovery thresholds (and carry no active blocklist hits) before it is
	// returned to service.  Default: 30 minutes.
	Cooldown time.Duration

	// now is an injectable clock for tests.  Nil means time.Now.
	now func() time.Time
}

func (c *IsolationConfig) minSamples() int {
	if c.MinSamples <= 0 {
		return 50
	}
	return c.MinSamples
}

func (c *IsolationConfig) complaintRate() float64 {
	if c.ComplaintRateThreshold <= 0 {
		return 0.001
	}
	return c.ComplaintRateThreshold
}

func (c *IsolationConfig) bounceRate() float64 {
	if c.BounceRateThreshold <= 0 {
		return 0.10
	}
	return c.BounceRateThreshold
}

func (c *IsolationConfig) blocklistHits() int {
	if c.BlocklistHitThreshold <= 0 {
		return 1
	}
	return c.BlocklistHitThreshold
}

func (c *IsolationConfig) recoveryComplaintRate() float64 {
	if c.RecoveryComplaintRate > 0 {
		return c.RecoveryComplaintRate
	}
	return c.complaintRate() / 2
}

func (c *IsolationConfig) recoveryBounceRate() float64 {
	if c.RecoveryBounceRate > 0 {
		return c.RecoveryBounceRate
	}
	return c.bounceRate() / 2
}

func (c *IsolationConfig) cooldown() time.Duration {
	if c.Cooldown <= 0 {
		return 30 * time.Minute
	}
	return c.Cooldown
}

func (c *IsolationConfig) clock() func() time.Time {
	if c.now != nil {
		return c.now
	}
	return time.Now
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-segment reputation state
// ─────────────────────────────────────────────────────────────────────────────

// SegmentReputation is a point-in-time snapshot of a segment's accrued
// reputation and breaker state.  Returned by Snapshot for metrics/alerting.
type SegmentReputation struct {
	// Segment is the pool segment this record describes.
	Segment sending.SegmentName

	// Sends is the total number of delivery outcomes recorded for the segment.
	Sends int64

	// Delivered, Bounced, Complaints are the per-state counters.
	Delivered  int64
	Bounced    int64
	Complaints int64

	// BlocklistHits is the number of distinct blocklist detections recorded
	// against the segment that have not yet been cleared.
	BlocklistHits int64

	// ComplaintRate and BounceRate are the current rates (0 when Sends == 0).
	ComplaintRate float64
	BounceRate    float64

	// Quarantined is true when the circuit-breaker has tripped for this segment.
	Quarantined bool

	// QuarantineReason is the human-readable reason the breaker tripped.
	QuarantineReason string

	// QuarantinedAt is when the segment was quarantined (zero if not).
	QuarantinedAt time.Time

	// HealthySince, while quarantined, is the time from which the segment has
	// continuously satisfied the recovery thresholds.  Zero means it is not
	// currently eligible (still unhealthy).  Recovery fires once
	// now - HealthySince >= Cooldown.
	HealthySince time.Time
}

// segState is the mutable internal state for one segment.
type segState struct {
	sends      int64
	delivered  int64
	bounced    int64
	complaints int64
	blocklist  int64

	quarantined      bool
	quarantineReason string
	quarantinedAt    time.Time

	// healthySince is the timestamp from which the segment has continuously met
	// the recovery thresholds while quarantined.  Zero when not currently
	// eligible.
	healthySince time.Time
}

func (s *segState) complaintRate() float64 {
	if s.sends == 0 {
		return 0
	}
	return float64(s.complaints) / float64(s.sends)
}

func (s *segState) bounceRate() float64 {
	if s.sends == 0 {
		return 0
	}
	return float64(s.bounced) / float64(s.sends)
}

// ─────────────────────────────────────────────────────────────────────────────
// SegmentReputationGuard — the circuit-breaker
// ─────────────────────────────────────────────────────────────────────────────

// SegmentReputationGuard tracks per-pool-segment reputation and trips a
// circuit-breaker that auto-quarantines a segment (draining its traffic and
// blocking new-sender assignment) when reputation crosses a threshold, then
// auto-recovers the segment once its reputation has stayed healthy for the
// configured cooldown window.
//
// It is safe for concurrent use.
type SegmentReputationGuard struct {
	cfg  IsolationConfig
	pool SegmentPool

	mu   sync.Mutex
	segs map[sending.SegmentName]*segState
}

// NewSegmentReputationGuard creates a guard bound to pool.  pool may be nil for
// pure bookkeeping (e.g. metrics-only) but is normally a SegmentPool wrapping
// the warm-IP pool via NewSendingPoolAdapter.
func NewSegmentReputationGuard(pool SegmentPool, cfg IsolationConfig) *SegmentReputationGuard {
	return &SegmentReputationGuard{
		cfg:  cfg,
		pool: pool,
		segs: make(map[sending.SegmentName]*segState),
	}
}

// NewSegmentReputationGuardWithClock is like NewSegmentReputationGuard but
// injects a clock for deterministic cooldown handling.  A nil now falls back to
// time.Now.  Primarily for tests and simulation.
func NewSegmentReputationGuardWithClock(pool SegmentPool, cfg IsolationConfig, now func() time.Time) *SegmentReputationGuard {
	cfg.now = now
	return NewSegmentReputationGuard(pool, cfg)
}

// state returns the (lazily created) segState for seg.  Caller holds g.mu.
func (g *SegmentReputationGuard) state(seg sending.SegmentName) *segState {
	st := g.segs[seg]
	if st == nil {
		st = &segState{}
		g.segs[seg] = st
	}
	return st
}

// RecordOutcome accrues a single delivery outcome against seg's reputation and
// re-evaluates the circuit-breaker.  Call it from the send pipeline alongside
// the existing policy.RecordResult, passing the segment the message was sent
// from.
func (g *SegmentReputationGuard) RecordOutcome(seg sending.SegmentName, state reputation.SendState) {
	g.mu.Lock()
	defer g.mu.Unlock()

	st := g.state(seg)
	st.sends++
	switch state {
	case reputation.SendDelivered:
		st.delivered++
	case reputation.SendBounced:
		st.bounced++
	case reputation.SendComplaint:
		st.complaints++
	case reputation.SendDeferred:
		// Deferrals are transient; counted toward sends as exposure but not as a
		// reputation defect.
	}

	g.evaluateLocked(seg, st)
}

// RecordBlocklistHit records a distinct blocklist detection against seg and
// re-evaluates the breaker.  Call it from the BlocklistMonitor quarantine path
// when a warm-IP that belongs to seg is newly listed, so that a live blocklist
// hit isolates the whole segment immediately.
func (g *SegmentReputationGuard) RecordBlocklistHit(seg sending.SegmentName, source string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	st := g.state(seg)
	st.blocklist++
	_ = source
	g.evaluateLocked(seg, st)
}

// ClearBlocklistHit decrements seg's active blocklist-hit count when a listing
// is confirmed cleared (call from the BlocklistMonitor unquarantine path).  It
// never goes below zero.  Clearing a hit makes the segment eligible for
// auto-recovery once rates are also healthy.
func (g *SegmentReputationGuard) ClearBlocklistHit(seg sending.SegmentName) {
	g.mu.Lock()
	defer g.mu.Unlock()

	st := g.state(seg)
	if st.blocklist > 0 {
		st.blocklist--
	}
	g.evaluateLocked(seg, st)
}

// Assignable reports whether new senders may currently be assigned to seg.  The
// send-side assignment path should consult this before calling Pool.Select so
// that a quarantined segment accepts no new senders.  Unknown segments are
// assignable by default.
func (g *SegmentReputationGuard) Assignable(seg sending.SegmentName) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.segs[seg]
	return st == nil || !st.quarantined
}

// IsQuarantined reports whether seg's breaker is currently tripped.
func (g *SegmentReputationGuard) IsQuarantined(seg sending.SegmentName) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.segs[seg]
	return st != nil && st.quarantined
}

// Tick re-evaluates every tracked segment.  It is the auto-recovery driver: a
// quarantined segment whose recovery thresholds have held for the cooldown
// window is returned to service.  Call it periodically (e.g. once a minute) and
// after feeding fresh outcomes.  Returns the segments that were recovered on
// this tick.
func (g *SegmentReputationGuard) Tick() []sending.SegmentName {
	g.mu.Lock()
	defer g.mu.Unlock()

	var recovered []sending.SegmentName
	// Iterate deterministically for stable behaviour/tests.
	names := make([]sending.SegmentName, 0, len(g.segs))
	for name := range g.segs {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })

	for _, name := range names {
		st := g.segs[name]
		if g.evaluateLocked(name, st) {
			recovered = append(recovered, name)
		}
	}
	return recovered
}

// evaluateLocked re-runs the breaker decision for one segment.  Caller holds
// g.mu.  It returns true iff the segment was auto-recovered on this call.
func (g *SegmentReputationGuard) evaluateLocked(seg sending.SegmentName, st *segState) bool {
	now := g.cfg.clock()()

	if !st.quarantined {
		if reason, trip := g.shouldTripLocked(st); trip {
			st.quarantined = true
			st.quarantineReason = reason
			st.quarantinedAt = now
			st.healthySince = time.Time{}
			if g.pool != nil {
				g.pool.QuarantineSegment(seg, "repisolation: "+reason)
			}
		}
		return false
	}

	// Already quarantined → assess recovery eligibility (hysteresis + cooldown).
	if g.healthyForRecoveryLocked(st) {
		if st.healthySince.IsZero() {
			st.healthySince = now
		}
		if now.Sub(st.healthySince) >= g.cfg.cooldown() {
			st.quarantined = false
			st.quarantineReason = ""
			st.quarantinedAt = time.Time{}
			st.healthySince = time.Time{}
			if g.pool != nil {
				g.pool.RestoreSegment(seg)
			}
			return true
		}
	} else {
		// Reputation regressed during cooldown → reset the healthy timer.
		st.healthySince = time.Time{}
	}
	return false
}

// shouldTripLocked decides whether a not-yet-quarantined segment should trip the
// breaker.  Caller holds g.mu.
func (g *SegmentReputationGuard) shouldTripLocked(st *segState) (reason string, trip bool) {
	// A live blocklist hit is an immediate emergency regardless of volume.
	if st.blocklist >= int64(g.cfg.blocklistHits()) {
		return fmt.Sprintf("blocklist hits %d >= threshold %d", st.blocklist, g.cfg.blocklistHits()), true
	}

	// Rate-based signals only after enough samples to be meaningful.
	if st.sends < int64(g.cfg.minSamples()) {
		return "", false
	}

	if cr := st.complaintRate(); cr >= g.cfg.complaintRate() {
		return fmt.Sprintf("complaint rate %.4f >= threshold %.4f", cr, g.cfg.complaintRate()), true
	}
	if br := st.bounceRate(); br >= g.cfg.bounceRate() {
		return fmt.Sprintf("bounce rate %.4f >= threshold %.4f", br, g.cfg.bounceRate()), true
	}
	return "", false
}

// healthyForRecoveryLocked reports whether a quarantined segment currently
// satisfies the recovery thresholds (hysteresis below the trip thresholds) and
// carries no active blocklist hits.  Caller holds g.mu.
func (g *SegmentReputationGuard) healthyForRecoveryLocked(st *segState) bool {
	if st.blocklist > 0 {
		return false
	}
	if st.complaintRate() > g.cfg.recoveryComplaintRate() {
		return false
	}
	if st.bounceRate() > g.cfg.recoveryBounceRate() {
		return false
	}
	return true
}

// Snapshot returns a stable, sorted snapshot of every tracked segment's
// reputation and breaker state for metrics/alerting.
func (g *SegmentReputationGuard) Snapshot() []SegmentReputation {
	g.mu.Lock()
	defer g.mu.Unlock()

	out := make([]SegmentReputation, 0, len(g.segs))
	for name, st := range g.segs {
		out = append(out, SegmentReputation{
			Segment:          name,
			Sends:            st.sends,
			Delivered:        st.delivered,
			Bounced:          st.bounced,
			Complaints:       st.complaints,
			BlocklistHits:    st.blocklist,
			ComplaintRate:    st.complaintRate(),
			BounceRate:       st.bounceRate(),
			Quarantined:      st.quarantined,
			QuarantineReason: st.quarantineReason,
			QuarantinedAt:    st.quarantinedAt,
			HealthySince:     st.healthySince,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Segment < out[j].Segment })
	return out
}
