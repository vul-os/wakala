// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/relay"
	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
)

// fakeSegmentPool records segment-level quarantine/restore calls so tests can
// assert that the breaker drains and restores the underlying pool.
type fakeSegmentPool struct {
	mu          sync.Mutex
	quarantined map[sending.SegmentName]string
	restored    []sending.SegmentName
}

func newFakeSegmentPool() *fakeSegmentPool {
	return &fakeSegmentPool{quarantined: make(map[sending.SegmentName]string)}
}

func (f *fakeSegmentPool) QuarantineSegment(seg sending.SegmentName, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quarantined[seg] = reason
}

func (f *fakeSegmentPool) RestoreSegment(seg sending.SegmentName) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.quarantined, seg)
	f.restored = append(f.restored, seg)
}

func (f *fakeSegmentPool) isQuarantined(seg sending.SegmentName) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.quarantined[seg]
	return ok
}

// fakeClock is a controllable monotonic clock for cooldown tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ── reputation accrual ────────────────────────────────────────────────────────

// TestReputationAccrual verifies that per-segment outcomes accrue into the
// correct counters and rates.
func TestReputationAccrual(t *testing.T) {
	g := relay.NewSegmentReputationGuard(nil, relay.IsolationConfig{MinSamples: 1000})

	for i := 0; i < 80; i++ {
		g.RecordOutcome(sending.SegmentEstablished, reputation.SendDelivered)
	}
	for i := 0; i < 15; i++ {
		g.RecordOutcome(sending.SegmentEstablished, reputation.SendBounced)
	}
	for i := 0; i < 5; i++ {
		g.RecordOutcome(sending.SegmentEstablished, reputation.SendComplaint)
	}
	// A different segment must accrue independently.
	g.RecordOutcome(sending.SegmentUntrusted, reputation.SendDelivered)

	snap := g.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 segments tracked, got %d", len(snap))
	}

	var est relay.SegmentReputation
	for _, s := range snap {
		if s.Segment == sending.SegmentEstablished {
			est = s
		}
	}
	if est.Sends != 100 {
		t.Errorf("Sends = %d, want 100", est.Sends)
	}
	if est.Delivered != 80 || est.Bounced != 15 || est.Complaints != 5 {
		t.Errorf("counters delivered/bounced/complaints = %d/%d/%d, want 80/15/5",
			est.Delivered, est.Bounced, est.Complaints)
	}
	if got := est.BounceRate; got != 0.15 {
		t.Errorf("BounceRate = %v, want 0.15", got)
	}
	if got := est.ComplaintRate; got != 0.05 {
		t.Errorf("ComplaintRate = %v, want 0.05", got)
	}
	// High MinSamples means the breaker must NOT have tripped despite bad rates.
	if est.Quarantined {
		t.Error("segment quarantined below MinSamples; expected not tripped")
	}
}

// ── threshold trips the breaker ───────────────────────────────────────────────

// TestBounceRateTripsBreaker verifies the bounce-rate threshold trips the
// breaker once enough samples are present, draining the pool segment.
func TestBounceRateTripsBreaker(t *testing.T) {
	pool := newFakeSegmentPool()
	g := relay.NewSegmentReputationGuard(pool, relay.IsolationConfig{
		MinSamples:          100,
		BounceRateThreshold: 0.10,
	})

	// 95 delivered + 5 bounced = 5% bounce over 100 samples → below threshold.
	for i := 0; i < 95; i++ {
		g.RecordOutcome(sending.SegmentEstablished, reputation.SendDelivered)
	}
	for i := 0; i < 5; i++ {
		g.RecordOutcome(sending.SegmentEstablished, reputation.SendBounced)
	}
	if g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("breaker tripped at 5% bounce; threshold is 10%")
	}

	// Push bounce rate to ~10.4% (12 bounces / 115 sends) → should trip.
	for i := 0; i < 7; i++ {
		g.RecordOutcome(sending.SegmentEstablished, reputation.SendBounced)
	}
	if !g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("breaker did not trip above bounce-rate threshold")
	}
	if !pool.isQuarantined(sending.SegmentEstablished) {
		t.Error("pool segment was not drained when breaker tripped")
	}
}

// TestComplaintRateTripsBreaker verifies the (very low) complaint-rate
// threshold trips the breaker.
func TestComplaintRateTripsBreaker(t *testing.T) {
	g := relay.NewSegmentReputationGuard(nil, relay.IsolationConfig{
		MinSamples:             100,
		ComplaintRateThreshold: 0.001, // 0.1%
	})
	for i := 0; i < 999; i++ {
		g.RecordOutcome(sending.SegmentEstablished, reputation.SendDelivered)
	}
	if g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("breaker tripped with zero complaints")
	}
	// One complaint over 1000 sends = 0.1% → at threshold → trip.
	g.RecordOutcome(sending.SegmentEstablished, reputation.SendComplaint)
	if !g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("breaker did not trip at complaint-rate threshold")
	}
}

// TestBlocklistHitTripsBreakerImmediately verifies a single live blocklist hit
// quarantines the segment regardless of send volume.
func TestBlocklistHitTripsBreakerImmediately(t *testing.T) {
	pool := newFakeSegmentPool()
	g := relay.NewSegmentReputationGuard(pool, relay.IsolationConfig{})

	g.RecordBlocklistHit(sending.SegmentEstablished, "spamhaus")
	if !g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("breaker did not trip on a blocklist hit")
	}
	if !pool.isQuarantined(sending.SegmentEstablished) {
		t.Error("pool segment not drained on blocklist hit")
	}
}

// ── quarantined segment drains and accepts no new senders ─────────────────────

// TestQuarantinedSegmentBlocksNewSenders verifies Assignable returns false for a
// quarantined segment (no new senders) while other segments stay assignable.
func TestQuarantinedSegmentBlocksNewSenders(t *testing.T) {
	g := relay.NewSegmentReputationGuard(newFakeSegmentPool(), relay.IsolationConfig{})

	// Unknown / healthy segments are assignable.
	if !g.Assignable(sending.SegmentEstablished) {
		t.Fatal("healthy segment should be assignable")
	}

	g.RecordBlocklistHit(sending.SegmentEstablished, "spamhaus")

	if g.Assignable(sending.SegmentEstablished) {
		t.Error("quarantined segment must not accept new senders")
	}
	if !g.Assignable(sending.SegmentUntrusted) {
		t.Error("unaffected segment should remain assignable")
	}
}

// TestQuarantineDrainsRealPool verifies the sending.Pool adapter: tripping the
// breaker quarantines exactly the affected segment's IPs in a real *sending.Pool
// so Pool.Select stops returning them (drain), while a sibling segment keeps
// serving.
func TestQuarantineDrainsRealPool(t *testing.T) {
	pool := sending.NewPool()
	estIP := net.ParseIP("10.0.0.1")
	untIP := net.ParseIP("10.0.1.1")
	pool.AddEntry(sending.PoolEntry{IP: estIP, HELOName: "est.example.com", Segment: sending.SegmentEstablished})
	pool.AddEntry(sending.PoolEntry{IP: untIP, HELOName: "unt.example.com", Segment: sending.SegmentUntrusted})

	adapter := relay.NewSendingPoolAdapter(pool)
	g := relay.NewSegmentReputationGuard(adapter, relay.IsolationConfig{})

	// Before: an established-hint Select prefers the established IP.
	if b, err := pool.Select("acct", sending.SegmentEstablished); err != nil {
		t.Fatalf("pre-quarantine Select failed: %v", err)
	} else if !b.LocalIP.Equal(estIP) {
		t.Fatalf("pre-quarantine: expected established IP %s, got %s", estIP, b.LocalIP)
	}

	// Trip the established segment.
	g.RecordBlocklistHit(sending.SegmentEstablished, "spamhaus")

	// After: the established IP is drained (never handed out again); traffic
	// falls back onto the still-healthy untrusted segment.
	for i := 0; i < 10; i++ {
		b, err := pool.Select("acct", sending.SegmentEstablished)
		if err != nil {
			t.Fatalf("Select after drain failed: %v", err)
		}
		if b.LocalIP.Equal(estIP) {
			t.Fatal("drained established IP was still handed out by Select")
		}
		if !b.LocalIP.Equal(untIP) {
			t.Fatalf("expected fallback to untrusted IP %s, got %s", untIP, b.LocalIP)
		}
	}

	// Now drain the untrusted segment too → no IP remains → ErrNoAvailableIP.
	g.RecordBlocklistHit(sending.SegmentUntrusted, "sorbs")
	if _, err := pool.Select("acct", sending.SegmentEstablished); err != sending.ErrNoAvailableIP {
		t.Errorf("with all segments drained: got err=%v, want ErrNoAvailableIP", err)
	}
}

// ── auto-recovery after cooldown ──────────────────────────────────────────────

// TestAutoRecoveryAfterCooldown verifies a quarantined segment is returned to
// service only after its reputation stays healthy for the full cooldown window,
// and that the pool segment is restored.
func TestAutoRecoveryAfterCooldown(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	pool := newFakeSegmentPool()
	g := relay.NewSegmentReputationGuardWithClock(pool, relay.IsolationConfig{
		Cooldown: 30 * time.Minute,
	}, clk.now)

	// Trip via blocklist, then clear it (simulating BlocklistMonitor delisting).
	g.RecordBlocklistHit(sending.SegmentEstablished, "spamhaus")
	if !g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("segment not quarantined after blocklist hit")
	}
	g.ClearBlocklistHit(sending.SegmentEstablished)

	// Still within cooldown → no recovery yet.
	clk.advance(29 * time.Minute)
	if recovered := g.Tick(); len(recovered) != 0 {
		t.Fatalf("recovered too early: %v", recovered)
	}
	if !g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("segment recovered before cooldown elapsed")
	}

	// Past cooldown → auto-recover.
	clk.advance(2 * time.Minute)
	recovered := g.Tick()
	if len(recovered) != 1 || recovered[0] != sending.SegmentEstablished {
		t.Fatalf("expected established recovered, got %v", recovered)
	}
	if g.IsQuarantined(sending.SegmentEstablished) {
		t.Error("segment still quarantined after cooldown")
	}
	if !g.Assignable(sending.SegmentEstablished) {
		t.Error("recovered segment should accept new senders again")
	}
	if pool.isQuarantined(sending.SegmentEstablished) {
		t.Error("pool segment was not restored on recovery")
	}
}

// TestRecoveryResetsOnRegression verifies that a fresh defect during the
// cooldown window resets the healthy timer so recovery does not fire.
func TestRecoveryResetsOnRegression(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	g := relay.NewSegmentReputationGuardWithClock(newFakeSegmentPool(), relay.IsolationConfig{
		Cooldown: 30 * time.Minute,
	}, clk.now)

	g.RecordBlocklistHit(sending.SegmentEstablished, "spamhaus")
	g.ClearBlocklistHit(sending.SegmentEstablished)

	// Most of the cooldown passes healthily...
	clk.advance(29 * time.Minute)
	g.Tick()

	// ...then a NEW blocklist hit lands, which must keep it quarantined and reset
	// the healthy timer.
	g.RecordBlocklistHit(sending.SegmentEstablished, "sorbs")
	g.ClearBlocklistHit(sending.SegmentEstablished)

	clk.advance(2 * time.Minute) // would have crossed the original window
	if recovered := g.Tick(); len(recovered) != 0 {
		t.Fatalf("recovered despite mid-cooldown regression: %v", recovered)
	}
	if !g.IsQuarantined(sending.SegmentEstablished) {
		t.Fatal("segment recovered despite regression resetting the timer")
	}

	// Now let the full window elapse from the reset point.
	clk.advance(30 * time.Minute)
	if recovered := g.Tick(); len(recovered) != 1 {
		t.Fatalf("expected recovery after full post-reset window, got %v", recovered)
	}
}
