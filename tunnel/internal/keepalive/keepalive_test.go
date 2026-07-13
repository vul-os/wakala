// keepalive_test.go — PURE, decision-level tests of the adaptive keepalive interval
// policy. No real sockets: a fake Pinger and a manual clock drive the logic, so the
// tests are fully deterministic. They pin the ratified idle-cost tweak: idle => a
// longer keepalive interval; active => the base interval; and dead-peer detection
// stays bounded (Idle + write timeout), never unbounded.
package keepalive

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testParams() Params {
	return Params{Base: 10 * time.Second, Idle: 60 * time.Second, IdleAfter: 2 * time.Minute}
}

// TestAdaptive_ActiveStaysAtBase: while streams are open the interval never backs
// off — active sessions behave exactly like the old fixed keepalive.
func TestAdaptive_ActiveStaysAtBase(t *testing.T) {
	t0 := time.Unix(0, 0)
	a := NewAdaptive(testParams(), t0)
	// Advance well past IdleAfter, but keep observing an open stream each tick.
	now := t0
	for i := 0; i < 10; i++ {
		now = now.Add(30 * time.Second)
		if got := a.Next(now, 1); got != 10*time.Second {
			t.Fatalf("active tick %d: interval = %v, want base 10s", i, got)
		}
	}
}

// TestAdaptive_IdleBacksOff: with no streams for >= IdleAfter the interval lengthens
// to Idle; before IdleAfter it stays at Base.
func TestAdaptive_IdleBacksOff(t *testing.T) {
	t0 := time.Unix(0, 0)
	a := NewAdaptive(testParams(), t0)

	// Just under the idle threshold => still base.
	if got := a.Next(t0.Add(119*time.Second), 0); got != 10*time.Second {
		t.Fatalf("pre-threshold interval = %v, want base 10s", got)
	}
	// At/after the idle threshold => backed-off Idle interval.
	if got := a.Next(t0.Add(2*time.Minute), 0); got != 60*time.Second {
		t.Fatalf("at-threshold interval = %v, want idle 60s", got)
	}
	if got := a.Next(t0.Add(10*time.Minute), 0); got != 60*time.Second {
		t.Fatalf("deep-idle interval = %v, want idle 60s", got)
	}
}

// TestAdaptive_ActivityRestoresBase: a backed-off idle session drops straight back
// to Base the moment a stream is observed again — reachability responsiveness is
// restored immediately on activity.
func TestAdaptive_ActivityRestoresBase(t *testing.T) {
	t0 := time.Unix(0, 0)
	a := NewAdaptive(testParams(), t0)

	// Go idle first.
	if got := a.Next(t0.Add(5*time.Minute), 0); got != 60*time.Second {
		t.Fatalf("idle interval = %v, want 60s", got)
	}
	// A stream appears => back to base immediately.
	if got := a.Next(t0.Add(5*time.Minute+1*time.Second), 2); got != 10*time.Second {
		t.Fatalf("restored interval = %v, want base 10s", got)
	}
	// And it stays at base for the next quiet tick that is within IdleAfter of the
	// activity we just saw.
	if got := a.Next(t0.Add(5*time.Minute+30*time.Second), 0); got != 10*time.Second {
		t.Fatalf("post-activity interval = %v, want base 10s", got)
	}
}

// TestAdaptive_DeadPeerDetectionBounded: the backed-off interval must stay bounded
// so a dead idle peer is still noticed within a predictable time. We assert the
// idle interval never exceeds a sane ceiling and always equals the configured Idle.
func TestAdaptive_DeadPeerDetectionBounded(t *testing.T) {
	t0 := time.Unix(0, 0)
	p := testParams()
	a := NewAdaptive(p, t0)
	got := a.Next(t0.Add(time.Hour), 0)
	if got != p.Idle {
		t.Fatalf("deep-idle interval = %v, want exactly Idle %v", got, p.Idle)
	}
	// The worst-case detection latency (idle interval) must be bounded and modest —
	// a dead tunnel is never left to linger unboundedly.
	if got > 2*time.Minute {
		t.Fatalf("idle interval %v exceeds the dead-peer detection ceiling", got)
	}
}

// TestParams_Normalized: misconfiguration can never produce a hot-looping (<=0)
// interval or an "idle" interval faster than base.
func TestParams_Normalized(t *testing.T) {
	// Zero base, idle shorter than base, zero IdleAfter all get coerced.
	n := Params{Base: 0, Idle: 1 * time.Second, IdleAfter: 0}.normalized()
	if n.Base <= 0 {
		t.Fatalf("Base must be coerced positive, got %v", n.Base)
	}
	if n.Idle < n.Base {
		t.Fatalf("Idle must be >= Base, got Idle=%v Base=%v", n.Idle, n.Base)
	}
	if n.IdleAfter <= 0 {
		t.Fatalf("IdleAfter must be coerced positive, got %v", n.IdleAfter)
	}
	// A fresh Adaptive with degenerate params must still pick a positive interval.
	a := NewAdaptive(Params{}, time.Unix(0, 0))
	if iv := a.Next(time.Unix(0, 0).Add(time.Hour), 0); iv <= 0 {
		t.Fatalf("interval must be positive, got %v", iv)
	}
}

// --- Run loop: minimal deterministic checks over a fake Pinger (no real sockets) ---

type fakePinger struct {
	pings   int
	streams int
	err     error
}

func (f *fakePinger) Ping() (time.Duration, error) { f.pings++; return 0, f.err }
func (f *fakePinger) NumStreams() int              { return f.streams }

// TestRun_ReturnsPingErrorForDeadPeer: when Ping fails, Run returns that error so
// the caller tears the session down (dead-peer path). Base=0 fires the timer
// immediately, keeping the test fast and deterministic.
func TestRun_ReturnsPingErrorForDeadPeer(t *testing.T) {
	dead := errors.New("keepalive timeout")
	p := &fakePinger{err: dead}
	// Base=0 normalizes to 10s, so drive via a very small base instead.
	err := Run(context.Background(), p, Params{Base: time.Millisecond, Idle: time.Millisecond, IdleAfter: time.Millisecond}, time.Now)
	if !errors.Is(err, dead) {
		t.Fatalf("Run should return the ping error, got %v", err)
	}
	if p.pings == 0 {
		t.Fatal("Run should have pinged at least once")
	}
}

// TestRun_StopsOnContextCancel: Run returns nil promptly when ctx is cancelled and
// does not leak. Use a long base so the only way out is the ctx path.
func TestRun_StopsOnContextCancel(t *testing.T) {
	p := &fakePinger{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, p, Params{Base: time.Hour, Idle: time.Hour, IdleAfter: time.Hour}, time.Now) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ctx-cancel should return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}
