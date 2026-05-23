// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"net"
	"testing"
	"time"
)

// parseIP is a test helper that panics on invalid IP strings.
func parseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid IP: " + s)
	}
	return ip
}

func TestRampScheduler_InitialCap(t *testing.T) {
	r := NewRampScheduler(RampConfig{})
	ip := parseIP("1.2.3.4")

	// A fresh IP starts at step 0 with cap 50.
	if got := r.DailyCap(ip); got != 50 {
		t.Fatalf("DailyCap: want 50 got %d", got)
	}
	if got := r.CapFor(ip); got != 50 {
		t.Fatalf("CapFor: want 50 got %d", got)
	}
}

func TestRampScheduler_RecordDecrementsCap(t *testing.T) {
	r := NewRampScheduler(RampConfig{})
	ip := parseIP("1.2.3.4")

	for i := 0; i < 5; i++ {
		r.Record(ip)
	}

	if got := r.CapFor(ip); got != 45 {
		t.Fatalf("after 5 records CapFor: want 45 got %d", got)
	}
}

func TestRampScheduler_CapExhaustion(t *testing.T) {
	r := NewRampScheduler(RampConfig{})
	ip := parseIP("1.2.3.4")

	// Exhaust all 50 sends.
	for i := 0; i < 50; i++ {
		r.Record(ip)
	}

	if got := r.CapFor(ip); got != 0 {
		t.Fatalf("exhausted cap: want 0 got %d", got)
	}
}

func TestRampScheduler_DayRollover(t *testing.T) {
	r := NewRampScheduler(RampConfig{})
	ip := parseIP("1.2.3.4")

	// Send 30 messages.
	for i := 0; i < 30; i++ {
		r.Record(ip)
	}

	// Manually wind back the dayStart to yesterday to simulate a day change.
	r.mu.Lock()
	s := r.state(ip)
	s.dayStart = s.dayStart.Add(-25 * time.Hour)
	r.mu.Unlock()

	// After the rollover, cap should be reset to the full daily allowance.
	if got := r.CapFor(ip); got != rampSteps[0] {
		t.Fatalf("after rollover CapFor: want %d got %d", rampSteps[0], got)
	}
}

func TestRampScheduler_GraduationAfterHealthyDays(t *testing.T) {
	cfg := RampConfig{HealthyDaysToGraduate: 2}
	r := NewRampScheduler(cfg)
	ip := parseIP("10.0.0.1")

	if r.Step(ip) != 0 {
		t.Fatalf("initial step: want 0")
	}

	r.RecordDaySignal(ip, WarmSignalHealthy)
	if r.Step(ip) != 0 {
		t.Fatalf("after 1 healthy day: want step 0")
	}

	r.RecordDaySignal(ip, WarmSignalHealthy)
	if r.Step(ip) != 1 {
		t.Fatalf("after 2 healthy days: want step 1 got %d", r.Step(ip))
	}
	if got := r.DailyCap(ip); got != 200 {
		t.Fatalf("step 1 DailyCap: want 200 got %d", got)
	}
}

func TestRampScheduler_DemotionOnBadSignal(t *testing.T) {
	cfg := RampConfig{HealthyDaysToGraduate: 1}
	r := NewRampScheduler(cfg)
	ip := parseIP("10.0.0.2")

	// Graduate to step 1.
	r.RecordDaySignal(ip, WarmSignalHealthy)
	if r.Step(ip) != 1 {
		t.Fatalf("pre-demotion step: want 1 got %d", r.Step(ip))
	}

	// Bad signal should demote back to step 0.
	r.RecordDaySignal(ip, WarmSignalBad)
	if r.Step(ip) != 0 {
		t.Fatalf("after demotion: want step 0 got %d", r.Step(ip))
	}
}

func TestRampScheduler_DemotionAtStep0IsNoop(t *testing.T) {
	r := NewRampScheduler(RampConfig{})
	ip := parseIP("10.0.0.3")

	// Step 0 — demotion should not go below 0.
	r.RecordDaySignal(ip, WarmSignalBad)
	if r.Step(ip) != 0 {
		t.Fatalf("demotion at step 0: want 0 got %d", r.Step(ip))
	}
}

func TestRampScheduler_FullRamp(t *testing.T) {
	cfg := RampConfig{HealthyDaysToGraduate: 1}
	r := NewRampScheduler(cfg)
	ip := parseIP("192.0.2.1")

	expectedCaps := []int{50, 200, 500, 1000, 2500}
	for i, want := range expectedCaps {
		if got := r.DailyCap(ip); got != want {
			t.Fatalf("step %d DailyCap: want %d got %d", i, want, got)
		}
		if i < len(expectedCaps)-1 {
			r.RecordDaySignal(ip, WarmSignalHealthy)
		}
	}

	// At the final step, another healthy day must NOT advance beyond the last step.
	r.RecordDaySignal(ip, WarmSignalHealthy)
	if got := r.Step(ip); got != len(rampSteps)-1 {
		t.Fatalf("beyond max step: want %d got %d", len(rampSteps)-1, got)
	}
}

func TestRampScheduler_ConsecutiveHealthyResetsOnBad(t *testing.T) {
	cfg := RampConfig{HealthyDaysToGraduate: 3}
	r := NewRampScheduler(cfg)
	ip := parseIP("198.51.100.1")

	r.RecordDaySignal(ip, WarmSignalHealthy)
	r.RecordDaySignal(ip, WarmSignalHealthy)
	// Should still be at step 0 (need 3 healthy days).
	if r.Step(ip) != 0 {
		t.Fatalf("want step 0 after 2 healthy days")
	}

	// Bad signal resets healthy counter.
	r.RecordDaySignal(ip, WarmSignalBad)

	// Two more healthy days should not graduate (counter was reset).
	r.RecordDaySignal(ip, WarmSignalHealthy)
	r.RecordDaySignal(ip, WarmSignalHealthy)
	if r.Step(ip) != 0 {
		t.Fatalf("want step 0 after counter reset; got %d", r.Step(ip))
	}

	// Third healthy day after the reset graduates.
	r.RecordDaySignal(ip, WarmSignalHealthy)
	if r.Step(ip) != 1 {
		t.Fatalf("want step 1 after 3 healthy days post-reset; got %d", r.Step(ip))
	}
}

func TestRampScheduler_MultipleIPs(t *testing.T) {
	r := NewRampScheduler(RampConfig{HealthyDaysToGraduate: 1})
	ip1 := parseIP("10.1.1.1")
	ip2 := parseIP("10.1.1.2")

	r.RecordDaySignal(ip1, WarmSignalHealthy) // ip1 → step 1
	// ip2 remains at step 0.
	if r.Step(ip1) != 1 {
		t.Fatalf("ip1 step: want 1 got %d", r.Step(ip1))
	}
	if r.Step(ip2) != 0 {
		t.Fatalf("ip2 step: want 0 got %d", r.Step(ip2))
	}
}
