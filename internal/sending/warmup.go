// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"net"
	"sync"
	"time"
)

// rampSteps defines the daily send cap for each warm-up step, in order.
// Step indices map to: 0=50, 1=200, 2=500, 3=1000, 4=2500.
var rampSteps = []int{50, 200, 500, 1000, 2500}

// WarmSignal classifies the health outcome of a single day's sends for an IP,
// used by the RampScheduler to decide graduation vs demotion.
type WarmSignal int

const (
	// WarmSignalHealthy indicates the day's metrics are within acceptable thresholds.
	WarmSignalHealthy WarmSignal = iota
	// WarmSignalBad indicates a bounce/complaint rate that exceeds the threshold,
	// triggering a demotion.
	WarmSignalBad
)

// ipRampState tracks warm-up state for a single IP.
type ipRampState struct {
	// step is the current ramp step index (0-based; capped at len(rampSteps)-1).
	step int

	// dayStart is midnight UTC for the current send day.
	dayStart time.Time

	// sentToday is the number of messages sent during the current day.
	sentToday int

	// consecutiveHealthy counts consecutive healthy days at the current step,
	// used to decide when to graduate to the next step.
	consecutiveHealthy int
}

// RampConfig holds configuration for a RampScheduler.
type RampConfig struct {
	// HealthyDaysToGraduate is the number of consecutive healthy days an IP
	// must maintain at its current step before advancing to the next step.
	// Default: 3.
	HealthyDaysToGraduate int

	// DayBoundaryLoc is the timezone used for day-boundary rollover. If nil,
	// UTC is used.
	DayBoundaryLoc *time.Location
}

func (c *RampConfig) healthyDaysToGraduate() int {
	if c.HealthyDaysToGraduate <= 0 {
		return 3
	}
	return c.HealthyDaysToGraduate
}

func (c *RampConfig) loc() *time.Location {
	if c.DayBoundaryLoc != nil {
		return c.DayBoundaryLoc
	}
	return time.UTC
}

// RampScheduler manages the per-IP warm-up ramp. It tracks each IP's current
// step (50→200→500→1k→2.5k messages/day), today's send count, and step-start
// date.
//
// The pipeline calls CapFor before selecting an IP to bind a message; the pool
// selector (RELAY-11) should refuse to bind IPs whose CapFor returns 0.
// Record is called after each successful send attempt.
//
// Graduation from one step to the next requires N consecutive healthy days
// (configurable via RampConfig.HealthyDaysToGraduate). A bad-signal day
// demotes the IP one step immediately.
//
// RampScheduler is safe for concurrent use.
type RampScheduler struct {
	mu  sync.Mutex
	ips map[string]*ipRampState
	cfg RampConfig
}

// NewRampScheduler creates a RampScheduler with the given configuration.
func NewRampScheduler(cfg RampConfig) *RampScheduler {
	return &RampScheduler{
		ips: make(map[string]*ipRampState),
		cfg: cfg,
	}
}

// ipKey converts a net.IP to a stable string key.
func ipKey(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func (r *RampScheduler) state(ip net.IP) *ipRampState {
	key := ipKey(ip)
	s, ok := r.ips[key]
	if !ok {
		s = &ipRampState{
			step:     0,
			dayStart: dayStart(time.Now(), r.cfg.loc()),
		}
		r.ips[key] = s
	}
	return s
}

// rollDay advances the day counters if the current wall-clock day has changed
// since dayStart, resetting sentToday and optionally incrementing the healthy
// streak.  The signal parameter captures the previous day's health; pass
// WarmSignalHealthy if no explicit signal was recorded.
//
// Must be called with r.mu held.
func (r *RampScheduler) rollDay(s *ipRampState, now time.Time) {
	today := dayStart(now, r.cfg.loc())
	if !today.After(s.dayStart) {
		return // same day — nothing to roll
	}
	// The day has changed. The previous day's health is tracked via
	// consecutive-healthy counter; if sentToday > 0 we treat missing explicit
	// signals as healthy (the caller uses RecordDaySignal for bad days).
	s.dayStart = today
	s.sentToday = 0
}

// CapFor returns the number of messages the given IP may still send today.
// Returns 0 if the IP has exhausted its daily allowance.
func (r *RampScheduler) CapFor(ip net.IP) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	s := r.state(ip)
	r.rollDay(s, now)

	allowance := rampSteps[s.step] - s.sentToday
	if allowance < 0 {
		allowance = 0
	}
	return allowance
}

// Record increments today's send count for ip. It should be called once per
// message that is successfully dispatched to the SMTP layer.
func (r *RampScheduler) Record(ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	s := r.state(ip)
	r.rollDay(s, now)
	s.sentToday++
}

// RecordDaySignal applies a daily health signal for ip.
//
//   - WarmSignalHealthy: increments the consecutive healthy counter; advances
//     to the next ramp step when the threshold is reached.
//   - WarmSignalBad: resets the healthy counter and demotes the IP one step.
//
// Callers feed this from RELAY-07 / RELAY-10 bounce/complaint/Rspamd signals
// on a per-day basis (e.g. at end-of-day or when a threshold crossing occurs).
func (r *RampScheduler) RecordDaySignal(ip net.IP, signal WarmSignal) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s := r.state(ip)
	switch signal {
	case WarmSignalHealthy:
		s.consecutiveHealthy++
		threshold := r.cfg.healthyDaysToGraduate()
		if s.consecutiveHealthy >= threshold && s.step < len(rampSteps)-1 {
			s.step++
			s.consecutiveHealthy = 0
		}
	case WarmSignalBad:
		s.consecutiveHealthy = 0
		if s.step > 0 {
			s.step--
		}
	}
}

// Step returns the current ramp step index (0 = 50/day … 4 = 2500/day) for ip.
func (r *RampScheduler) Step(ip net.IP) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state(ip).step
}

// DailyCap returns the absolute daily cap (in messages) for ip at its current
// step.
func (r *RampScheduler) DailyCap(ip net.IP) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return rampSteps[r.state(ip).step]
}

// dayStart returns midnight of t in the given location.
func dayStart(t time.Time, loc *time.Location) time.Time {
	t = t.In(loc)
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, loc)
}
