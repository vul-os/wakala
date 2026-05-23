// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package sending implements the outbound SMTP sender, the warmed-IP pool,
// the ramp scheduler, and associated deliverability helpers.
package sending

import (
	"errors"
	"net"
	"sync"
)

// ErrNoAvailableIP is returned when Pool.Select cannot find a suitable
// SourceBinding for the given account (e.g. all IPs are quarantined or over
// their ramp cap).
var ErrNoAvailableIP = errors.New("pool: no available IP for selection")

// SegmentName identifies a pool segment by trust/age tier.
type SegmentName string

const (
	// SegmentNew holds freshly-provisioned IPs that have not yet started warming.
	SegmentNew SegmentName = "new"

	// SegmentUntrusted holds IPs in early warm-up phases (steps 0–1).
	SegmentUntrusted SegmentName = "untrusted"

	// SegmentEstablished holds IPs that have completed warm-up (step 4).
	SegmentEstablished SegmentName = "established"

	// SegmentDedicated holds IPs reserved for a single dedicated-IP account.
	SegmentDedicated SegmentName = "dedicated"
)

// PoolEntry represents one IP in the pool with its HELO name and assignment.
type PoolEntry struct {
	// IP is the source address for outbound connections.
	IP net.IP

	// HELOName is the hostname announced in the SMTP EHLO command.
	HELOName string

	// Segment identifies which trust/age tier this IP belongs to.
	Segment SegmentName

	// DedicatedAccount is non-empty for dedicated-IP entries and holds the
	// account ID that owns this IP exclusively.
	DedicatedAccount string

	// quarantined is true when the IP has been pulled from rotation.
	quarantined bool

	// quarantineReason is an informational string set on quarantine.
	quarantineReason string
}

// Pool is the warmed-IP pool.  It holds entries organised by segment and
// selects the correct SourceBinding for each outbound delivery attempt.
//
// Trust / age tiers (in ascending trust order):
//
//	new          — freshly provisioned; used only before warming begins.
//	untrusted    — early warm-up; ramp steps 0–1 (≤200/day).
//	established  — fully warmed; ramp step 4 (2500/day).
//	dedicated    — a single account's private IP.
//
// Selection rules:
//   - dedicated-IP accounts always get their own binding.
//   - untrusted/new accounts never receive an established IP.
//   - established accounts prefer the established segment.
//   - Quarantined IPs are never returned.
//
// Pool is safe for concurrent use.
type Pool struct {
	mu      sync.Mutex
	entries []*PoolEntry
}

// NewPool creates an empty Pool.  Use AddEntry to populate it.
func NewPool() *Pool {
	return &Pool{}
}

// AddEntry adds a PoolEntry to the pool.  It is safe to call at any time.
func (p *Pool) AddEntry(e PoolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := e // copy
	p.entries = append(p.entries, &entry)
}

// Quarantine removes ip from active rotation for the given reason.
// It implements the IPPool interface consumed by BlocklistMonitor.
func (p *Pool) Quarantine(ip net.IP, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		if e.IP.Equal(ip) {
			e.quarantined = true
			e.quarantineReason = reason
		}
	}
}

// Unquarantine restores ip to active rotation.
// It implements the IPPool interface consumed by BlocklistMonitor.
func (p *Pool) Unquarantine(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		if e.IP.Equal(ip) {
			e.quarantined = false
			e.quarantineReason = ""
		}
	}
}

// Select returns a SourceBinding for accountID honouring the policyHint
// (which maps to a SegmentName; empty string means "best available for this
// account").
//
// Selection rules (in order):
//  1. If policyHint matches SegmentDedicated and there is a dedicated entry for
//     accountID, return it.
//  2. If accountID has a dedicated entry, always return it (ignoring hint).
//  3. If policyHint specifies a segment, return an available IP from that
//     segment — but NEVER hand an untrusted/new segment hint an established IP,
//     and never hand a new/untrusted account an established IP.
//  4. Fall back to any available non-quarantined IP whose segment is compatible
//     with the account's trust level.
//
// "Compatible" means: established accounts may use any segment; new/untrusted
// accounts may only use new or untrusted segments.
func (p *Pool) Select(accountID, policyHint SegmentName) (SourceBinding, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1 & 2: dedicated binding takes priority.
	for _, e := range p.entries {
		if e.Segment == SegmentDedicated && e.DedicatedAccount == string(accountID) {
			if e.quarantined {
				return SourceBinding{}, ErrNoAvailableIP
			}
			return SourceBinding{LocalIP: e.IP, HELOName: e.HELOName}, nil
		}
	}

	// Determine whether the account is considered "untrusted" by the hint.
	accountIsLowTrust := policyHint == SegmentNew || policyHint == SegmentUntrusted || policyHint == ""

	// 3: honour an explicit non-dedicated segment hint.
	if policyHint != "" && policyHint != SegmentDedicated {
		for _, e := range p.entries {
			if e.quarantined {
				continue
			}
			if e.Segment != policyHint {
				continue
			}
			// Never hand an established IP to a low-trust account.
			if accountIsLowTrust && e.Segment == SegmentEstablished {
				continue
			}
			return SourceBinding{LocalIP: e.IP, HELOName: e.HELOName}, nil
		}
	}

	// 4: fallback — best available compatible IP.
	// Prefer established for established accounts, untrusted/new otherwise.
	var fallback *PoolEntry
	for _, e := range p.entries {
		if e.quarantined {
			continue
		}
		if e.Segment == SegmentDedicated {
			continue // dedicated IPs are never shared
		}
		// Low-trust accounts must not get established IPs.
		if accountIsLowTrust && e.Segment == SegmentEstablished {
			continue
		}
		if fallback == nil {
			fallback = e
			continue
		}
		// Prefer better-trusted segments for established accounts.
		if !accountIsLowTrust && segmentRank(e.Segment) > segmentRank(fallback.Segment) {
			fallback = e
		}
	}

	if fallback == nil {
		return SourceBinding{}, ErrNoAvailableIP
	}
	return SourceBinding{LocalIP: fallback.IP, HELOName: fallback.HELOName}, nil
}

// Entries returns a snapshot of all pool entries (including quarantined ones).
func (p *Pool) Entries() []PoolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]PoolEntry, len(p.entries))
	for i, e := range p.entries {
		out[i] = *e
	}
	return out
}

// segmentRank returns a numeric rank for a segment (higher = more trusted).
func segmentRank(s SegmentName) int {
	switch s {
	case SegmentNew:
		return 0
	case SegmentUntrusted:
		return 1
	case SegmentEstablished:
		return 2
	case SegmentDedicated:
		return 3
	default:
		return -1
	}
}
