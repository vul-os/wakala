// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// ─── Attack class 5: trust-segment gating ────────────────────────────────────
//
// A new/untrusted sender must NEVER be placed on a warm/established IP: a fresh
// account can torch an established IP's reputation. The gating is: trust tier →
// segment hint → Pool.Select, and Pool.Select additionally refuses to hand a
// low-trust account an established IP even if it is the only one available.

// warmPool builds a pool that contains an established (warm) IP plus optional
// cold/ramp IPs.
func warmPool(withCold bool) (*sending.Pool, net.IP, net.IP, net.IP) {
	p := sending.NewPool()
	warm := net.ParseIP("203.0.113.1")
	cold := net.ParseIP("203.0.113.50")
	ramp := net.ParseIP("203.0.113.60")
	p.AddEntry(sending.PoolEntry{IP: warm, HELOName: "warm.mta", Segment: sending.SegmentEstablished})
	if withCold {
		p.AddEntry(sending.PoolEntry{IP: cold, HELOName: "cold.mta", Segment: sending.SegmentNew})
		p.AddEntry(sending.PoolEntry{IP: ramp, HELOName: "ramp.mta", Segment: sending.SegmentUntrusted})
	}
	return p, warm, cold, ramp
}

// ATTACK: a brand-new (untrusted) sender requests an IP from a pool that
// contains a warm/established IP. EXPECT: it is NOT given the established IP —
// it lands on a cold/ramp segment instead.
func TestTrustGating_NewSender_NeverRidesWarmIP(t *testing.T) {
	pool, warm, _, _ := warmPool(true)

	// A new account: TrustNew → SegmentNew hint.
	src := sending.StaticTrustSource{Tier: sending.TrustNew}
	hint := sending.SegmentForTrust(src, "brand-new-account")
	if hint != sending.SegmentNew {
		t.Fatalf("trust→segment: new account should map to SegmentNew, got %q", hint)
	}

	binding, err := pool.Select("brand-new-account", hint)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if binding.LocalIP.Equal(warm) {
		t.Fatal("VULN: a new/untrusted sender was placed on the warm/established IP")
	}
}

// ATTACK: the harder case — the pool's ONLY non-quarantined IP is the warm one.
// A low-trust account must STILL not be handed it (Pool defers instead of
// promoting). EXPECT: ErrNoAvailableIP, never the established IP.
func TestTrustGating_NewSender_DefersWhenOnlyWarmIPExists(t *testing.T) {
	pool, warm, _, _ := warmPool(false) // only the established IP exists

	src := sending.StaticTrustSource{Tier: sending.TrustUntrusted}
	hint := sending.SegmentForTrust(src, "ramp-account")

	binding, err := pool.Select("ramp-account", hint)
	if err == nil && binding.LocalIP.Equal(warm) {
		t.Fatal("VULN: low-trust account promoted onto the only (established) IP instead of deferring")
	}
	if err != sending.ErrNoAvailableIP {
		t.Fatalf("want ErrNoAvailableIP (defer) for a low-trust account with only a warm IP, got binding=%v err=%v", binding.LocalIP, err)
	}
}

// FAIL-CLOSED: a nil TrustSource must classify the account at the coldest tier,
// so a missing classifier can never accidentally promote a sender to warm IPs.
func TestTrustGating_NilTrustSource_FailsClosedToCold(t *testing.T) {
	hint := sending.SegmentForTrust(nil, "anyone")
	if hint != sending.SegmentNew {
		t.Fatalf("VULN: nil TrustSource did not fail closed; hint=%q (want %q)", hint, sending.SegmentNew)
	}
}

// captureBinding is an inner Sender that records the source IP the PoolSender
// chose for each message — the canary for the trust-gating attack via the REAL
// production send path.
type captureBinding struct {
	mu  sync.Mutex
	ips []net.IP
}

func (c *captureBinding) Send(_ context.Context, msg sending.Message) (sending.SendResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if msg.Binding != nil {
		c.ips = append(c.ips, msg.Binding.LocalIP)
	}
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

func (c *captureBinding) usedWarm(warm net.IP) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range c.ips {
		if ip.Equal(warm) {
			return true
		}
	}
	return false
}

// ATTACK (self-inflation, production path): a sender tries to GAME its way onto
// warm IPs. The authoritative TrustSource is the ONLY thing that decides
// eligibility — a sender has no input into it. We drive the real PoolSender: an
// account the TrustSource classifies as TrustNew must be confined to the cold
// segment and must NEVER ride the warm/established IP, even when warm + cold IPs
// both exist. EXPECT: the captured source IP is never the warm one.
func TestTrustGating_SelfInflation_ProductionPath_Blocked(t *testing.T) {
	pool, warm, cold, _ := warmPool(true)
	_ = cold

	inner := &captureBinding{}
	// The authoritative classifier says: brand-new account. A sender cannot
	// override this — it is resolved server-side from reputation/trust state.
	ps := &sending.PoolSender{
		Pool:  pool,
		Inner: inner,
		Trust: sending.StaticTrustSource{Tier: sending.TrustNew},
	}

	for i := 0; i < 10; i++ {
		_, err := ps.Send(context.Background(), sending.Message{
			ID:         "atk",
			AccountID:  "self-inflating-account",
			Sender:     "attacker@new.example",
			Recipients: []string{"victim@dest.example"},
			RawRFC822:  []byte("Subject: x\r\n\r\nbody"),
		})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if inner.usedWarm(warm) {
		t.Fatal("VULN: a TrustNew account was placed on the warm/established IP via the real send path")
	}
}

// ATTACK (self-inflation, pool seam): even when handed the authoritative tier
// directly, SelectForTrust must IGNORE a forged request for a warmer segment
// than the tier permits. A TrustNew account asking for SegmentEstablished is
// still denied the warm IP. EXPECT: never the warm IP (deferred or cold).
func TestTrustGating_SelectForTrust_IgnoresForgedSegment(t *testing.T) {
	pool, warm, _, _ := warmPool(false) // only the warm IP exists

	// Account is authoritatively TrustNew but FORGES a request for the
	// established segment. SelectForTrust decides by tier, not the request.
	b, err := pool.SelectForTrust("liar", sending.TrustNew, sending.SegmentEstablished)
	if err == nil && b.LocalIP.Equal(warm) {
		t.Fatal("VULN: SelectForTrust honoured a forged established-segment request for a TrustNew account")
	}
	if err != sending.ErrNoAvailableIP {
		t.Fatalf("a TrustNew account requesting established with only a warm IP must defer (ErrNoAvailableIP), got binding=%v err=%v", b.LocalIP, err)
	}
}

// CONTROL: an ESTABLISHED account rides the warm IP — proves the gate is real
// (it discriminates by trust, not a blanket deny).
func TestTrustGating_EstablishedSender_RidesWarmIP(t *testing.T) {
	pool, warm, _, _ := warmPool(true)
	src := sending.StaticTrustSource{Tier: sending.TrustEstablished}
	hint := sending.SegmentForTrust(src, "old-trusted-account")
	if hint != sending.SegmentEstablished {
		t.Fatalf("established account should map to SegmentEstablished, got %q", hint)
	}
	binding, err := pool.Select("old-trusted-account", hint)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if !binding.LocalIP.Equal(warm) {
		t.Fatalf("established account should ride the warm IP, got %v", binding.LocalIP)
	}
}
