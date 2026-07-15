package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

// staggered_reconnect_test.go — CONNECTION-FLOOD (agent side): a mass reconnect
// (every agent on a PoP told to re-dial when it drains) must NOT thundering-herd the
// target PoP. Each agent staggers its successor dial by a random offset in
// [0, ReconnectJitter), so N reconnects spread across the window instead of arriving
// synchronized. This test drives N real agents through a proactive reconnect and
// asserts their successor DIALS are spread across the window with a bounded rate.

// holdingRelayPeer plays the server half of ONE control connection: it reads the
// Register frame, acks OK, becomes the yamux client, and HOLDS the session until
// closeCh fires (so the agent stays "connected" — no spurious reconnects). Each call
// records the dial time via onDial.
func holdingRelayPeer(serverConn net.Conn, closeCh <-chan struct{}) {
	dec := json.NewDecoder(io.LimitReader(serverConn, wire.MaxControlMessage))
	var reg wire.Register
	if err := dec.Decode(&reg); err != nil {
		serverConn.Close()
		return
	}
	if err := json.NewEncoder(serverConn).Encode(wire.RegisterAck{
		Type: "register_ack", OK: true, PublicURL: "https://box.relay.test",
	}); err != nil {
		serverConn.Close()
		return
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Client(serverConn, cfg)
	if err != nil {
		serverConn.Close()
		return
	}
	go func() {
		<-closeCh
		_ = sess.Close()
		_ = serverConn.Close()
	}()
}

// TestStaggeredReconnect_SpreadsMassDrain starts N agents, waits for all to connect,
// then signals every one to reconnect AT THE SAME INSTANT (the drain thundering-herd
// scenario) and asserts the successor dials are STAGGERED across the jitter window —
// spread out, bounded per sub-window, and never all clustered at t=0.
func TestStaggeredReconnect_SpreadsMassDrain(t *testing.T) {
	const (
		n      = 24
		jitter = 400 * time.Millisecond
	)

	closeCh := make(chan struct{})
	defer close(closeCh)

	type dialRec struct {
		mu    sync.Mutex
		times []time.Time
	}
	recs := make([]*dialRec, n)
	agents := make([]*Agent, n)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < n; i++ {
		rec := &dialRec{}
		recs[i] = rec
		a := New(Options{
			ServerURL:        "ws://relay.test",
			Token:            "t",
			Name:             "box",
			LocalAddr:        "127.0.0.1:1",
			HandshakeTimeout: 2 * time.Second,
			ReconnectJitter:  jitter,
		})
		a.dialHook = func(context.Context, string) (net.Conn, error) {
			rec.mu.Lock()
			rec.times = append(rec.times, time.Now())
			rec.mu.Unlock()
			clientConn, serverConn := net.Pipe()
			go holdingRelayPeer(serverConn, closeCh)
			return clientConn, nil
		}
		agents[i] = a
		if err := a.Start(ctx); err != nil {
			t.Fatalf("agent %d Start: %v", i, err)
		}
	}

	// Wait for every agent to reach its FIRST (un-staggered) connect.
	for i, a := range agents {
		if !waitForStatus(a, StatusConnected, 3*time.Second) {
			t.Fatalf("agent %d never connected (status=%s)", i, a.Snapshot().Status)
		}
	}

	// Fire the mass reconnect: every agent is signaled at (nearly) the same instant.
	trigger := time.Now()
	for _, a := range agents {
		a.requestReconnect("drain")
	}

	// Collect each agent's SUCCESSOR dial offset (the first dial at/after the trigger).
	offsets := make([]time.Duration, 0, n)
	deadline := time.Now().Add(jitter + 3*time.Second)
	for len(offsets) < n && time.Now().Before(deadline) {
		offsets = offsets[:0]
		for _, rec := range recs {
			rec.mu.Lock()
			var found time.Time
			for _, ts := range rec.times {
				if !ts.Before(trigger) {
					found = ts
					break
				}
			}
			rec.mu.Unlock()
			if !found.IsZero() {
				offsets = append(offsets, found.Sub(trigger))
			}
		}
		if len(offsets) < n {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if len(offsets) != n {
		t.Fatalf("only %d/%d agents produced a successor dial", len(offsets), n)
	}

	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	minOff, maxOff := offsets[0], offsets[n-1]

	// (1) BOUNDED: every staggered dial lands within the window (+ scheduling slack).
	if maxOff > jitter+500*time.Millisecond {
		t.Fatalf("a successor dial at %s exceeded the jitter window %s (unbounded stagger)", maxOff, jitter)
	}

	// (2) SPREAD (NOT a herd): the reconnects must actually spread across the window,
	// not all fire together. With N=24 uniform offsets over the window, the span is
	// near the full window; require at least a third of it.
	if span := maxOff - minOff; span < jitter/3 {
		t.Fatalf("successor dials clustered in %s (< %s): thundering herd not spread", span, jitter/3)
	}

	// (3) BOUNDED RATE: no single tight sub-window swallows the whole herd. Split the
	// window into 4 buckets; the busiest must hold well under all N (uniform ≈ N/4).
	buckets := make([]int, 4)
	for _, off := range offsets {
		b := int(off * 4 / jitter)
		if b < 0 {
			b = 0
		}
		if b > 3 {
			b = 3
		}
		buckets[b]++
	}
	busiest := 0
	for _, c := range buckets {
		if c > busiest {
			busiest = c
		}
	}
	if busiest > (n*3)/4 {
		t.Fatalf("a single sub-window held %d/%d reconnects (buckets=%v): reconnect rate not bounded", busiest, n, buckets)
	}
}

// waitForStatus polls until the agent reaches want or the deadline elapses.
func waitForStatus(a *Agent, want Status, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return a.Snapshot().Status == want
}
