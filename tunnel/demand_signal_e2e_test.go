package tunnel_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
)

// demand_signal_e2e_test.go — AUTOSCALE DEMAND SIGNAL end-to-end.
//
// A CP-side autoscaler scales the relay pool off THIS node's live load surface:
// server.Load() returns the {Agents, Streams, TotalBytes} sample (autoscale.Sample,
// satisfying autoscale.LoadSource) that an Autoscaler samples each tick, and that
// the saturation sampler turns into the vulos_relay_saturation_ratio gauge an
// external orchestrator scrapes. load_test.go proves Load() reflects SYNTHETIC
// metric mutations; this file proves the three signal dimensions actually MOVE under
// REAL tunneled traffic over the ws+yamux path — i.e. the number the autoscaler
// consumes is a true reflection of live demand, not just an internal counter:
//
//   - Agents rises to 1 when a real agent registers and returns to 0 when it leaves;
//   - Streams counts an in-flight proxied request WHILE it is on the wire (and drops
//     back to 0 once it completes) — the in-flight gauge, not a cumulative counter;
//   - TotalBytes (cumulative) grows by at least the proxied response payload.

// TestDemandSignal_ReflectsLiveTunnelTraffic drives one real tunnel and asserts the
// autoscaler's load sample tracks it across register → in-flight request → done.
func TestDemandSignal_ReflectsLiveTunnelTraffic(t *testing.T) {
	const body = "demand-signal-payload-bytes-that-must-be-metered-through-the-tunnel"

	arrived := make(chan struct{}, 1) // box signals the request reached it
	release := make(chan struct{})    // test holds the response open to catch Streams==1
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signalOnce(arrived)
		<-release
		_, _ = io.WriteString(w, body)
	}))
	defer target.Close()

	srv, hs := newRelayWithServer(t, defaultGrants(), testDomain)
	relayURL := hs.URL

	// Baseline: no agents, no streams, no bytes.
	if ld := srv.Load(); ld.Agents != 0 || ld.Streams != 0 || ld.TotalBytes != 0 {
		t.Fatalf("baseline Load = %+v, want all zero", ld)
	}

	a := agent.New(agent.Options{
		ServerURL: relayURL,
		Token:     testToken,
		Name:      testName,
		LocalAddr: localAddr(target.URL),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("agent.Start: %v", err)
	}

	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	// Agents dimension now reflects the live tunnel.
	if ld := srv.Load(); ld.Agents != 1 {
		t.Fatalf("Load.Agents = %d after one agent connected, want 1", ld.Agents)
	}

	// Fire a request and hold it open at the box so it is genuinely in flight.
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		resp, err := http.Get(relayURL + "/t/" + testName + "/held")
		if err != nil {
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()

	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the box")
	}

	// Streams is an IN-FLIGHT gauge: while the box holds the response, exactly one
	// proxied stream is open, so the autoscaler sees Streams >= 1.
	if !waitFor2(2*time.Second, func() bool { return srv.Load().Streams >= 1 }) {
		t.Fatalf("Load.Streams never rose while a request was in flight (got %d)", srv.Load().Streams)
	}

	// Release the box; the response streams back and the request completes.
	close(release)
	select {
	case <-reqDone:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}

	// The in-flight gauge drops back to 0 once the stream closes...
	if !waitFor2(2*time.Second, func() bool { return srv.Load().Streams == 0 }) {
		t.Fatalf("Load.Streams did not return to 0 after the request completed (got %d)", srv.Load().Streams)
	}
	// ...and the cumulative byte counter has grown by at least the response payload.
	if ld := srv.Load(); ld.TotalBytes < int64(len(body)) {
		t.Fatalf("Load.TotalBytes = %d after proxying %d-byte body, want >= %d", ld.TotalBytes, len(body), len(body))
	}

	// When the agent leaves, the demand signal releases the node: Agents → 0 so the
	// autoscaler can scale this PoP down.
	a.Stop()
	if !waitFor2(3*time.Second, func() bool { return srv.Load().Agents == 0 }) {
		t.Fatalf("Load.Agents did not return to 0 after the agent left (got %d)", srv.Load().Agents)
	}
}
