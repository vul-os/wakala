// direct_test.go — DIRECT-IP: end-to-end negotiation through a live relay + agent.
//
// These drive a REAL agent (ws control + yamux) against a real relay and assert:
//
//   - A box advertising a direct endpoint that the (stubbed) verifier accepts gets
//     its endpoint surfaced on the /_vulos-direct/resolve discovery endpoint, and
//     the agent's Snapshot reports it verified.
//   - A box whose advertised endpoint FAILS verification comes up on the relay path
//     anyway (fallback is seamless) and resolve reports direct=false.
//   - With direct negotiation DISABLED (config-gated off), an advertised endpoint is
//     ignored entirely and resolve always reports direct=false — pure relay behavior
//     is unchanged.
//   - The verifier is only consulted AFTER auth: an unauthorized register never
//     triggers a probe (the relay must not probe on an anonymous box's word).
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
)

// stubVerifier is an in-memory directEndpointVerifier for tests (no real probe).
// accept controls the verdict; calls counts how often verify ran.
type stubVerifier struct {
	accept bool
	calls  atomic.Int64
}

func (v *stubVerifier) verify(_ context.Context, endpoint string) (string, error) {
	v.calls.Add(1)
	if !v.accept {
		return "", errUnreachableStub
	}
	return endpoint, nil
}

var errUnreachableStub = &stubErr{"unreachable"}

type stubErr struct{ s string }

func (e *stubErr) Error() string { return e.s }

// liveRelay starts a relay Handler on an httptest server and returns its ws URL +
// http base URL. cfg is applied on top of a minimal single-grant store.
func liveRelay(t *testing.T, cfg Config) (wsURL, httpBase string, s *Server) {
	t.Helper()
	store, err := NewStaticTokenStore([]Grant{{Token: "tok", Names: []string{"box1"}}})
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	cfg.Domain = "relay.test"
	cfg.Tokens = store
	cfg.RevokeSweepPeriod = -1 // no background sweep in tests
	s, err = New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(s.Close)
	pub := httptest.NewServer(s.Handler())
	t.Cleanup(pub.Close)
	wsURL = "ws" + pub.URL[len("http"):]
	return wsURL, pub.URL, s
}

// resolveDirect calls the discovery endpoint host-routed to box1.relay.test and
// returns the parsed response.
func resolveDirect(t *testing.T, httpBase string) directResolveResponse {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, httpBase+wireDirectResolvePath, nil)
	req.Host = "box1.relay.test" // subdomain routing selects the tunnel name
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("resolve GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve status = %d", resp.StatusCode)
	}
	var out directResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode resolve: %v", err)
	}
	return out
}

// bringUpBox connects a real agent advertising directEP; returns a stop func + the
// agent so the caller can read its Snapshot.
func bringUpBox(t *testing.T, wsURL, directEP string) (*agent.Agent, func()) {
	t.Helper()
	target := startLoopbackTarget(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	a := agent.New(agent.Options{
		ServerURL: wsURL, Token: "tok", Name: "box1", LocalAddr: target,
		DirectEndpoint: directEP, HandshakeTimeout: 3 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := a.Start(ctx); err != nil {
		cancel()
		t.Fatalf("agent.Start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == agent.StatusConnected {
			return a, func() { a.Stop(); cancel() }
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.Stop()
	cancel()
	t.Fatalf("agent never connected: %+v", a.Snapshot())
	return nil, func() {}
}

func TestDirect_E2E_VerifiedEndpointAdvertised(t *testing.T) {
	sv := &stubVerifier{accept: true}
	ws, base, _ := liveRelay(t, Config{directVerifier: sv})

	a, stop := bringUpBox(t, ws, "https://box1.example.net")
	defer stop()

	// The agent learned its verified endpoint from the ack.
	snap := a.Snapshot()
	if !snap.DirectVerified || snap.DirectEndpoint != "https://box1.example.net" {
		t.Fatalf("agent snapshot should report verified direct endpoint, got %+v", snap)
	}
	if sv.calls.Load() != 1 {
		t.Fatalf("verifier should have run exactly once, ran %d", sv.calls.Load())
	}

	// A client discovers it via the resolve endpoint.
	got := resolveDirect(t, base)
	if !got.Direct || got.DirectEndpoint != "https://box1.example.net" {
		t.Fatalf("resolve should surface the verified endpoint, got %+v", got)
	}
	if got.Name != "box1" {
		t.Fatalf("resolve name = %q, want box1", got.Name)
	}
}

func TestDirect_E2E_UnverifiedFallsBackToRelay(t *testing.T) {
	sv := &stubVerifier{accept: false} // verification fails
	ws, base, _ := liveRelay(t, Config{directVerifier: sv})

	a, stop := bringUpBox(t, ws, "https://box1.example.net")
	defer stop()

	// The tunnel still came up on the relay path (fallback is seamless).
	snap := a.Snapshot()
	if snap.Status != agent.StatusConnected {
		t.Fatalf("box must still connect on the relay path when direct fails, got %v", snap.Status)
	}
	if snap.DirectVerified {
		t.Fatal("direct must NOT be reported verified when verification failed")
	}
	// Resolve reports no direct ⇒ clients use the relay path.
	got := resolveDirect(t, base)
	if got.Direct {
		t.Fatalf("resolve must report direct=false when verification failed, got %+v", got)
	}
}

func TestDirect_E2E_ConfigGatedOff_PureRelay(t *testing.T) {
	sv := &stubVerifier{accept: true}
	// DisableDirect => the verifier is never wired; advertised endpoints ignored.
	ws, base, srv := liveRelay(t, Config{DisableDirect: true, directVerifier: sv})
	if srv.directVerifier != nil {
		t.Fatal("DisableDirect must leave directVerifier nil")
	}

	_, stop := bringUpBox(t, ws, "https://box1.example.net")
	defer stop()

	if sv.calls.Load() != 0 {
		t.Fatalf("verifier must NOT run when direct is disabled, ran %d", sv.calls.Load())
	}
	got := resolveDirect(t, base)
	if got.Direct {
		t.Fatalf("with direct disabled, resolve must always be direct=false, got %+v", got)
	}
}

func TestDirect_VerifierNotConsultedForUnauthorized(t *testing.T) {
	// An unauthorized token must be rejected BEFORE any direct probe — the relay
	// must never probe an endpoint on an anonymous/unauthorized box's say-so.
	sv := &stubVerifier{accept: true}
	ws, _, _ := liveRelay(t, Config{directVerifier: sv})

	target := startLoopbackTarget(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	a := agent.New(agent.Options{
		ServerURL: ws, Token: "WRONG-TOKEN", Name: "box1", LocalAddr: target,
		DirectEndpoint: "https://box1.example.net", HandshakeTimeout: 3 * time.Second,
		MaxBackoff: 200 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = a.Start(ctx)
	// Give the (failed) handshake a moment.
	time.Sleep(600 * time.Millisecond)
	a.Stop()

	if sv.calls.Load() != 0 {
		t.Fatalf("verifier must NOT run for an unauthorized register, ran %d", sv.calls.Load())
	}
}
