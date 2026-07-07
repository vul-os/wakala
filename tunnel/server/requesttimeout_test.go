package server

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// TestProxy_RequestTimeout_CutsHalfDeadAgent is the regression guard for the
// RequestTimeout enforcement fix. RequestTimeout was defined, defaulted, and
// documented as "per public request forward timeout" but was NEVER applied, so a
// HALF-DEAD agent — one whose yamux keepalive still answers (session stays up) but
// which accepts a stream and never responds — would hold the public request open
// indefinitely. Once MaxStreamsPerAgent such streams accumulate the whole tunnel
// bricks (503 to everyone) with no recovery. The fix bounds time-to-response-headers
// and frees the stream slot, so requests fail fast with 502 and the tunnel keeps
// accepting new ones instead of wedging.
func TestProxy_RequestTimeout_CutsHalfDeadAgent(t *testing.T) {
	s, ts := newAdvServer(t, Config{
		EnablePathMode:     true,
		RequestTimeout:     400 * time.Millisecond,
		MaxStreamsPerAgent: 2, // small cap: a leak of held streams would brick the tunnel
	})

	// A manual HALF-DEAD agent: register normally, become the yamux server, accept
	// every stream the relay opens — and never write a response.
	c, nc := dialControl(t, ts.URL, "tok")
	defer c.Close(websocket.StatusNormalClosure, "")
	ack := registerAndReadAck(t, nc, "box1", "tok")
	if !ack.OK {
		t.Fatalf("register rejected: %+v", ack)
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Server(nc, cfg)
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	defer sess.Close()
	go func() {
		var held []*yamux.Stream
		for {
			st, err := sess.Accept()
			if err != nil {
				return
			}
			held = append(held, st.(*yamux.Stream)) // hold it open; never respond
			_ = held
		}
	}()

	// Wait for the relay to register the agent session.
	deadline := time.Now().Add(3 * time.Second)
	for s.registry.count() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.registry.count() != 1 {
		t.Fatalf("agent never registered (count=%d)", s.registry.count())
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Fire several MORE than the stream cap, sequentially. Pre-fix, the first
	// MaxStreamsPerAgent requests would hang forever (held streams never freed) and
	// subsequent ones would get 503; each request must instead fail fast with 502 and
	// free its slot so the NEXT request is served (never a 503 pile-up).
	for i := 0; i < 5; i++ {
		start := time.Now()
		resp, err := client.Get(ts.URL + "/t/box1/")
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		resp.Body.Close()
		elapsed := time.Since(start)
		if resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("req %d got 503: stream slots leaked (half-dead streams not freed)", i)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("req %d: want 502 (half-dead agent timed out), got %d", i, resp.StatusCode)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("req %d: RequestTimeout not enforced, took %v", i, elapsed)
		}
	}
}
