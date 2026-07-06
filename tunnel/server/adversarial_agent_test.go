// adversarial_agent_test.go — WAVE61-RELAY-ADVERSARIAL: a real agent driver for the
// server-package adversarial tests that need a LIVE session (over-quota mid-session
// cut, metering exactness). It uses the actual tunnel/agent client against a real
// loopback target, so the full wire path (ws control conn + yamux + HTTP proxy) is
// exercised, not a mock.
package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
)

// startLoopbackTarget starts a loopback HTTP server with handler h and returns its
// host:port (a 127.0.0.1 address, so it passes the agent's SSRF guard).
func startLoopbackTarget(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln.Addr().String()
}

// connectLiveAgentTo brings a real agent up against the relay, pointed at target,
// and blocks until it reports connected. Returns a stop func.
func connectLiveAgentTo(t *testing.T, relayURL, token, name, target string) func() {
	t.Helper()
	a := agent.New(agent.Options{
		ServerURL: relayURL, Token: token, Name: name, LocalAddr: target,
		HandshakeTimeout: 3 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := a.Start(ctx); err != nil {
		cancel()
		t.Fatalf("agent.Start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == agent.StatusConnected {
			return func() { a.Stop(); cancel() }
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.Stop()
	cancel()
	t.Fatalf("agent never connected: %+v", a.Snapshot())
	return func() {}
}

// connectLiveAgent connects an agent whose local target just returns 200 OK.
func connectLiveAgent(t *testing.T, relayURL, token, name string) func() {
	target := startLoopbackTarget(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return connectLiveAgentTo(t, relayURL, token, name, target)
}

// connectLiveAgentEcho connects an agent whose local target echoes the request body
// back (so response bytes flow too), for the metering test.
func connectLiveAgentEcho(t *testing.T, relayURL, token, name string) func() {
	target := startLoopbackTarget(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "echo:%s", b)
	})
	return connectLiveAgentTo(t, relayURL, token, name, target)
}
