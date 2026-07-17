package tunnel_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

// shutdown_e2e_test.go — GRACEFUL SHUTDOWN (SIGTERM path) end-to-end.
//
// drain_e2e_test.go proves the CP-signalled Drain() migration (make-before-break,
// zero drop). This file proves the OTHER half of the drain story: the SIGTERM /
// Shutdown(ctx) path that cmd/vulos-relayd runs on process teardown. The contract:
//
//   - an in-flight proxied request that is mid-response when Shutdown starts RUNS
//     TO COMPLETION (its full body is delivered) — nothing is dropped mid-response;
//   - Shutdown BLOCKS until that in-flight request finishes (the process exits only
//     after connections close), bounded by the ctx deadline; and
//   - once Shutdown starts, NEW connections are refused (the public listener stops
//     accepting), so no new work lands on a node that is going away.
//
// The whole path is real: a relay on a real TCP listener (so *Server.pubSrv is set
// and Shutdown actually drains it), a real agent over ws+yamux, and a real box.

// newRelayOnListener stands up a relay bound to a REAL ephemeral loopback listener
// (not httptest) so Shutdown(ctx) drains an actual *http.Server. Returns the server
// and its host:port. It mirrors the bind-then-rebind trick in the server package's
// shutdown_test: grab an ephemeral port, free it, and let ListenAndServe rebind it.
func newRelayOnListener(t *testing.T, grants []server.Grant) (*server.Server, string) {
	t.Helper()
	store, err := server.NewStaticTokenStore(grants)
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain:             testDomain,
		Tokens:             store,
		EnablePathMode:     true,
		MaxAgents:          8,
		MaxStreamsPerAgent: 8,
		RevokeSweepPeriod:  -1,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // free it; ListenAndServe rebinds the same host:port

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe(addr) }()
	t.Cleanup(func() {
		// If a test did not already Shutdown, close now and drain the serve error.
		_ = srv.Shutdown(context.Background())
		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
		}
	})

	// Wait until the listener is actually accepting.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			return srv, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay listener at %s never came up", addr)
	return nil, ""
}

// signalOnce sends a single non-blocking notification on a buffered chan. Using a
// send (not close) makes it safe even if the box handler runs more than once.
func signalOnce(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// TestShutdown_InFlightRequestCompletes proves the headline invariant: a request
// that is being served through the tunnel when Shutdown begins is NOT dropped —
// it runs to completion with its full body, and Shutdown blocks until it does.
func TestShutdown_InFlightRequestCompletes(t *testing.T) {
	const wantBody = "the-full-in-flight-response-body-that-must-not-be-truncated"

	arrived := make(chan struct{}, 1) // box signals the request reached it
	release := make(chan struct{})    // test releases the box to finish responding
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signalOnce(arrived)
		<-release // hold the response open until the test says go
		_, _ = io.WriteString(w, wantBody)
	}))
	defer target.Close()

	srv, addr := newRelayOnListener(t, defaultGrants())
	relayURL := "http://" + addr

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
	defer a.Stop()

	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	// Fire the request that will be in flight across the shutdown.
	type result struct {
		code int
		body string
		err  error
	}
	reqDone := make(chan result, 1)
	go func() {
		resp, err := http.Get(relayURL + "/t/" + testName + "/slow")
		if err != nil {
			reqDone <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		reqDone <- result{code: resp.StatusCode, body: string(b)}
	}()

	// Wait until the box has the request (it is now genuinely in flight).
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the box")
	}

	// Begin graceful shutdown WHILE the request is held open.
	var shutdownReturned atomic.Bool
	shutdownDone := make(chan error, 1)
	go func() {
		sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer scancel()
		err := srv.Shutdown(sctx)
		shutdownReturned.Store(true)
		shutdownDone <- err
	}()

	// Shutdown MUST block: give it a beat and confirm it has not returned while the
	// in-flight request is still unfinished. This is the "process exits only after
	// connections close" guarantee.
	time.Sleep(300 * time.Millisecond)
	if shutdownReturned.Load() {
		t.Fatal("Shutdown returned while an in-flight request was still open (dropped in-flight work)")
	}
	select {
	case r := <-reqDone:
		t.Fatalf("in-flight request finished before it was released: %+v", r)
	default:
	}

	// Release the box: the response now streams back through the (still-open) tunnel.
	close(release)

	// The in-flight request must complete cleanly with the FULL body.
	select {
	case r := <-reqDone:
		if r.err != nil {
			t.Fatalf("in-flight request errored across shutdown: %v", r.err)
		}
		if r.code != http.StatusOK {
			t.Fatalf("in-flight request status = %d, want 200", r.code)
		}
		if r.body != wantBody {
			t.Fatalf("in-flight response truncated/altered: got %q, want %q", r.body, wantBody)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed after release")
	}

	// Shutdown must now return (it was waiting on exactly that request).
	select {
	case err := <-shutdownDone:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the in-flight request completed")
	}

	// New work is refused: the public listener is closed, so a fresh dial fails.
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("relay still accepted a new connection after Shutdown")
	}
}

// TestShutdown_BoundedByDeadline proves the drain is BOUNDED: if an in-flight
// request refuses to finish, Shutdown does not hang forever — it returns by the ctx
// deadline (the process is not held hostage by one stuck stream).
func TestShutdown_BoundedByDeadline(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signalOnce(arrived)
		<-release // never released before the deadline fires
		_, _ = io.WriteString(w, "late")
	}))
	// Defers run LIFO: register target.Close() FIRST so close(release) runs BEFORE it
	// at teardown — otherwise target.Close() would block forever waiting on the held
	// handler that is itself parked on <-release (a cleanup deadlock).
	defer target.Close()
	defer close(release) // unblock the held box handler at test end

	srv, addr := newRelayOnListener(t, defaultGrants())
	relayURL := "http://" + addr

	a := agent.New(agent.Options{
		ServerURL: relayURL, Token: testToken, Name: testName, LocalAddr: localAddr(target.URL),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("agent.Start: %v", err)
	}
	defer a.Stop()
	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	go func() { _, _ = http.Get(relayURL + "/t/" + testName + "/stuck") }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the box")
	}

	// Shutdown with a SHORT deadline: a stuck in-flight request must not hang it.
	sctx, scancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer scancel()
	start := time.Now()
	err := srv.Shutdown(sctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with a stuck request = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Shutdown took %s, expected to return near the 400ms deadline (not hang)", elapsed)
	}
}
