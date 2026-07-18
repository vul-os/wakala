package tunnel_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
	"github.com/vul-os/vulos-relay/tunnel/cost"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

// concurrency_cost_test.go — TASK-45 (relay half): prove the relay scales under REAL
// concurrency GRACEFULLY, with COST accounting, and holds its graceful-drain contract
// UNDER LOAD. Everything here runs on the real ws+yamux wire in-process (no network
// flood) and is deterministic (fixed byte volumes, no time/random-seeded flakiness) so
// it runs green under `go test -race`.
//
// scaling_bench_test.go already measures per-tunnel heap/goroutine COST and aggregate
// throughput, but it is skipped under -short and its guards are order-of-magnitude
// sanity bounds, not exact assertions. These tests add the exact, race-checked
// guarantees the "scales gracefully, cost-managed" claim rests on:
//
//  1. N concurrent tunnels register and relay bytes EXACTLY, with no data race and no
//     goroutine leak once torn down;
//  2. a slow consumer under load does not starve other tunnels and does not blow memory
//     (yamux flow-control backpressure, tied to the slow-body DoS hardening);
//  3. graceful drain UNDER LOAD — N in-flight streams all complete while new work is
//     refused; and
//  4. bytes relayed → a grounded €1/TB Hetzner data-plane cost projection.

// settledGoroutines GCs repeatedly and returns a STABILIZED goroutine count — the value
// once several consecutive samples agree within scheduler noise — so a leak assertion
// measures the quiesced plateau rather than a transient dip or a teardown in progress.
func settledGoroutines() int {
	last := runtime.NumGoroutine()
	stable := 0
	for i := 0; i < 120; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n >= last-1 && n <= last+1 {
			if stable++; stable >= 5 {
				return n
			}
		} else {
			stable = 0
		}
		last = n
	}
	return runtime.NumGoroutine()
}

// newScaleRelay stands up a relay whose caps and rate limits are sized for a
// concurrency test (limiters disabled — we measure capacity, not throttling, which is
// covered by ratelimit_test.go).
func newScaleRelay(t *testing.T, names []string, maxStreams int) (*server.Server, *httptest.Server) {
	t.Helper()
	store, err := server.NewStaticTokenStore([]server.Grant{{Token: testToken, Names: names}})
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain:             testDomain,
		Tokens:             store,
		EnablePathMode:     true,
		MaxAgents:          len(names) + 8,
		MaxStreamsPerAgent: maxStreams,
		RevokeSweepPeriod:  -1,
		PublicReqRate:      -1,
		GlobalReqRate:      -1,
		ControlConnRate:    -1,
		GlobalConnRate:     -1,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	t.Cleanup(srv.Close)
	return srv, hs
}

// TestConcurrentTunnels_ExactBytesAndCost_NoLeak brings up N real tunnels, drives a
// deterministic request fan-out concurrently across all of them, and asserts:
//   - every request succeeds with the full body (no data races under -race);
//   - the relay's cumulative byte counter equals EXACTLY the bytes it moved (GETs carry
//     no request body and headers are unmetered, so the total is response bytes only);
//   - the €1/TB Hetzner cost projection matches that exact volume; and
//   - tearing every tunnel down returns the process to its goroutine baseline (no leak).
func TestConcurrentTunnels_ExactBytesAndCost_NoLeak(t *testing.T) {
	const (
		nTunnels = 16
		reqsPer  = 8
		bodySize = 4096
	)
	body := bytes.Repeat([]byte("z"), bodySize)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer target.Close()

	names := make([]string, nTunnels)
	for i := range names {
		names[i] = fmt.Sprintf("cbx%02d", i)
	}
	srv, relay := newScaleRelay(t, names, 16)

	// Goroutine baseline AFTER the relay/target exist but BEFORE any tunnel, so the
	// delta isolates tunnel goroutines.
	base := settledGoroutines()

	ctx, cancel := context.WithCancel(context.Background())
	agents := make([]*agent.Agent, nTunnels)
	local := localAddr(target.URL)
	for i := 0; i < nTunnels; i++ {
		a := agent.New(agent.Options{
			ServerURL: relay.URL, Token: testToken, Name: names[i],
			LocalAddr: local, ReconnectJitter: -1,
		})
		if err := a.Start(ctx); err != nil {
			cancel()
			t.Fatalf("agent %d start: %v", i, err)
		}
		agents[i] = a
	}
	if !waitFor2(15*time.Second, func() bool { return srv.AgentCount() == nTunnels }) {
		cancel()
		t.Fatalf("only %d/%d tunnels registered", srv.AgentCount(), nTunnels)
	}

	// Fan out reqsPer requests to EVERY tunnel, all concurrently.
	tr := &http.Transport{MaxIdleConns: nTunnels * 2, MaxIdleConnsPerHost: nTunnels * 2}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr}
	var (
		wg   sync.WaitGroup
		ok   atomic.Int64
		fail atomic.Int64
	)
	for i := 0; i < nTunnels; i++ {
		for j := 0; j < reqsPer; j++ {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				resp, err := client.Get(relay.URL + "/t/" + name + "/")
				if err != nil {
					fail.Add(1)
					return
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK || n != bodySize {
					fail.Add(1)
					return
				}
				ok.Add(1)
			}(names[i])
		}
	}
	wg.Wait()

	wantReq := int64(nTunnels * reqsPer)
	if fail.Load() != 0 || ok.Load() != wantReq {
		t.Fatalf("concurrent fan-out: ok=%d fail=%d, want %d ok / 0 fail", ok.Load(), fail.Load(), wantReq)
	}

	// EXACT byte accounting: only these GET responses transited the relay.
	wantBytes := wantReq * bodySize
	if got := srv.Load().TotalBytes; got != wantBytes {
		t.Fatalf("TotalBytes = %d, want EXACTLY %d (%d reqs × %d B)", got, wantBytes, wantReq, bodySize)
	}

	// COST projection grounded in the exact volume.
	eur := cost.ProjectEUR(wantBytes, cost.HetznerEUEURPerTB)
	wantEUR := float64(wantBytes) / float64(cost.BytesPerTB) * cost.HetznerEUEURPerTB
	if math.Abs(eur-wantEUR) > 1e-12 {
		t.Fatalf("cost projection = %v, want %v", eur, wantEUR)
	}
	t.Logf("CONCURRENCY+COST: %d tunnels × %d reqs relayed %d B exactly → €%.9f @ €1/TB (Hetzner EU); "+
		"1 TB of relay traffic ⇒ €%.2f, i.e. €5/mo bandwidth ⇒ %.0f TB",
		nTunnels, reqsPer, wantBytes, eur, cost.HetznerEUEURPerTB, cost.TBFor(5, cost.HetznerEUEURPerTB))

	// Tear every tunnel down and prove no goroutine leak. Close the client's pooled
	// keep-alive connections FIRST — those are live pooled conns, not leaks, and would
	// otherwise inflate the count — then stop the agents and wait for the relay to drop
	// them, so the sample measures the quiesced steady state.
	tr.CloseIdleConnections()
	cancel()
	for _, a := range agents {
		a.Stop()
	}
	waitFor2(10*time.Second, func() bool { return srv.AgentCount() == 0 })
	after := settledGoroutines()
	if after-base > 15 {
		t.Fatalf("goroutine leak after tearing down %d tunnels: base=%d after=%d (grew %d)",
			nTunnels, base, after, after-base)
	}
	t.Logf("NO-LEAK: goroutines base=%d after teardown=%d (delta %d ≤ 15)", base, after, after-base)
}

// TestSlowConsumer_DoesNotStarveOthers_BoundedMemory parks several slow readers on one
// tunnel (they receive headers but never drain the body) and proves that (a) requests
// to a DIFFERENT tunnel still complete promptly — the slow readers do not starve the
// relay — and (b) memory stays bounded: yamux per-stream flow control caps in-flight
// bytes at the receive window, so K parked readers hold ~K×window, NOT K×fullBody. This
// is the positive-capacity counterpart to the slow-body DoS guard (slowbody_test.go),
// which proves the malicious upload case is cut.
func TestSlowConsumer_DoesNotStarveOthers_BoundedMemory(t *testing.T) {
	const (
		slowBody   = 8 << 20 // 8 MiB response the slow reader never drains
		fastBody   = 256
		slowReader = 4  // parked readers on the slow tunnel
		fastReqs   = 40 // requests to the fast tunnel that must NOT be starved
	)
	bigBody := bytes.Repeat([]byte("S"), slowBody)
	slowTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // get headers to the client so client.Get returns while body is undrained
		}
		_, _ = w.Write(bigBody)
	}))
	defer slowTarget.Close()
	smallBody := bytes.Repeat([]byte("F"), fastBody)
	fastTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(smallBody)
	}))
	defer fastTarget.Close()

	names := []string{"slowbox", "fastbox"}
	// Stream cap well above fastReqs so the burst never hits the per-agent cap — this
	// test isolates cross-tunnel starvation, not the (separately tested) stream cap.
	srv, relay := newScaleRelay(t, names, 64)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slowA := agent.New(agent.Options{ServerURL: relay.URL, Token: testToken, Name: "slowbox", LocalAddr: localAddr(slowTarget.URL), ReconnectJitter: -1})
	fastA := agent.New(agent.Options{ServerURL: relay.URL, Token: testToken, Name: "fastbox", LocalAddr: localAddr(fastTarget.URL), ReconnectJitter: -1})
	if err := slowA.Start(ctx); err != nil {
		t.Fatalf("slow agent: %v", err)
	}
	defer slowA.Stop()
	if err := fastA.Start(ctx); err != nil {
		t.Fatalf("fast agent: %v", err)
	}
	defer fastA.Stop()
	if !waitFor2(10*time.Second, func() bool { return srv.AgentCount() == 2 }) {
		t.Fatalf("agents did not register (got %d)", srv.AgentCount())
	}

	var heapBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&heapBefore)

	// Park slowReader responses: read ONLY the headers (client.Get returns after them),
	// then hold the body open WITHOUT reading it, applying backpressure to the relay.
	parked := make([]*http.Response, 0, slowReader)
	defer func() {
		for _, resp := range parked {
			resp.Body.Close()
		}
	}()
	for i := 0; i < slowReader; i++ {
		resp, err := http.Get(relay.URL + "/t/slowbox/big")
		if err != nil {
			t.Fatalf("park slow reader %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("slow reader %d status = %d", i, resp.StatusCode)
		}
		parked = append(parked, resp) // deliberately do NOT read resp.Body
	}

	// While the slow readers are parked, fast-tunnel requests must all succeed quickly.
	tr := &http.Transport{MaxIdleConns: 16, MaxIdleConnsPerHost: 16}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	var wg sync.WaitGroup
	var fastOK, fastFail atomic.Int64
	start := time.Now()
	for i := 0; i < fastReqs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(relay.URL + "/t/fastbox/")
			if err != nil {
				fastFail.Add(1)
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || n != fastBody {
				fastFail.Add(1)
				return
			}
			fastOK.Add(1)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	if fastFail.Load() != 0 || fastOK.Load() != fastReqs {
		t.Fatalf("slow readers STARVED the fast tunnel: ok=%d fail=%d, want %d/0",
			fastOK.Load(), fastFail.Load(), fastReqs)
	}
	// Primary starvation signal is the success count above (a starved fast tunnel fails
	// on the client timeout). This elapsed bound is a soft head-of-line-blocking guard,
	// kept loose so it does not flake on slow/-race CI.
	if elapsed > 8*time.Second {
		t.Fatalf("fast tunnel served %d reqs in %v while slow readers parked — starvation/head-of-line blocking?", fastReqs, elapsed)
	}

	// Memory bound: if the relay buffered each parked response IN FULL it would hold
	// slowReader×slowBody = 32 MiB. Flow control caps it at ~a receive window per stream,
	// so the growth must be a small fraction of the unbounded figure.
	var heapAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&heapAfter)
	growth := int64(heapAfter.HeapInuse) - int64(heapBefore.HeapInuse)
	unbounded := int64(slowReader) * slowBody
	if growth > unbounded/2 {
		t.Fatalf("memory not bounded under slow consumers: heap grew %d B, near the unbounded %d B — flow control not applying backpressure",
			growth, unbounded)
	}
	t.Logf("BACKPRESSURE: %d fast reqs served in %v with %d slow readers parked; heap grew %d B (unbounded would be %d B) — yamux flow control holds",
		fastReqs, elapsed, slowReader, growth, unbounded)
}

// newDrainLoadRelay binds a relay to a real loopback listener (so Shutdown drains an
// actual *http.Server) with stream headroom for N concurrent in-flight streams.
func newDrainLoadRelay(t *testing.T, maxStreams int) (*server.Server, string) {
	t.Helper()
	store, err := server.NewStaticTokenStore(defaultGrants())
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain: testDomain, Tokens: store, EnablePathMode: true,
		MaxAgents: 8, MaxStreamsPerAgent: maxStreams, RevokeSweepPeriod: -1,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe(addr) }()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond); derr == nil {
			_ = c.Close()
			return srv, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay listener at %s never came up", addr)
	return nil, ""
}

// TestGracefulDrainUnderLoad drives N concurrent in-flight streams through one tunnel,
// begins a graceful Shutdown WHILE they flow, and asserts the drain contract holds
// under load:
//   - Shutdown BLOCKS while the N streams are still open (it does not abandon in-flight work);
//   - NEW connections are refused the moment the drain starts (nothing new lands on a node going away);
//   - once released, ALL N streams complete with their FULL, UN-MIXED bodies (no dropped
//     in-flight bytes, no cross-stream corruption); and
//   - Shutdown then returns cleanly.
func TestGracefulDrainUnderLoad(t *testing.T) {
	const (
		nStreams = 8
		bodySize = 64 << 10 // 64 KiB per stream
	)
	// Each request is held open at the box until released, then answered with a body of
	// a byte unique to its id — so a client can prove it got its OWN full body.
	arrived := make(chan struct{}, nStreams)
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		signalOnce(arrived)
		<-release
		fill := byte('A')
		if len(id) > 0 {
			fill = id[0]
		}
		_, _ = w.Write(bytes.Repeat([]byte{fill}, bodySize))
	}))
	defer target.Close()

	srv, addr := newDrainLoadRelay(t, 16)
	relayURL := "http://" + addr

	a := startAgent(t, relayURL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	// Launch N concurrent requests; each verifies it received exactly bodySize bytes,
	// all equal to its own fill byte (no dropped/mixed bytes).
	type res struct {
		id   int
		err  error
		code int
		body []byte
	}
	results := make(chan res, nStreams)
	for i := 0; i < nStreams; i++ {
		go func(id int) {
			fill := byte('a' + id) // distinct per stream
			resp, err := http.Get(fmt.Sprintf("%s/t/%s/stream?id=%c", relayURL, testName, fill))
			if err != nil {
				results <- res{id: id, err: err}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			results <- res{id: id, code: resp.StatusCode, body: b}
		}(i)
	}

	// Wait until all N are genuinely in flight at the box.
	for i := 0; i < nStreams; i++ {
		select {
		case <-arrived:
		case <-time.After(8 * time.Second):
			t.Fatalf("only %d/%d streams reached the box", i, nStreams)
		}
	}

	// Begin graceful shutdown WHILE all N streams are held open.
	var shutdownReturned atomic.Bool
	shutdownDone := make(chan error, 1)
	go func() {
		sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer scancel()
		err := srv.Shutdown(sctx)
		shutdownReturned.Store(true)
		shutdownDone <- err
	}()

	// Shutdown MUST block while the N streams are unfinished.
	time.Sleep(300 * time.Millisecond)
	if shutdownReturned.Load() {
		t.Fatal("Shutdown returned while N in-flight streams were still open (dropped in-flight work under load)")
	}

	// NEW work is refused during the drain: a fresh dial to the public listener fails.
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("relay accepted a NEW connection while draining under load")
	}

	// Release the box: all N held responses now stream back through the still-open tunnel.
	close(release)

	// Every stream must complete with its FULL, correct body.
	seen := make(map[int]bool)
	for i := 0; i < nStreams; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("stream %d errored across drain: %v", r.id, r.err)
			}
			if r.code != http.StatusOK {
				t.Fatalf("stream %d status = %d, want 200", r.id, r.code)
			}
			if len(r.body) != bodySize {
				t.Fatalf("stream %d dropped bytes: got %d, want %d", r.id, len(r.body), bodySize)
			}
			want := byte('a' + r.id)
			if !bytes.Equal(r.body, bytes.Repeat([]byte{want}, bodySize)) {
				t.Fatalf("stream %d body corrupted/mixed (first byte %q, want %q)", r.id, r.body[0], want)
			}
			seen[r.id] = true
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/%d streams completed after release", len(seen), nStreams)
		}
	}

	// Shutdown must now return cleanly (it was waiting on exactly those N streams).
	select {
	case err := <-shutdownDone:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after all in-flight streams completed")
	}

	// After Shutdown, no new connection is accepted.
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("relay still accepted a new connection after Shutdown")
	}
	t.Logf("DRAIN-UNDER-LOAD: %d concurrent in-flight streams (%d B each) all completed intact; new work refused; clean shutdown",
		nStreams, bodySize)
}
