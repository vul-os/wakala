package tunnel_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

// scaling_bench_test.go — OPTIMAL-SIZE BENCH HARNESS (cost vs scaling).
//
// This opens MANY concurrent real tunnels (real ws control conn + yamux) against ONE
// relay instance and measures the per-tunnel resource cost — heap, goroutines — plus
// the aggregate forwarding throughput one instance sustains. The numbers feed the
// Fly-size recommendation (tunnels-per-dollar) and the saturation threshold the
// autoscaler should scale at.
//
// It is a TEST (not a Benchmark) so it can measure steady-state memory with an
// explicit GC + MemStats read at defined points, and log a sizing table. It is
// skipped under -short. Size it with RELAY_BENCH_TUNNELS (default 200) and
// RELAY_BENCH_PAYLOAD bytes (default 65536).
//
// MEASUREMENT SCOPE: both tunnel ends (agent + server) live in THIS process over
// loopback, so the measured heap/goroutines-per-tunnel cover BOTH halves. The report
// attributes the server-side fraction and applies a stated Fly-overhead factor; see
// the logged breakdown and the accompanying report.

func benchEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// TestTunnelScalingCost is the harness. Run it explicitly:
//
//	go test ./tunnel/ -run TestTunnelScalingCost -v
//	RELAY_BENCH_TUNNELS=500 go test ./tunnel/ -run TestTunnelScalingCost -v -timeout 5m
func TestTunnelScalingCost(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling cost harness skipped under -short")
	}
	nTunnels := benchEnvInt("RELAY_BENCH_TUNNELS", 100)
	payload := benchEnvInt("RELAY_BENCH_PAYLOAD", 64<<10)

	// A local target that streams `?bytes=N` back (default the payload size), so a
	// request exercises the relay's egress forwarding path with a realistic body.
	buf := make([]byte, payload)
	for i := range buf {
		buf[i] = byte('a' + i%26)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := payload
		if q := r.URL.Query().Get("bytes"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v >= 0 && v <= len(buf) {
				n = v
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(buf[:n])
	}))
	defer target.Close()

	// One grant whose token authorizes every tunnel name we will register.
	names := make([]string, nTunnels)
	for i := range names {
		names[i] = fmt.Sprintf("box%05d", i)
	}
	store, err := server.NewStaticTokenStore([]server.Grant{{Token: testToken, Names: names}})
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain:             testDomain,
		Tokens:             store,
		EnablePathMode:     true,
		MaxAgents:          nTunnels + 16,
		MaxStreamsPerAgent: 64,
		// Give the bench headroom on the request limiters (we are measuring capacity,
		// not the rate-limiter, which is validated elsewhere).
		PublicReqRate:   -1,
		GlobalReqRate:   -1,
		ControlConnRate: -1,
		GlobalConnRate:  -1,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer srv.Close()
	relay := httptest.NewServer(srv.Handler())
	defer relay.Close()

	// Baseline memory/goroutines BEFORE any tunnel exists.
	baseHeap, baseGor := memSnapshot()

	// Bring up N agents. Deterministic teardown (Stop every agent + settle) so the
	// process returns to a clean baseline — required for -count>1, where a polluted
	// baseline would otherwise underflow the per-tunnel heap delta and leftover
	// connections would error the next run's load phase.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agents := make([]*agent.Agent, nTunnels)
	defer func() {
		for _, a := range agents {
			if a != nil {
				a.Stop()
			}
		}
		time.Sleep(300 * time.Millisecond) // let goroutines/conns wind down before the next run
	}()
	local := localAddr(target.URL)
	for i := 0; i < nTunnels; i++ {
		a := agent.New(agent.Options{
			ServerURL:       relay.URL,
			Token:           testToken,
			Name:            names[i],
			LocalAddr:       local,
			ReconnectJitter: -1,
		})
		if err := a.Start(ctx); err != nil {
			t.Fatalf("agent %d start: %v", i, err)
		}
		agents[i] = a
	}

	// Wait until every tunnel is registered on the relay.
	deadline := time.Now().Add(60 * time.Second)
	for srv.AgentCount() < nTunnels && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := srv.AgentCount(); got != nTunnels {
		t.Fatalf("only %d/%d tunnels came up", got, nTunnels)
	}

	// Let idle keepalive settle, then measure steady-state IDLE cost.
	time.Sleep(500 * time.Millisecond)
	idleHeap, idleGor := memSnapshot()

	// Guard against a noisy baseline (idle < base after GC reclaims a prior run's
	// working set): clamp the delta at 0 rather than underflowing the unsigned
	// subtraction into a garbage value.
	perTunnelHeap := 0.0
	if idleHeap > baseHeap {
		perTunnelHeap = float64(idleHeap-baseHeap) / float64(nTunnels)
	}
	perTunnelGor := 0.0
	if idleGor > baseGor {
		perTunnelGor = float64(idleGor-baseGor) / float64(nTunnels)
	}

	// ── Drive bandwidth: W workers hammer random tunnels, each request pulling
	// `payload` bytes back through the relay. Measure aggregate throughput + the heap
	// under load.
	//
	// The load is bounded by a fixed REQUEST BUDGET (not a wall-clock window): the
	// agent dials its loopback target with a FRESH TCP connection per proxied request
	// (its real design — one local dial per yamux stream), so each request costs one
	// ephemeral socket that lingers in TIME_WAIT. Capping total requests keeps socket
	// churn well inside the ephemeral range so the harness is robust under -count>1.
	// The client side is pooled so ITS conns are reused (only the agent→target side
	// churns, which is inherent).
	const (
		workers     = 32
		loadBudget  = 4000            // total requests across all workers
		loadMaxWait = 8 * time.Second // safety cap if the relay stalls
	)
	var (
		reqs      atomic.Int64
		bytesGot  atomic.Int64
		errCount  atomic.Int64
		loadStop  atomic.Bool
		wg        sync.WaitGroup
		peakHeap  uint64
		peakGorou int
		peakMu    sync.Mutex
	)
	tr := &http.Transport{
		MaxIdleConns:        workers * 2,
		MaxIdleConnsPerHost: workers * 2,
		IdleConnTimeout:     30 * time.Second,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	loadStart := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			i := seed
			for !loadStop.Load() {
				if reqs.Load()+errCount.Load() >= loadBudget {
					return
				}
				name := names[i%nTunnels]
				i += workers
				resp, err := client.Get(relay.URL + "/t/" + name + "/?bytes=" + strconv.Itoa(payload))
				if err != nil {
					errCount.Add(1)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					errCount.Add(1)
					continue
				}
				reqs.Add(1)
				bytesGot.Add(n)
			}
		}(w)
	}
	// Stop the load once the request budget is met (or the safety cap elapses).
	go func() {
		deadline := time.Now().Add(loadMaxWait)
		for time.Now().Before(deadline) {
			if reqs.Load()+errCount.Load() >= loadBudget {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		loadStop.Store(true)
	}()
	// Sample peak memory mid-load.
	go func() {
		for !loadStop.Load() {
			h, g := memSnapshot()
			peakMu.Lock()
			if h > peakHeap {
				peakHeap = h
			}
			if g > peakGorou {
				peakGorou = g
			}
			peakMu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}()
	wg.Wait() // workers exit when the request budget is met (or the safety cap fires)
	loadStop.Store(true)
	elapsed := time.Since(loadStart).Seconds()

	totReq := reqs.Load()
	totBytes := bytesGot.Load()
	reqPerSec := float64(totReq) / elapsed
	mbPerSec := float64(totBytes) / elapsed / (1 << 20)

	// ── Report ────────────────────────────────────────────────────────────────
	t.Logf("=== RELAY SCALING / PER-TUNNEL COST (N=%d tunnels, payload=%d B) ===", nTunnels, payload)
	t.Logf("baseline:   heap=%s goroutines=%d", human(baseHeap), baseGor)
	t.Logf("idle (N up): heap=%s goroutines=%d", human(idleHeap), idleGor)
	t.Logf("PER-TUNNEL (both ends, loopback): heap=%.1f KiB  goroutines=%.2f",
		perTunnelHeap/1024, perTunnelGor)
	t.Logf("under load: peakHeap=%s peakGoroutines=%d", human(peakHeap), peakGorou)
	t.Logf("throughput: %.0f req/s  %.1f MiB/s  (%d reqs, %d errs, %.1fs, %d workers)",
		reqPerSec, mbPerSec, totReq, errCount.Load(), elapsed, workers)

	// Extrapolate the IDLE tunnel ceiling for each candidate Fly size, reserving a
	// fixed base RSS for the Go runtime + relay working set and assuming the measured
	// per-tunnel heap is ~representative (the report widens it with a safety factor
	// and a server-only fraction). This is a guide the report interprets, not a hard
	// assertion.
	const runtimeReserveMiB = 96.0 // Go runtime + relay working set + TCP/TLS slack
	for _, size := range []struct {
		name   string
		ramMiB float64
	}{
		{"shared-cpu-1x-256MB", 256},
		{"shared-cpu-1x-512MB", 512},
		{"shared-cpu-1x-1GB", 1024},
		{"shared-cpu-2x-1GB", 1024},
	} {
		usable := (size.ramMiB - runtimeReserveMiB) * (1 << 20)
		if usable < 0 {
			usable = 0
		}
		// Use max(measured, a conservative floor) so a tiny loopback measurement does
		// not over-promise; the report justifies the floor.
		perTun := perTunnelHeap
		if perTun < 24*1024 {
			perTun = 24 * 1024 // conservative floor: ~24 KiB/tunnel server-side
		}
		ceiling := int(usable / perTun)
		t.Logf("  Fly %-22s ~%d idle tunnels (@%.0f KiB/tunnel, %.0f MiB reserve)",
			size.name, ceiling, perTun/1024, runtimeReserveMiB)
	}

	// Sanity guards so the harness fails loudly if the relay regresses badly, without
	// being brittle about exact numbers on shared CI hardware.
	if perTunnelHeap > 512*1024 {
		t.Fatalf("per-tunnel heap %.0f KiB is implausibly high (>512 KiB): a leak/regression?", perTunnelHeap/1024)
	}
	if totReq == 0 {
		t.Fatal("no successful requests under load — forwarding path broken")
	}
	if errCount.Load() > totReq/10 {
		t.Fatalf("too many errors under load: %d errs vs %d ok", errCount.Load(), totReq)
	}
}

// memSnapshot forces a GC and returns (HeapInuse bytes, live goroutines).
func memSnapshot() (uint64, int) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse, runtime.NumGoroutine()
}

func human(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGT"[exp])
}
