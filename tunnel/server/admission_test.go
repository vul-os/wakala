package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vul-os/vulos-relay/tunnel/autoscale"
)

// admission_test.go — CONNECTION-FLOOD ADMISSION CONTROL tests: per-IP + per-account
// NEW-connection rate limits, the global connection cap + graceful shed at capacity,
// saturation shedding, and the memory-bounded backpressure under a distinct-key
// flood (no unbounded growth / OOM).

// newAdmissionServer builds a server with an allow-all token store and explicit
// admission knobs, sweeps/samplers off, for deterministic admission tests.
func newAdmissionServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	store, err := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	cfg.Domain = "relay.test"
	cfg.Tokens = store
	cfg.RevokeSweepPeriod = -1
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// bearerReq builds a control-connection request from ip with a bearer token set.
func bearerReq(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://relay.test"+wireControlPath, nil)
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Authorization", "Bearer t")
	return r
}

// TestAdmission_PerIPConnectRateLimit: a single source IP is throttled on NEW
// control connections BEFORE any upgrade — the cheap per-IP guard.
func TestAdmission_PerIPConnectRateLimit(t *testing.T) {
	s := newAdmissionServer(t, Config{
		ControlConnRate:    1, // slow refill
		ControlConnBurst:   2, // 2 through, then 429
		GlobalConnRate:     -1,
		ConnPerAccountRate: -1,
	})
	r := bearerReq("203.0.113.7")
	if v := s.admitControlConn(r); !v.ok {
		t.Fatalf("1st connect should be admitted: %+v", v)
	}
	if v := s.admitControlConn(r); !v.ok {
		t.Fatalf("2nd connect should be admitted: %+v", v)
	}
	v := s.admitControlConn(r)
	if v.ok {
		t.Fatal("3rd connect past the per-IP burst should be rejected")
	}
	if v.httpStatus != http.StatusTooManyRequests || v.surface != limitControl {
		t.Fatalf("per-IP reject verdict = %+v, want 429 surface=control", v)
	}
	// A DIFFERENT source IP has its own bucket and is admitted.
	if v := s.admitControlConn(bearerReq("203.0.113.8")); !v.ok {
		t.Fatalf("a distinct IP must not share the throttled bucket: %+v", v)
	}
}

// TestAdmission_GlobalConnectRateLimit: the aggregate NEW-connection limiter sheds a
// DISTRIBUTED flood (many IPs each under the per-IP limit) on the cheap pre-upgrade
// path.
func TestAdmission_GlobalConnectRateLimit(t *testing.T) {
	s := newAdmissionServer(t, Config{
		ControlConnRate:    -1, // isolate the global limiter
		GlobalConnRate:     1,
		GlobalConnBurst:    2,
		ConnPerAccountRate: -1,
	})
	// Each call uses a DISTINCT IP, so only the aggregate limiter can reject.
	if v := s.admitControlConn(bearerReq("198.51.100.1")); !v.ok {
		t.Fatalf("1st admitted: %+v", v)
	}
	if v := s.admitControlConn(bearerReq("198.51.100.2")); !v.ok {
		t.Fatalf("2nd admitted: %+v", v)
	}
	v := s.admitControlConn(bearerReq("198.51.100.3"))
	if v.ok {
		t.Fatal("3rd connect past the global burst should be rejected even from a fresh IP")
	}
	if v.httpStatus != http.StatusTooManyRequests || v.surface != limitGlobalConn {
		t.Fatalf("global reject verdict = %+v, want 429 surface=global_conn", v)
	}
}

// TestAdmission_MissingBearerRejectedPreUpgrade: an anonymous connect is refused
// before the upgrade so it costs nothing.
func TestAdmission_MissingBearerRejectedPreUpgrade(t *testing.T) {
	s := newAdmissionServer(t, Config{})
	r := httptest.NewRequest(http.MethodGet, "http://relay.test"+wireControlPath, nil)
	r.RemoteAddr = "203.0.113.9:5000"
	v := s.admitControlConn(r)
	if v.ok || v.httpStatus != http.StatusUnauthorized || v.reason != authFailNoBearer {
		t.Fatalf("missing-bearer verdict = %+v, want 401 no_bearer", v)
	}
}

// TestAdmission_HardCapGracefulShed: at the hard MaxAgents cap the PoP SHEDS new
// connects with a retryable 503 ("try another PoP") on the cheap path.
func TestAdmission_HardCapGracefulShed(t *testing.T) {
	s := newAdmissionServer(t, Config{MaxAgents: 2})
	// Fill the registry to the hard cap.
	for i := 0; i < 2; i++ {
		if _, _, err := s.registry.add(&session{name: fmt.Sprintf("box%d", i)}); err != nil {
			t.Fatalf("seed session %d: %v", i, err)
		}
	}
	if !s.atHardCap() {
		t.Fatal("registry should be at the hard cap")
	}
	v := s.admitControlConn(bearerReq("203.0.113.20"))
	if v.ok {
		t.Fatal("a connect at the hard cap must be shed")
	}
	if v.httpStatus != http.StatusServiceUnavailable || v.reason != authFailCapacity {
		t.Fatalf("capacity shed verdict = %+v, want 503 at_capacity", v)
	}
	if v.retryAfter == "" {
		t.Fatal("a capacity shed should carry a Retry-After hint")
	}
}

// TestAdmission_SaturationShed: at/above the shedding threshold the PoP refuses NEW
// tunnels (retryable) while keeping live ones up. Below it, connects are admitted.
func TestAdmission_SaturationShed(t *testing.T) {
	s := newAdmissionServer(t, Config{
		SoftCapacity:           autoscale.Capacity{MaxStreams: 10},
		SaturationSamplePeriod: -1, // disable the sampler; set the gauge by hand
		SheddingThreshold:      0.9,
	})
	// Below threshold → admitted.
	s.metrics.setSaturation(0.5)
	if v := s.admitControlConn(bearerReq("203.0.113.30")); !v.ok {
		t.Fatalf("below the shed threshold a connect must be admitted: %+v", v)
	}
	// At/above threshold → shed (retryable 503).
	s.metrics.setSaturation(0.95)
	v := s.admitControlConn(bearerReq("203.0.113.31"))
	if v.ok || v.httpStatus != http.StatusServiceUnavailable || v.reason != authFailSaturation {
		t.Fatalf("saturation shed verdict = %+v, want 503 saturation_shed", v)
	}
}

// TestAdmission_SheddingDisabled: a negative threshold disables saturation shedding
// even at full saturation (the hard cap still protects the node).
func TestAdmission_SheddingDisabled(t *testing.T) {
	s := newAdmissionServer(t, Config{
		SoftCapacity:           autoscale.Capacity{MaxStreams: 10},
		SaturationSamplePeriod: -1,
		SheddingThreshold:      -1, // disabled
	})
	s.metrics.setSaturation(5.0) // wildly over capacity
	if s.saturationShed() {
		t.Fatal("saturation shedding must stay off when the threshold is disabled")
	}
	if v := s.admitControlConn(bearerReq("203.0.113.40")); !v.ok {
		t.Fatalf("with shedding disabled the connect must be admitted: %+v", v)
	}
}

// TestAdmission_DrainingShed: a draining PoP sheds new connects pre-upgrade.
func TestAdmission_DrainingShed(t *testing.T) {
	s := newAdmissionServer(t, Config{})
	s.draining.Store(true)
	v := s.admitControlConn(bearerReq("203.0.113.50"))
	if v.ok || v.httpStatus != http.StatusServiceUnavailable || v.reason != authFailDraining {
		t.Fatalf("draining shed verdict = %+v, want 503 draining", v)
	}
}

// TestAdmission_PerAccountConnectRateLimit: a single ACCOUNT's NEW-connection burst
// is bounded; an empty (unbilled) account is never throttled.
func TestAdmission_PerAccountConnectRateLimit(t *testing.T) {
	s := newAdmissionServer(t, Config{
		ConnPerAccountRate:  1,
		ConnPerAccountBurst: 3,
	})
	for i := 0; i < 3; i++ {
		if !s.admitAccountConnect("acct-A") {
			t.Fatalf("connect %d within the account burst should be admitted", i)
		}
	}
	if s.admitAccountConnect("acct-A") {
		t.Fatal("4th connect past the per-account burst should be rejected")
	}
	// A different account has its own bucket.
	if !s.admitAccountConnect("acct-B") {
		t.Fatal("a distinct account must not share the throttled bucket")
	}
	// Unbilled (empty) accounts are never keyed/throttled.
	for i := 0; i < 100; i++ {
		if !s.admitAccountConnect("") {
			t.Fatal("an empty (unbilled) account must never be throttled")
		}
	}
}

// TestAdmission_FloodBoundedMemory is the BACKPRESSURE / no-OOM guard: a flood of
// connects from a huge number of DISTINCT source IPs must NOT grow the limiter's
// bucket map without bound — the per-key cap evicts/refuses past the ceiling — and
// the overwhelming majority of the flood must be shed (the global limiter kicks in),
// proving the admission path cannot be turned into an unbounded-memory amplifier.
func TestAdmission_FloodBoundedMemory(t *testing.T) {
	const maxKeys = 500
	s := newAdmissionServer(t, Config{
		ControlConnRate:  1000,
		ControlConnBurst: 1,
		GlobalConnRate:   50, // aggregate cap: the flood is mostly shed
		GlobalConnBurst:  100,
		RateLimitMaxKeys: maxKeys,
	})

	const flood = 50_000
	admitted := 0
	for i := 0; i < flood; i++ {
		// A fresh source IP every time — the worst case for per-key memory growth.
		r := bearerReq(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
		if v := s.admitControlConn(r); v.ok {
			admitted++
		}
	}

	// (a) MEMORY IS BOUNDED: the per-IP bucket map never exceeds the configured cap
	// despite 50k distinct keys hammering it.
	if got := len(s.ctrlLimiter.buckets); got > maxKeys {
		t.Fatalf("ctrl limiter grew to %d buckets, exceeding the %d cap (unbounded growth)", got, maxKeys)
	}
	// (b) THE FLOOD IS SHED: only a small fraction is ever admitted (the global
	// aggregate limiter sheds the rest). If nearly everything were admitted the node
	// would have no backpressure at all.
	if admitted > flood/100 {
		t.Fatalf("admitted %d/%d — flood was not shed (no backpressure)", admitted, flood)
	}
}

// TestAdmission_EndToEndFloodNoUpgrade drives the REAL public handler with a burst of
// unauthenticated + rate-limited control-connection attempts and asserts every one is
// rejected with a fast HTTP status (never a 101 upgrade), so a flood is shed on the
// cheap path without spending a WS upgrade / yamux session.
func TestAdmission_EndToEndFloodNoUpgrade(t *testing.T) {
	s := newAdmissionServer(t, Config{
		ControlConnRate:  1,
		ControlConnBurst: 2,
		GlobalConnRate:   1,
		GlobalConnBurst:  2,
	})
	h := s.Handler()

	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "http://relay.test"+wireControlPath, nil)
			r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i%250)
			// Half present a bearer, half are anonymous — both must be shed cheaply.
			if i%2 == 0 {
				r.Header.Set("Authorization", "Bearer t")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			mu.Lock()
			statuses[w.Code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Not a single attempt should have upgraded (101) — the whole flood is rejected
	// on the cheap path with 401/429/503.
	if statuses[http.StatusSwitchingProtocols] != 0 {
		t.Fatalf("a flood attempt upgraded the connection (%d× 101) — not shed cheaply", statuses[http.StatusSwitchingProtocols])
	}
	// Acceptable outcomes: the flood is either SHED cheaply (401 anonymous / 429
	// rate-limited / 503 capacity-drain-saturation), or — for the handful within the
	// connection burst that pass admission — rejected at the real WS handshake with
	// 426 (the httptest requests are not genuine upgrades). The invariant is that NONE
	// upgraded (no 101) and nothing spent a tunnel.
	total := 0
	admittedToHandshake := 0
	for code, n := range statuses {
		switch code {
		case http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusServiceUnavailable:
			// shed on the cheap path
		case http.StatusUpgradeRequired:
			admittedToHandshake += n // passed admission, failed the (fake) WS handshake
		default:
			t.Fatalf("unexpected status %d (%d×) under flood; want only 401/429/503/426", code, n)
		}
		total += n
	}
	if total != 200 {
		t.Fatalf("accounted for %d/200 responses", total)
	}
	// The connection burst is small, so only a tiny fraction can reach the handshake;
	// the flood must be overwhelmingly shed.
	if admittedToHandshake > 20 {
		t.Fatalf("%d/200 attempts passed admission — flood not shed hard enough", admittedToHandshake)
	}
}

// TestAdmission_LimitsDisabledForSelfHost: negative rates disable every admission
// limiter so a self-hosted relay is byte-for-byte unchanged (allow all).
func TestAdmission_LimitsDisabledForSelfHost(t *testing.T) {
	s := newAdmissionServer(t, Config{
		ControlConnRate:    -1,
		GlobalConnRate:     -1,
		ConnPerAccountRate: -1,
	})
	if s.ctrlLimiter != nil || s.globalConnLimiter != nil || s.acctConnLimiter != nil {
		t.Fatal("negative rates must yield nil (disabled) limiters")
	}
	for i := 0; i < 1000; i++ {
		if v := s.admitControlConn(bearerReq("203.0.113.99")); !v.ok {
			t.Fatalf("disabled limiters must admit everything (call %d)", i)
		}
		if !s.admitAccountConnect("acct") {
			t.Fatalf("disabled account limiter must admit everything (call %d)", i)
		}
	}
}
