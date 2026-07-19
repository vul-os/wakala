package server

// rendezvous_mount_test.go — the relay-integration contract for the RENDEZVOUS
// role: when enabled it is served on the relay's APEX host, is a no-op when
// disabled, and NEVER shadows a tunnel subdomain's own paths (a box reached at
// <name>.<domain> keeps full control of /rendezvous/*).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRendezvousTestServer(t *testing.T, enable bool) *Server {
	t.Helper()
	store, err := NewStaticTokenStore([]Grant{{Token: "tok", Names: []string{"box1"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Domain:           "relay.example.com",
		Tokens:           store,
		EnableRendezvous: enable,
		// Disable the internet-facing rate limiters so the test is deterministic.
		ControlConnRate: -1, PublicReqRate: -1, GlobalReqRate: -1,
		GlobalConnRate: -1, ConnPerAccountRate: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// TestRendezvousDisabledByDefault: with EnableRendezvous=false a /rendezvous path on
// the apex host is just an unknown route (404 no-such-tunnel), i.e. the plain
// reverse-tunnel relay is unchanged.
func TestRendezvousDisabledByDefault(t *testing.T) {
	srv := newRendezvousTestServer(t, false)
	if srv.rendezvous != nil {
		t.Fatal("rendezvous service built despite EnableRendezvous=false")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/rendezvous/ice", nil)
	req.Host = "relay.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled rendezvous should 404, got %d", resp.StatusCode)
	}
}

// TestRendezvousServedOnApex: with the role enabled, GET /rendezvous/ice on the apex
// host is answered by the rendezvous service.
func TestRendezvousServedOnApex(t *testing.T) {
	srv := newRendezvousTestServer(t, true)
	if srv.rendezvous == nil {
		t.Fatal("rendezvous service not built despite EnableRendezvous=true")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/rendezvous/ice", nil)
	req.Host = "relay.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apex rendezvous ICE should 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected JSON, got %q", ct)
	}
}

// TestRendezvousCORSOnApexOnly is the containment contract for the browser CORS
// policy added to the rendezvous role (tunnel/rendezvous/cors.go).
//
// The rendezvous surface is deliberately cross-origin reachable: its writes are
// Ed25519-signed and it never accepts credentials, so origin is not its security
// boundary and blocking browsers only broke the honest case. The TUNNEL surface is
// the opposite — it proxies a box's own app, which DOES carry ambient authority
// (cookies, sessions). It must never emit CORS headers, or a hostile page could
// read a tunneled app's authenticated responses.
func TestRendezvousCORSOnApexOnly(t *testing.T) {
	srv := newRendezvousTestServer(t, true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Apex rendezvous path: CORS present.
	req, _ := http.NewRequest("GET", ts.URL+"/rendezvous/ice", nil)
	req.Host = "relay.example.com"
	req.Header.Set("Origin", "https://app.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("apex rendezvous Allow-Origin = %q, want * (browsers cannot reach it otherwise)", got)
	}

	// Tunnel subdomain, ANY path: no CORS, ever.
	for _, path := range []string{"/", "/rendezvous/ice", "/api/secret"} {
		r2, _ := http.NewRequest("GET", ts.URL+path, nil)
		r2.Host = "box1.relay.example.com"
		r2.Header.Set("Origin", "https://evil.example")
		resp2, err := http.DefaultClient.Do(r2)
		if err != nil {
			t.Fatal(err)
		}
		resp2.Body.Close()
		if got := resp2.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("tunnel path %s leaked Allow-Origin = %q — CORS escaped the rendezvous surface", path, got)
		}
	}

	// Apex non-rendezvous path: also no CORS (it is not part of the substrate).
	r3, _ := http.NewRequest("GET", ts.URL+"/some/other/path", nil)
	r3.Host = "relay.example.com"
	r3.Header.Set("Origin", "https://evil.example")
	resp3, err := http.DefaultClient.Do(r3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if got := resp3.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("apex non-rendezvous path leaked Allow-Origin = %q", got)
	}
}

// TestRendezvousPreflightOnApex: the preflight a browser sends before a signed
// POST is answered 204 by the relay-mounted service (not the 405 that blocked it).
func TestRendezvousPreflightOnApex(t *testing.T) {
	srv := newRendezvousTestServer(t, true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL+"/rendezvous/announce", nil)
	req.Host = "relay.example.com"
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("apex announce preflight = %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("preflight through the relay mount carried no Allow-Methods")
	}
}

// TestRendezvousNotShadowingTunnelSubdomain: a request to <name>.<domain>/rendezvous/ice
// must NOT be captured by the rendezvous service — it targets the box's tunnel, so it
// routes to tunnel logic (here: 502 offline, since no agent is connected), proving the
// box keeps control of its own /rendezvous/* paths.
func TestRendezvousNotShadowingTunnelSubdomain(t *testing.T) {
	srv := newRendezvousTestServer(t, true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/rendezvous/ice", nil)
	req.Host = "box1.relay.example.com" // a tunnel subdomain
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// box1 is a known name but has no live agent → tunnel-offline (502), NOT the
	// rendezvous 200. The key assertion is that it was NOT handled by rendezvous.
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("rendezvous wrongly shadowed a tunnel subdomain's path (got 200)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected tunnel-offline 502 for box1 subdomain, got %d", resp.StatusCode)
	}
}
