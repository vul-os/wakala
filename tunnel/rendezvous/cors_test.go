package rendezvous

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cors_test.go — the browser-access contract for the rendezvous surface.
//
// The regression these lock down: a real Chromium page could not reach a relayd
// at all. `fetch()` to /rendezvous/ice and /rendezvous/announce failed with
// "Failed to fetch" because the surface emitted no CORS headers and answered the
// preflight `OPTIONS /rendezvous/announce` with 405. That forced every app to put
// its own same-origin proxy in front of the relay, which defeats the "point any
// app at any relayd" contract.

const testOrigin = "https://app.example"

// TestPreflightAnswered: OPTIONS with Access-Control-Request-Method is answered
// 204 with the policy headers — NOT the 405 that ServeMux produces for an
// unregistered method. This is the exact call the browser makes first.
func TestPreflightAnswered(t *testing.T) {
	env := newTestEnv(t, Config{})

	for _, path := range []string{"/rendezvous/announce", "/rendezvous/signal/abc", "/rendezvous/mailbox/abc/poll"} {
		req, _ := http.NewRequest(http.MethodOptions, env.ts.URL+path, nil)
		req.Header.Set("Origin", testOrigin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: preflight status = %d, want 204", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("%s: Allow-Origin = %q, want *", path, got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
			t.Fatalf("%s: Allow-Methods = %q, want it to include POST", path, got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "content-type") {
			t.Fatalf("%s: Allow-Headers = %q, want it to include Content-Type", path, got)
		}
		if resp.Header.Get("Access-Control-Max-Age") == "" {
			t.Fatalf("%s: no Max-Age on preflight (browser re-preflights every request)", path)
		}
	}
}

// TestCredentialsNeverAllowed: the policy is "any origin, WITHOUT credentials".
// Allow-Credentials must never be emitted — it is what would turn this open
// surface into a CSRF-reachable one, and it is spec-illegal alongside "*".
func TestCredentialsNeverAllowed(t *testing.T) {
	env := newTestEnv(t, Config{})

	// Preflight.
	req, _ := http.NewRequest(http.MethodOptions, env.ts.URL+"/rendezvous/announce", nil)
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("preflight leaked Allow-Credentials = %q", got)
	}

	// Actual request.
	req2, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/rendezvous/ice", nil)
	req2.Header.Set("Origin", testOrigin)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if got := resp2.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("response leaked Allow-Credentials = %q", got)
	}
}

// TestSimpleRequestsCarryCORS: the reads a browser actually makes (/ice,
// /healthz, /resolve) come back with Allow-Origin so the page can read them.
func TestSimpleRequestsCarryCORS(t *testing.T) {
	env := newTestEnv(t, Config{})

	for _, path := range []string{"/rendezvous/ice", "/rendezvous/healthz", "/rendezvous/resolve/nosuchkey"} {
		req, _ := http.NewRequest(http.MethodGet, env.ts.URL+path, nil)
		req.Header.Set("Origin", testOrigin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("%s (status %d): Allow-Origin = %q, want *", path, resp.StatusCode, got)
		}
	}
}

// TestErrorResponsesCarryCORS: a 4xx must ALSO carry the header, otherwise the
// browser turns a perfectly informative "400 bad signature" into an opaque
// "Failed to fetch" and the app cannot tell a rejection from a dead node.
func TestErrorResponsesCarryCORS(t *testing.T) {
	env := newTestEnv(t, Config{})

	req, _ := http.NewRequest(http.MethodPost, env.ts.URL+"/rendezvous/announce", strings.NewReader("{ not json"))
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("malformed announce should be rejected, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("error response Allow-Origin = %q, want * (else the browser hides the status)", got)
	}
}

// TestNoOriginNoCORSHeaders: a plain non-browser client gets no CORS noise.
func TestNoOriginNoCORSHeaders(t *testing.T) {
	env := newTestEnv(t, Config{})

	resp, err := http.Get(env.ts.URL + "/rendezvous/ice")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q on an origin-less request, want none", got)
	}
}

// TestAllowedOriginsAllowList: when an operator narrows the policy, a listed
// origin is echoed (with Vary: Origin so a cache cannot cross-serve) and an
// unlisted one gets nothing.
func TestAllowedOriginsAllowList(t *testing.T) {
	env := newTestEnv(t, Config{AllowedOrigins: []string{testOrigin, "https://other.example"}})

	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/rendezvous/ice", nil)
	req.Header.Set("Origin", testOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Fatalf("listed origin: Allow-Origin = %q, want %q", got, testOrigin)
	}
	if got := resp.Header.Get("Vary"); !strings.Contains(got, "Origin") {
		t.Fatalf("listed origin: Vary = %q, want it to include Origin", got)
	}

	req2, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/rendezvous/ice", nil)
	req2.Header.Set("Origin", "https://evil.example")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if got := resp2.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unlisted origin: Allow-Origin = %q, want none", got)
	}
}

// TestAllowListWildcardCollapses: a literal "*" in the allow-list is the
// permissive default, not a host named "*".
func TestAllowListWildcardCollapses(t *testing.T) {
	env := newTestEnv(t, Config{AllowedOrigins: []string{"https://a.example", "*"}})

	req, _ := http.NewRequest(http.MethodGet, env.ts.URL+"/rendezvous/ice", nil)
	req.Header.Set("Origin", "https://anything.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Allow-Origin = %q, want * (a literal \"*\" entry means allow-all)", got)
	}
}

// TestPreflightDoesNotBypassSignature: the preflight is a browser handshake, not
// an authorization step. A signed-write endpoint must still reject an unsigned
// POST after a successful preflight — CORS must never become an auth bypass.
func TestPreflightDoesNotBypassSignature(t *testing.T) {
	env := newTestEnv(t, Config{})

	pre, _ := http.NewRequest(http.MethodOptions, env.ts.URL+"/rendezvous/announce", nil)
	pre.Header.Set("Origin", testOrigin)
	pre.Header.Set("Access-Control-Request-Method", "POST")
	preResp, err := http.DefaultClient.Do(pre)
	if err != nil {
		t.Fatal(err)
	}
	preResp.Body.Close()
	if preResp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight = %d, want 204", preResp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, env.ts.URL+"/rendezvous/announce",
		strings.NewReader(`{"key":"AAAA","endpoints":[],"ts":0,"nonce":"x","sig":"AAAA"}`))
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("unsigned announce accepted after preflight — CORS became an auth bypass")
	}
}

// TestOptionsWithoutPreflightHeaderIsNotHijacked: a bare OPTIONS (no
// Access-Control-Request-Method) is not a preflight and must fall through to the
// mux, so we do not silently 204 real traffic.
func TestOptionsWithoutPreflightHeaderIsNotHijacked(t *testing.T) {
	env := newTestEnv(t, Config{})

	req, _ := http.NewRequest(http.MethodOptions, env.ts.URL+"/rendezvous/ice", nil)
	req.Header.Set("Origin", testOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("bare OPTIONS was answered as a preflight")
	}
}

// TestCORSHandlerIsHTTPHandler is a compile-time-ish guard that Handler() still
// serves the routes after wrapping (the wrapper must not swallow anything).
func TestCORSHandlerIsHTTPHandler(t *testing.T) {
	svc := New(Config{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rendezvous/healthz", nil)
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz through the CORS wrapper = %d, want 200", rec.Code)
	}
}
