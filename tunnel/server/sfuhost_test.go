// sfuhost_test.go — SFU-HOST REGISTRY (Vulos Meet SFU Phase 2) coverage.
//
// Properties proven here:
//
//  1. INERT BY DEFAULT. With EnableSFUHostRegistry off, register is 404 and
//     resolve returns available=false — the relay is unchanged.
//  2. REGISTER → RESOLVE. A token-authorized box that advertises a reachable +
//     owned endpoint is verified (via the SAME directprobe verifier) and stored;
//     resolve then hands the verified endpoint back as the join serverUrl.
//  3. VERIFICATION IS ENFORCED. A box whose endpoint fails the nonce-echo
//     ownership proof is NOT registered (502) and resolve stays available=false —
//     a box cannot advertise an SFU endpoint it does not control.
//  4. AUTH IS ENFORCED. Register with no bearer / a wrong token / a name the token
//     does not grant is refused (401), and never runs a probe.
//  5. HEARTBEAT + TTL. A heartbeat refreshes the record; an expired record is
//     pruned so resolve falls back to available=false.
//  6. DEREGISTER removes the host.
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

// sfuRelay starts a relay whose direct verifier accepts loopback httptest boxes
// (allowInsecure). enable toggles the SFU-host registry flag.
func sfuRelay(t *testing.T, enable bool) (httpBase string, s *Server) {
	t.Helper()
	store, err := NewStaticTokenStore([]Grant{{Token: "tok", Names: []string{"box1"}}})
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	s, err = New(Config{
		Domain:                "relay.test",
		Tokens:                store,
		RevokeSweepPeriod:     -1,
		EnableSFUHostRegistry: enable,
		directVerifier:        &httpDirectVerifier{allowInsecure: true},
		// Disable the control-conn rate limiter so a burst of test registers isn't 429'd.
		ControlConnRate: -1,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(s.Close)
	pub := httptest.NewServer(s.Handler())
	t.Cleanup(pub.Close)
	return pub.URL, s
}

// sfuBox starts an httptest server that echoes the relay's probe nonce (echo=true
// ⇒ ownership proven) or a wrong body (echo=false ⇒ ownership fails).
func sfuBox(t *testing.T, echo bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(wire.DirectProbePath, func(w http.ResponseWriter, r *http.Request) {
		if echo {
			_, _ = w.Write([]byte(r.Header.Get(wire.DirectProbeHeader)))
			return
		}
		_, _ = w.Write([]byte("wrong-nonce"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func sfuPost(t *testing.T, httpBase, path, token string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, httpBase+path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func sfuResolve(t *testing.T, httpBase string) sfuHostResolveResponse {
	t.Helper()
	return sfuResolveName(t, httpBase, "box1")
}

// sfuResolveName resolves scoped to a specific tunnel name (the shared-relay
// tenant key). The default sfuResolve uses "box1" (the token-granted name in
// these tests).
func sfuResolveName(t *testing.T, httpBase, name string) sfuHostResolveResponse {
	t.Helper()
	u := httpBase + sfuHostResolvePath
	if name != "" {
		u += "?name=" + name
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("resolve GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve status = %d", resp.StatusCode)
	}
	var out sfuHostResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode resolve: %v", err)
	}
	return out
}

func reg(box *httptest.Server) sfuHostRegistration {
	return sfuHostRegistration{
		HostID:       "vula:box1",
		Name:         "box1",
		Endpoint:     box.URL,
		Capabilities: sfuHostCapabilities{MaxParticipants: 50, Region: "eu"},
	}
}

func TestSFUHost_InertByDefault(t *testing.T) {
	base, _ := sfuRelay(t, false /*registry OFF*/)
	box := sfuBox(t, true)

	resp := sfuPost(t, base, sfuHostRegisterPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("register with registry OFF = %d, want 404", resp.StatusCode)
	}
	if out := sfuResolve(t, base); out.Available {
		t.Fatalf("resolve with registry OFF must be available=false, got %+v", out)
	}
}

func TestSFUHost_RegisterThenResolve(t *testing.T) {
	base, _ := sfuRelay(t, true)
	box := sfuBox(t, true /*echo nonce ⇒ owned*/)

	resp := sfuPost(t, base, sfuHostRegisterPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d, want 200", resp.StatusCode)
	}
	out := sfuResolve(t, base)
	if !out.Available {
		t.Fatal("resolve must be available after a verified register")
	}
	if out.ServerURL != box.URL {
		t.Fatalf("resolve serverUrl = %q, want the verified endpoint %q", out.ServerURL, box.URL)
	}
	if out.MaxParticipants != 50 || out.Region != "eu" {
		t.Fatalf("resolve caps not echoed: %+v", out)
	}
}

func TestSFUHost_UnownedEndpointRefused(t *testing.T) {
	base, _ := sfuRelay(t, true)
	box := sfuBox(t, false /*wrong nonce ⇒ ownership fails*/)

	resp := sfuPost(t, base, sfuHostRegisterPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("register of an unowned endpoint = %d, want 502", resp.StatusCode)
	}
	if out := sfuResolve(t, base); out.Available {
		t.Fatal("an unverified endpoint must NOT be resolvable")
	}
}

func TestSFUHost_AuthEnforced(t *testing.T) {
	base, _ := sfuRelay(t, true)
	box := sfuBox(t, true)

	// No bearer.
	resp := sfuPost(t, base, sfuHostRegisterPath, "", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register with no token = %d, want 401", resp.StatusCode)
	}
	// Wrong token.
	resp = sfuPost(t, base, sfuHostRegisterPath, "nope", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register with wrong token = %d, want 401", resp.StatusCode)
	}
	// A name the token does not grant.
	bad := reg(box)
	bad.Name = "not-my-name"
	resp = sfuPost(t, base, sfuHostRegisterPath, "tok", bad)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register for an unauthorized name = %d, want 401", resp.StatusCode)
	}
	if out := sfuResolve(t, base); out.Available {
		t.Fatal("no host should be registered after auth failures")
	}
}

func TestSFUHost_HeartbeatAndExpiry(t *testing.T) {
	base, s := sfuRelay(t, true)
	box := sfuBox(t, true)

	resp := sfuPost(t, base, sfuHostRegisterPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d", resp.StatusCode)
	}

	// Heartbeat refreshes the record.
	resp = sfuPost(t, base, sfuHostHeartbeatPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat = %d, want 200", resp.StatusCode)
	}

	// Force expiry directly on the registry, then resolve must fall back.
	s.sfuHosts.mu.Lock()
	for _, rec := range s.sfuHosts.hosts {
		rec.expires = time.Now().Add(-time.Second)
	}
	s.sfuHosts.mu.Unlock()

	if out := sfuResolve(t, base); out.Available {
		t.Fatal("an expired host must be pruned ⇒ resolve available=false")
	}
	// A heartbeat for an expired/unknown host is 404 so the box re-registers.
	resp = sfuPost(t, base, sfuHostHeartbeatPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("heartbeat for pruned host = %d, want 404", resp.StatusCode)
	}
}

// TestSFUHost_ResolveIsNameScoped proves the shared relay never hands one
// tenant's verified SFU endpoint to another tenant's clients. box1 registers a
// verified host; a resolve for box1 returns it, but a resolve for a DIFFERENT
// name — or a resolve with NO name — returns available=false. Before the fix the
// unscoped "first live host" pick leaked box1's endpoint to any caller.
func TestSFUHost_ResolveIsNameScoped(t *testing.T) {
	base, _ := sfuRelay(t, true)
	box := sfuBox(t, true /*owned*/)

	resp := sfuPost(t, base, sfuHostRegisterPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d, want 200", resp.StatusCode)
	}

	// The owner (box1) resolves ITS OWN host.
	if out := sfuResolveName(t, base, "box1"); !out.Available || out.ServerURL != box.URL {
		t.Fatalf("owner resolve should return its endpoint, got %+v", out)
	}
	// A DIFFERENT tenant name must NOT see box1's endpoint (cross-tenant leak).
	if out := sfuResolveName(t, base, "someone-else"); out.Available {
		t.Fatalf("cross-tenant resolve leaked another tenant's SFU: %+v", out)
	}
	// A resolve with NO name must fail closed (cannot scope ⇒ nothing).
	if out := sfuResolveName(t, base, ""); out.Available {
		t.Fatalf("unscoped resolve must be available=false, got %+v", out)
	}
}

func TestSFUHost_Deregister(t *testing.T) {
	base, _ := sfuRelay(t, true)
	box := sfuBox(t, true)

	resp := sfuPost(t, base, sfuHostRegisterPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d", resp.StatusCode)
	}
	resp = sfuPost(t, base, sfuHostDeregisterPath, "tok", reg(box))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deregister = %d, want 200", resp.StatusCode)
	}
	if out := sfuResolve(t, base); out.Available {
		t.Fatal("a deregistered host must not be resolvable")
	}
}
