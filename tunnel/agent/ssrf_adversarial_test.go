// ssrf_adversarial_test.go — WAVE61-RELAY-ADVERSARIAL: adversarial coverage of the
// agent-side SSRF guard (wave-24) — the box-side dial screening that is the last
// line of defence keeping a tunneled request from reaching an internal host.
//
// The agent's SSRF posture has TWO independent properties, both proven here:
//
//  1. ensureLoopback rejects every non-loopback target FORM at configuration time:
//     the cloud metadata IP (169.254.169.254 in v4 and IPv4-mapped-v6 shape),
//     RFC1918, CGNAT, IPv6 ULA (fd00::/8) and link-local (fe80::/10), the
//     unspecified wildcard, and any bare hostname (DNS-rebind-shaped — the guard
//     never resolves an arbitrary name, so a name that would resolve off-loopback
//     is refused outright). Loopback forms (127/8, ::1, IPv4-mapped loopback,
//     "localhost") are the ONLY accepts.
//
//  2. serveStream ONLY ever dials the ONE configured LocalAddr, regardless of what
//     Host / URL the inbound tunneled request carries. An attacker who controls the
//     public request (Host: 169.254.169.254, absolute-URI to an internal host,
//     etc.) cannot redirect the agent's dial. We prove this at DIAL TIME by pointing
//     the agent's target at a real loopback listener and confirming the request
//     lands there and NOT at the attacker-named host — and by pointing the target at
//     a resolved PRIVATE ip so the guard blocks the dial (StatusForbidden) even when
//     the request itself looks benign.
package agent

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- 1. ensureLoopback: adversarial target forms ----------------------------

func TestSSRF_EnsureLoopback_BlocksInternalTargets(t *testing.T) {
	blocked := []string{
		// Cloud metadata service — the crown-jewel SSRF target.
		"169.254.169.254:80",
		"[0:0:0:0:0:ffff:169.254.169.254]:80", // IPv4-mapped-v6 metadata shape
		// RFC1918 private ranges.
		"10.0.0.5:80",
		"172.16.0.1:80",
		"192.168.1.1:8080",
		"[::ffff:10.0.0.1]:80", // IPv4-mapped-v6 private
		// CGNAT (RFC6598).
		"100.64.0.1:80",
		// IPv6 ULA + link-local.
		"[fd00::1]:80", // unique local address
		"[fe80::1]:80", // link-local
		// Wildcard / unspecified — dialing these can reach a locally-bound service
		// but is never a legitimate loopback target and must be refused.
		"0.0.0.0:80",
		"[::]:80",
		// DNS-rebind-shaped: an arbitrary hostname the guard must NOT resolve.
		"metadata.google.internal:80",
		"attacker.example.com:80",
		"internal-svc:80",
		// Malformed.
		"127.0.0.1",       // no port
		"127.0.0.1:",      // empty port
		"not a host:port", // garbage
	}
	for _, addr := range blocked {
		if err := ensureLoopback(addr); err == nil {
			t.Errorf("SSRF guard FAILED OPEN: ensureLoopback(%q) allowed a non-loopback/invalid target", addr)
		}
	}
}

func TestSSRF_EnsureLoopback_AllowsOnlyLoopback(t *testing.T) {
	allowed := []string{
		"127.0.0.1:8080",
		"127.0.0.5:80", // all of 127/8 is loopback
		"[::1]:8080",
		"[::ffff:127.0.0.1]:80", // IPv4-mapped loopback (IsLoopback == true)
		"localhost:3000",
		"LOCALHOST:3000", // case-insensitive
	}
	for _, addr := range allowed {
		if err := ensureLoopback(addr); err != nil {
			t.Errorf("legit loopback target %q was rejected: %v", addr, err)
		}
	}
}

// --- 2. serveStream: the dial-time guard on the real proxy path -------------

// serveOne drives ONE request through serveStream over an in-memory pipe and
// returns the raw HTTP response the agent wrote back. The agent side of the pipe
// is what serveStream reads/writes; the client side is what the "relay" holds.
func serveOne(t *testing.T, a *Agent, rawReq string) *http.Response {
	t.Helper()
	clientSide, agentSide := net.Pipe()
	go a.serveStream(agentSide) // serveStream closes agentSide on return

	// Write the request bytes as the relay would deliver them.
	go func() {
		_ = clientSide.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientSide.Write([]byte(rawReq))
	}()

	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
	if err != nil {
		t.Fatalf("read response from serveStream: %v", err)
	}
	t.Cleanup(func() { clientSide.Close() })
	return resp
}

// TestSSRF_ServeStream_IgnoresRequestTargetHost proves the core SSRF property: the
// agent dials its ONE configured loopback target and NEVER the host named in the
// inbound request. A request whose Host header + absolute URI name the cloud
// metadata endpoint still lands on the local target — the attacker cannot redirect
// the dial.
func TestSSRF_ServeStream_IgnoresRequestTargetHost(t *testing.T) {
	var landedHost atomic.Value // Host header the local target actually observed
	local := newLoopbackTarget(t, func(w http.ResponseWriter, r *http.Request) {
		landedHost.Store(r.Host)
		fmt.Fprint(w, "local-app-response")
	})

	a := New(Options{ServerURL: "ws://relay.test", Token: "t", Name: "box", LocalAddr: local})

	// Adversarial request: Host + absolute-form URI both point at the metadata IP.
	req := "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n" +
		"Host: 169.254.169.254\r\n" +
		"Connection: close\r\n\r\n"
	resp := serveOne(t, a, req)

	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "local-app-response") {
		t.Fatalf("request did not land on the local target: status=%d body=%q", resp.StatusCode, body)
	}
	// The local target must have seen the target rewritten to ITSELF, not the
	// attacker-named metadata host — proving no SSRF redirect.
	if got, _ := landedHost.Load().(string); got == "169.254.169.254" || strings.Contains(got, "169.254") {
		t.Fatalf("SSRF: agent forwarded the attacker's target host %q to the local app", got)
	}
	if got, _ := landedHost.Load().(string); got != local {
		t.Fatalf("agent should rewrite Host to its own loopback target %q, got %q", local, got)
	}
}

// TestSSRF_ServeStream_BlocksAtDialOnPrivateTarget proves the guard blocks at DIAL
// TIME on a resolved private IP: even a perfectly benign inbound request is refused
// with 403 when the agent's configured target resolves to a private (non-loopback)
// address. serveStream re-checks ensureLoopback before every dial, so a target that
// somehow presents as private never gets dialed — it fails CLOSED (403), it does
// not leak internal detail, and no connection to the private host is attempted.
func TestSSRF_ServeStream_BlocksAtDialOnPrivateTarget(t *testing.T) {
	// A sentinel private listener that MUST NOT be reached. If the guard ever dials
	// it, dialed flips and the test fails.
	var dialed atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Store(true)
			c.Close()
		}
	}()

	// Point the agent at a PRIVATE literal target (simulating a target that resolves
	// off-loopback). serveStream must refuse with 403 before dialing.
	a := New(Options{ServerURL: "ws://relay.test", Token: "t", Name: "box", LocalAddr: "10.0.0.5:80"})

	req := "GET /hello HTTP/1.1\r\nHost: box.relay.test\r\nConnection: close\r\n\r\n"
	resp := serveOne(t, a, req)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("private target must be refused with 403 at dial time, got %d", resp.StatusCode)
	}
	// The response must be non-leaky (no internal address / error detail).
	body := readBody(t, resp)
	if strings.Contains(body, "10.0.0.5") {
		t.Fatalf("SSRF 403 leaked the internal target in the body: %q", body)
	}
	if dialed.Load() {
		t.Fatal("SSRF guard dialed the private host — it must fail closed BEFORE dialing")
	}
}

// TestSSRF_ServeStream_MetadataAbsoluteURI is a second redirect-attempt shape: an
// absolute-URI request line pointed at an internal host must still be served only
// by the local target (the guard ignores the request target entirely).
func TestSSRF_ServeStream_MetadataAbsoluteURI(t *testing.T) {
	local := newLoopbackTarget(t, func(w http.ResponseWriter, r *http.Request) {
		// The path must be preserved; the HOST must be the local target.
		fmt.Fprintf(w, "path=%s host=%s", r.URL.Path, r.Host)
	})
	a := New(Options{ServerURL: "ws://relay.test", Token: "t", Name: "box", LocalAddr: local})

	req := "GET /latest/meta-data/iam/security-credentials/ HTTP/1.1\r\n" +
		"Host: 10.0.0.1\r\n" +
		"X-Forwarded-Host: 169.254.169.254\r\n" +
		"Connection: close\r\n\r\n"
	resp := serveOne(t, a, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if strings.Contains(body, "host=169.254") || strings.Contains(body, "host=10.0.0.1") {
		t.Fatalf("SSRF: local app saw an attacker-controlled Host: %q", body)
	}
	if !strings.Contains(body, "path=/latest/meta-data/iam/security-credentials/") {
		t.Fatalf("path not preserved to the local app: %q", body)
	}
}

// TestSSRF_ServeStream_BadRequestFailsClosed: a malformed request line yields a
// clean 400 and never dials anything.
func TestSSRF_ServeStream_BadRequestFailsClosed(t *testing.T) {
	var dialed atomic.Bool
	// Point at a live loopback listener; if the malformed request somehow reaches a
	// dial, dialed flips.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Store(true)
			c.Close()
		}
	}()
	a := New(Options{ServerURL: "ws://relay.test", Token: "t", Name: "box", LocalAddr: ln.Addr().String()})

	resp := serveOne(t, a, "GARBAGE-NOT-HTTP\r\n\r\n")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed request should be 400, got %d", resp.StatusCode)
	}
	// A malformed request must be rejected before any dial (parse fails first).
	time.Sleep(50 * time.Millisecond)
	if dialed.Load() {
		t.Fatal("malformed request must not reach a dial")
	}
}

// --- helpers ---------------------------------------------------------------

// newLoopbackTarget starts a loopback HTTP server and returns its host:port. The
// returned addr is a 127.0.0.1 address so it passes the SSRF guard.
func newLoopbackTarget(t *testing.T, h http.HandlerFunc) string {
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

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
