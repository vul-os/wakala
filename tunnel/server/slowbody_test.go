package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// echoAgent registers a normal responding agent over the real wire: it accepts
// every yamux stream the relay opens, reads the full HTTP request (INCLUDING its
// body), and replies 200. It is the well-behaved counterpart used to prove the
// slow-body guard cuts the CLIENT, not the agent.
func echoAgent(t *testing.T, tsURL, name, token string) *yamux.Session {
	t.Helper()
	c, nc := dialControl(t, tsURL, token)
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	ack := registerAndReadAck(t, nc, name, token)
	if !ack.OK {
		t.Fatalf("echoAgent register rejected: %+v", ack)
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Server(nc, cfg)
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	go func() {
		for {
			st, err := sess.Accept()
			if err != nil {
				return
			}
			go func(conn io.ReadWriteCloser) {
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body) // drain the body
				resp := &http.Response{
					StatusCode: http.StatusOK,
					Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Header: make(http.Header),
					Body:   io.NopCloser(strings.NewReader("ok")),
				}
				_ = resp.Write(conn)
			}(st)
		}
	}()
	return sess
}

// waitForAgent blocks until the relay has registered exactly one agent session.
func waitForAgent(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for s.registry.count() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.registry.count() != 1 {
		t.Fatalf("agent never registered (count=%d)", s.registry.count())
	}
}

// sendSlowBodyRequest opens a raw TCP connection to the relay, writes the request
// line + headers declaring a large Content-Length, sends ONE byte of body, then
// STALLS (never sends the rest) — a slow-body/slowloris upload. It returns the HTTP
// status line the relay eventually writes back (or fails the test on read error) and
// how long that took. The connection is closed by the caller via t.Cleanup.
func sendSlowBodyRequest(t *testing.T, addr, hostHeader, path string) (status int, elapsed time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Declare a 1 MiB body but only ever send 1 byte, then stall.
	reqHead := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 1048576\r\nContent-Type: application/octet-stream\r\n\r\n", path, hostHeader)
	start := time.Now()
	if _, err := conn.Write([]byte(reqHead)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil { // one byte, then we never send the other 1048575
		t.Fatalf("write first body byte: %v", err)
	}

	// Read the response. Bound our OWN read so a genuinely wedged relay fails the test
	// (this deadline is much larger than the relay's RequestBodyTimeout).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response (relay never answered a slow body — DoS window open?): %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, time.Since(start)
}

// TestProxy_SlowBody_CutWith408 is the MEDIUM-2 regression guard. Without a
// body-ingestion deadline, a client that declares a large Content-Length and then
// dribbles/stalls the body ties up a goroutine AND a per-agent yamux stream slot
// indefinitely; MaxStreamsPerAgent such trickles brick the tunnel (503 to everyone).
// The RequestBodyTimeout guard must cut each slow body fast with 408 and FREE its
// slot, so a well-behaved request served by the same agent still succeeds afterward.
func TestProxy_SlowBody_CutWith408(t *testing.T) {
	s, ts := newAdvServer(t, Config{
		EnablePathMode:     true,
		RequestBodyTimeout: 300 * time.Millisecond,
		RequestTimeout:     10 * time.Second, // large: prove it's the BODY deadline firing, not this
		MaxStreamsPerAgent: 2,                // small: a leaked slow slot would brick the tunnel
	})
	echoAgent(t, ts.URL, "box1", "tok")
	waitForAgent(t, s)

	addr := strings.TrimPrefix(ts.URL, "http://")

	// Fire several MORE slow bodies than the stream cap, sequentially. Each must be cut
	// with 408 (not 502/503) well within the RequestTimeout, and its slot freed.
	for i := 0; i < 4; i++ {
		status, elapsed := sendSlowBodyRequest(t, addr, "box1.relay.test", "/")
		if status != http.StatusRequestTimeout {
			t.Fatalf("slow body %d: want 408, got %d", i, status)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("slow body %d: not cut promptly (took %v) — body deadline not enforced", i, elapsed)
		}
	}

	// A well-behaved request through the SAME agent still works — proving the slots
	// were freed (no 503 pile-up) and the guard only cut the slow bodies.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(ts.URL + "/t/box1/")
	if err != nil {
		t.Fatalf("normal request after slow bodies: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("normal request after slow bodies: want 200 (slots freed), got %d", resp.StatusCode)
	}
}

// TestProxy_SlowBody_DisabledKnob asserts a negative RequestBodyTimeout disables the
// guard (normalized to 0 in applyDefaults) so an operator can opt out.
func TestProxy_SlowBody_DisabledKnob(t *testing.T) {
	c := Config{RequestBodyTimeout: -1}
	c.applyDefaults()
	if c.RequestBodyTimeout != 0 {
		t.Fatalf("negative RequestBodyTimeout should disable (→0), got %v", c.RequestBodyTimeout)
	}
	var zero Config
	zero.applyDefaults()
	if zero.RequestBodyTimeout != 30*time.Second {
		t.Fatalf("default RequestBodyTimeout = %v, want 30s", zero.RequestBodyTimeout)
	}
}
