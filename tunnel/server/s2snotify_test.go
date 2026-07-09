package server

// s2snotify_test.go — CROSS-INSTANCE NOTIFICATION FORWARDING (MINST-06 / S2S).
//
// Properties proven here:
//
//  1. FORWARD. A token-authorized origin box POSTs /api/s2s/notify {target,
//     sender, notification}; the relay forwards the BARE notification to the
//     target box over its EXISTING tunnel, hitting /api/notify/receive, and
//     returns 202.
//  2. AUTH IS ENFORCED (fail-closed). No bearer / wrong token / a sender name the
//     token does not grant is refused (401) and nothing is forwarded.
//  3. CROSS-TENANT GUARD (fail-closed). An origin box on account A cannot inject a
//     notification into account B's tunnel (403), even though both are live and
//     the caller holds a valid token.
//  4. BEST-EFFORT / NON-FATAL. An unknown/offline target is a clean non-2xx the
//     origin box logs and ignores — it never panics or wedges a tunnel.
//  5. SSRF-SAFE BY CONSTRUCTION. `target` only ever selects among live tunnels by
//     name; the forwarded path is a fixed constant. There is no attacker-supplied
//     URL for the relay to dial (implicit in the design; covered by 1–4).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// notifyBox connects a target-box agent to the relay under `name`/`token` and
// serves a tiny HTTP handler over every accepted yamux stream. It records the
// paths the relay forwarded to (so a test can assert /api/notify/receive was
// hit) and the raw request bodies. Returns a func to fetch what it received.
func notifyBox(t *testing.T, tsURL, name, headerToken, frameToken string) (received func() (paths []string, bodies []string)) {
	t.Helper()
	c, nc := dialControl(t, tsURL, headerToken)
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "") })
	ack := registerAndReadAck(t, nc, name, frameToken)
	if !ack.OK {
		t.Fatalf("notifyBox %q register rejected: %+v", name, ack)
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Server(nc, cfg)
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	var (
		mu        sync.Mutex
		gotPaths  []string
		gotBodies []string
	)
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
				body, _ := io.ReadAll(req.Body)
				mu.Lock()
				gotPaths = append(gotPaths, req.URL.Path)
				gotBodies = append(gotBodies, string(body))
				mu.Unlock()
				resp := &http.Response{
					StatusCode: http.StatusOK,
					Proto:      "HTTP/1.1",
					ProtoMajor: 1, ProtoMinor: 1,
					Header: make(http.Header),
					Body:   io.NopCloser(bytes.NewReader([]byte(`{"status":"delivered"}`))),
				}
				_ = resp.Write(conn)
			}(st)
		}
	}()
	return func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		p := append([]string(nil), gotPaths...)
		b := append([]string(nil), gotBodies...)
		return p, b
	}
}

// postS2SNotify POSTs an envelope to /api/s2s/notify with an optional bearer.
func postS2SNotify(t *testing.T, tsURL, bearer string, env s2sNotifyEnvelope) *http.Response {
	t.Helper()
	body, _ := json.Marshal(env)
	req, err := http.NewRequest(http.MethodPost, tsURL+s2sNotifyPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post s2s notify: %v", err)
	}
	return resp
}

// waitForAgents blocks until the relay has n live agent sessions (or fails).
func waitForAgents(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for s.registry.count() != n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.registry.count() != n {
		t.Fatalf("want %d agents, got %d", n, s.registry.count())
	}
}

func TestS2SNotify_ForwardsBareNotificationOverTunnel(t *testing.T) {
	s, ts := newAdvServer(t, Config{ControlConnRate: -1})
	recv := notifyBox(t, ts.URL, "box1", "tok", "tok")
	waitForAgents(t, s, 1)

	resp := postS2SNotify(t, ts.URL, "tok", s2sNotifyEnvelope{
		TargetULID:   "01HTARGET",
		Target:       "box1",
		Sender:       "box1", // single box may notify itself; account matches
		Notification: json.RawMessage(`{"id":"n-1","title":"Hi"}`),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 202; body: %s", resp.StatusCode, b)
	}

	// Give the box goroutine a moment to record the forwarded request.
	deadline := time.Now().Add(2 * time.Second)
	var paths, bodies []string
	for time.Now().Before(deadline) {
		paths, bodies = recv()
		if len(paths) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(paths) == 0 {
		t.Fatal("target box never received a forwarded request")
	}
	if paths[0] != s2sNotifyForwardPath {
		t.Errorf("forwarded path: got %q want %q", paths[0], s2sNotifyForwardPath)
	}
	// The forwarded body must be the BARE notification, not the relay envelope.
	if bodies[0] != `{"id":"n-1","title":"Hi"}` {
		t.Errorf("forwarded body: got %q want the bare notification", bodies[0])
	}
}

func TestS2SNotify_NoBearerRefused(t *testing.T) {
	s, ts := newAdvServer(t, Config{ControlConnRate: -1})
	_ = notifyBox(t, ts.URL, "box1", "tok", "tok")
	waitForAgents(t, s, 1)

	resp := postS2SNotify(t, ts.URL, "", s2sNotifyEnvelope{
		Target:       "box1",
		Sender:       "box1",
		Notification: json.RawMessage(`{"id":"n-1"}`),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-bearer: got %d want 401", resp.StatusCode)
	}
}

func TestS2SNotify_WrongTokenRefused(t *testing.T) {
	s, ts := newAdvServer(t, Config{ControlConnRate: -1})
	_ = notifyBox(t, ts.URL, "box1", "tok", "tok")
	waitForAgents(t, s, 1)

	resp := postS2SNotify(t, ts.URL, "not-the-token", s2sNotifyEnvelope{
		Target:       "box1",
		Sender:       "box1",
		Notification: json.RawMessage(`{"id":"n-1"}`),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-token: got %d want 401", resp.StatusCode)
	}
}

func TestS2SNotify_SenderNameNotGrantedRefused(t *testing.T) {
	// The token grants only "box1"; a sender claiming "box2" is refused.
	s, ts := newAdvServer(t, Config{ControlConnRate: -1})
	_ = notifyBox(t, ts.URL, "box1", "tok", "tok")
	waitForAgents(t, s, 1)

	resp := postS2SNotify(t, ts.URL, "tok", s2sNotifyEnvelope{
		Target:       "box1",
		Sender:       "box2", // not in the grant
		Notification: json.RawMessage(`{"id":"n-1"}`),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ungranted-sender: got %d want 401", resp.StatusCode)
	}
}

func TestS2SNotify_UnknownTargetBestEffort(t *testing.T) {
	s, ts := newAdvServer(t, Config{ControlConnRate: -1})
	_ = notifyBox(t, ts.URL, "box1", "tok", "tok")
	waitForAgents(t, s, 1)

	resp := postS2SNotify(t, ts.URL, "tok", s2sNotifyEnvelope{
		Target:       "ghost", // no such live tunnel
		Sender:       "box1",
		Notification: json.RawMessage(`{"id":"n-1"}`),
	})
	defer resp.Body.Close()
	// Best-effort: a clean non-2xx (502) the origin box logs and ignores.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unknown-target: got %d want 502", resp.StatusCode)
	}
}

func TestS2SNotify_CrossAccountRefused(t *testing.T) {
	// Two accounts, each with its own tunnel name. Account A's token authorizes
	// "boxa" (account "acct-a"); the target "boxb" belongs to "acct-b". A valid
	// A-token must NOT be able to push into B's tunnel.
	st, err := NewStaticTokenStore([]Grant{
		{Token: "tok-a", Names: []string{"boxa"}, AccountID: "acct-a"},
		{Token: "tok-b", Names: []string{"boxb"}, AccountID: "acct-b"},
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, ts := newAdvServer(t, Config{Tokens: st, ControlConnRate: -1})
	_ = notifyBox(t, ts.URL, "boxa", "tok-a", "tok-a")
	_ = notifyBox(t, ts.URL, "boxb", "tok-b", "tok-b")
	waitForAgents(t, s, 2)

	// Account A (valid token, valid own sender name) targets account B's tunnel.
	resp := postS2SNotify(t, ts.URL, "tok-a", s2sNotifyEnvelope{
		Target:       "boxb", // belongs to acct-b
		Sender:       "boxa", // authorized for acct-a
		Notification: json.RawMessage(`{"id":"leak"}`),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-account: got %d want 403", resp.StatusCode)
	}
}

func TestS2SNotify_SameAccountDifferentTunnelForwards(t *testing.T) {
	// One account owns TWO tunnels (multi-device). A notification from boxa to boxb
	// under the SAME account is forwarded (the real multi-instance case).
	st, err := NewStaticTokenStore([]Grant{
		{Token: "tok", Names: []string{"boxa", "boxb"}, AccountID: "acct-1"},
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, ts := newAdvServer(t, Config{Tokens: st, ControlConnRate: -1})
	_ = notifyBox(t, ts.URL, "boxa", "tok", "tok")
	recvB := notifyBox(t, ts.URL, "boxb", "tok", "tok")
	waitForAgents(t, s, 2)

	resp := postS2SNotify(t, ts.URL, "tok", s2sNotifyEnvelope{
		Target:       "boxb",
		Sender:       "boxa",
		Notification: json.RawMessage(`{"id":"cross-device"}`),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("same-account cross-tunnel: got %d want 202; body: %s", resp.StatusCode, b)
	}

	deadline := time.Now().Add(2 * time.Second)
	var paths []string
	for time.Now().Before(deadline) {
		paths, _ = recvB()
		if len(paths) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(paths) == 0 || paths[0] != s2sNotifyForwardPath {
		t.Fatalf("boxb did not receive the forwarded notification (paths=%v)", paths)
	}
}

func TestS2SNotify_MissingTargetOrNotificationBadRequest(t *testing.T) {
	s, ts := newAdvServer(t, Config{ControlConnRate: -1})
	_ = notifyBox(t, ts.URL, "box1", "tok", "tok")
	waitForAgents(t, s, 1)

	// Missing target.
	resp := postS2SNotify(t, ts.URL, "tok", s2sNotifyEnvelope{
		Sender:       "box1",
		Notification: json.RawMessage(`{"id":"n"}`),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing target: got %d want 400", resp.StatusCode)
	}

	// Missing notification.
	resp2 := postS2SNotify(t, ts.URL, "tok", s2sNotifyEnvelope{
		Target: "box1",
		Sender: "box1",
	})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing notification: got %d want 400", resp2.StatusCode)
	}
}
