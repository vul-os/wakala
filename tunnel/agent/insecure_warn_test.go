package agent

import (
	"strings"
	"testing"
)

// TestWarnInsecureOnce_AppendsLoudLog asserts that enabling InsecureSkipVerify emits
// a loud, security-relevant warning into the agent's log (surfaced via Snapshot), so
// a library embedder cannot disable TLS verification of the token-bearing control
// connection silently.
func TestWarnInsecureOnce_AppendsLoudLog(t *testing.T) {
	a := New(Options{
		ServerURL: "wss://relay.example.com", Token: "t", Name: "box1",
		LocalAddr: "127.0.0.1:8080", InsecureSkipVerify: true,
	})
	a.warnInsecureOnce()

	log := a.Snapshot().Log
	if len(log) == 0 {
		t.Fatal("expected a warning log line, got none")
	}
	joined := strings.ToLower(strings.Join(log, "\n"))
	if !strings.Contains(joined, "insecureskipverify") || !strings.Contains(joined, "disabled") {
		t.Fatalf("warning log missing the security wording, got: %q", joined)
	}
	if !strings.Contains(joined, "token") {
		t.Fatalf("warning must call out the token-theft risk, got: %q", joined)
	}
}
