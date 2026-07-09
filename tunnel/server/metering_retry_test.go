package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMeter_ResponseLostDoesNotDoubleBill is the regression guard for the metering
// idempotency bug: the flush used to drain deltas, post them under a report_id, and
// on ANY error restore the deltas into the pending pool — so the NEXT flush re-sent
// them under a FRESH report_id. When the CP had actually APPLIED the batch but its
// HTTP response was lost (timeout / 5xx after commit), the retry's fresh id defeated
// the CP's dedup and the usage was billed TWICE.
//
// Here the fake CP commits the batch on the first attempt and THEN fails the
// response (500). The retry must reuse the SAME report_id so the CP dedups it and
// the account is billed exactly once.
func TestMeter_ResponseLostDoesNotDoubleBill(t *testing.T) {
	const secret = "shh"
	var (
		mu       sync.Mutex
		applied  int64 // total bytes the CP actually committed
		seen     = map[string]bool{}
		attempts int32
	)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/relay/usage", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		if r.Header.Get("X-Pop-Sig") != hex.EncodeToString(mac.Sum(nil)) {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		var env usageEnvelope
		_ = json.Unmarshal(body, &env)

		mu.Lock()
		if !seen[env.ReportID] {
			seen[env.ReportID] = true
			for _, it := range env.Items {
				applied += it.Bytes
			}
		}
		mu.Unlock()

		// First attempt: the CP has COMMITTED the delta above, but we simulate the
		// response being lost by returning 500. The relay sees an error and must
		// retry with the SAME report_id (a dedup no-op), not re-bill under a new id.
		if atomic.AddInt32(&attempts, 1) == 1 {
			http.Error(w, "response lost after commit", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "applied": false})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cp := &CPClient{BaseURL: srv.URL, SharedSecret: secret, PoPID: "pop-1"}
	m := newMeter(cp, time.Hour) // manual flush only

	m.addBytes("acct-1", 1000)
	m.flushOnce() // attempt 1: CP commits 1000, then 500 → relay requeues the batch
	m.flushOnce() // attempt 2: retry with the SAME id → CP dedups → no re-bill

	mu.Lock()
	got := applied
	mu.Unlock()
	if got != 1000 {
		t.Fatalf("account double-billed on response-lost retry: CP applied %d bytes, want 1000", got)
	}

	// The batch was ultimately acknowledged, so nothing should remain queued.
	m.mu.Lock()
	remaining := len(m.retry)
	m.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("retry queue not cleared after successful retry: %d batches left", remaining)
	}
}

// TestMeter_BootIDMakesReportIDsUniqueAcrossRestarts guards the cross-restart
// collision fix: two meter instances (simulating a process restart) must never mint
// the same report_id for their first batch, otherwise the CP's dedup drops the
// second one and that usage is lost (under-billing on every restart).
func TestMeter_BootIDMakesReportIDsUniqueAcrossRestarts(t *testing.T) {
	cp := &CPClient{PoPID: "pop-1"}
	a := newMeter(cp, time.Hour)
	b := newMeter(cp, time.Hour)
	if a.bootID == b.bootID {
		t.Fatalf("two meters share a boot id %q — report_ids would collide across restarts", a.bootID)
	}
	if a.nextReportID() == b.nextReportID() {
		t.Fatal("first report_id collides across a simulated restart")
	}
}
