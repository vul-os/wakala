// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/queue"
	"github.com/vul-os/vulos-relay/internal/relay"
	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
	"github.com/vul-os/vulos-relay/internal/suppression"
)

// ─── Attack class 7: suppression send-gate + report-intake poisoning ──────────
//
// Two threats are modelled here:
//
//  1. Send-gate: a recipient that previously hard-bounced or filed an abuse
//     complaint FOR AN ACCOUNT must be dropped at that account's send gate —
//     re-sending to a hard-bounce/complaint address is exactly the abuse pattern
//     blocklists watch for.
//
//  2. Report-intake poisoning (the CRITICAL finding): the POST /reports endpoint
//     must be AUTHENTICATED and PER-ACCOUNT scoped. An unauthenticated forged
//     DSN/ARF must be REJECTED (no global denial-of-delivery), and an
//     authenticated report for one account must NEVER suppress a recipient for a
//     different account (no cross-account poisoning).

// recordingSender captures the recipients each Send call is asked to deliver
// to. It is the canary: a suppressed address appearing here is a hole.
type recordingSender struct {
	mu  sync.Mutex
	got [][]string
}

func (s *recordingSender) Send(_ context.Context, msg sending.Message) (sending.SendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, append([]string(nil), msg.Recipients...))
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

func (s *recordingSender) allRecipients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.got {
		out = append(out, r...)
	}
	return out
}

// ATTACK (gate seam): the exact partition the pipeline relies on — a suppressed
// recipient must be classified as dropped for the account that suppressed it.
func TestSuppression_HardBounce_DroppedAtGate(t *testing.T) {
	list := suppression.NewList()
	list.Suppress("acct-victim", "bounced@victim.example", suppression.ReasonHardBounce, "5.1.1 user unknown")
	list.Suppress("acct-victim", "complainer@victim.example", suppression.ReasonComplaint, "arf")

	allowed, dropped := list.FilterRecipients("acct-victim", []string{
		"bounced@victim.example",
		"ok@victim.example",
		"complainer@victim.example",
	})
	if contains(allowed, "bounced@victim.example") || contains(allowed, "complainer@victim.example") {
		t.Fatal("VULN: a hard-bounced/complaint recipient was allowed through the send gate")
	}
	if !contains(allowed, "ok@victim.example") {
		t.Fatal("a non-suppressed recipient was wrongly dropped")
	}
	if !contains(dropped, "bounced@victim.example") || !contains(dropped, "complainer@victim.example") {
		t.Fatal("suppressed recipients not reported as dropped")
	}
}

// ATTACK (end-to-end): drive the real send Pipeline. A message addressed to a
// suppressed recipient (plus a clean one) is leased and processed; the Sender
// must be asked to deliver ONLY to the clean recipient — the suppressed one is
// dropped before delivery.
func TestSuppression_PipelineNeverSendsToSuppressed(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:         "m1",
		AccountID:  "acct",
		Sender:     "alice@tenant.example",
		Recipients: []string{"bounced@victim.example", "clean@victim.example"},
		RawRFC822:  []byte("Subject: hi\r\n\r\nbody"),
	})

	list := suppression.NewList()
	list.Suppress("acct", "bounced@victim.example", suppression.ReasonHardBounce, "5.1.1")

	sender := &recordingSender{}
	pipe := sending.NewPipeline(q, reputation.Permissive{}, sender, sending.PipelineConfig{
		Workers:      1,
		PollInterval: time.Millisecond,
		Suppression:  list,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { pipe.Run(ctx); close(done) }()

	// Wait until the message has been processed (sender called) then stop.
	deadline := time.After(2 * time.Second)
	for {
		if len(sender.allRecipients()) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("pipeline did not process the message in time")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	<-done

	got := sender.allRecipients()
	if contains(got, "bounced@victim.example") {
		t.Fatalf("VULN: pipeline delivered to a suppressed recipient: %v", got)
	}
	if !contains(got, "clean@victim.example") {
		t.Fatalf("clean recipient should have been delivered to, got %v", got)
	}
}

// ATTACK (all-suppressed): a message whose EVERY recipient is suppressed for the
// account must never reach the Sender at all (it is acked, not sent).
func TestSuppression_AllSuppressed_NeverSent(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:         "m2",
		AccountID:  "acct",
		Sender:     "alice@tenant.example",
		Recipients: []string{"a@victim.example", "b@victim.example"},
		RawRFC822:  []byte("Subject: hi\r\n\r\nbody"),
	})
	list := suppression.NewList()
	list.Suppress("acct", "a@victim.example", suppression.ReasonComplaint, "")
	list.Suppress("acct", "b@victim.example", suppression.ReasonHardBounce, "")

	sender := &recordingSender{}
	pipe := sending.NewPipeline(q, reputation.Permissive{}, sender, sending.PipelineConfig{
		Workers:      1,
		PollInterval: time.Millisecond,
		Suppression:  list,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { pipe.Run(ctx); close(done) }()
	<-ctx.Done()
	<-done

	if got := sender.allRecipients(); len(got) != 0 {
		t.Fatalf("VULN: an all-suppressed message reached the Sender: %v", got)
	}
}

// ─── CRITICAL: report-intake authentication + per-account scoping ─────────────

// A realistic RFC 3464 DSN with a permanent (5.1.1) failure for a victim
// recipient. A forger POSTs this to suppress that recipient.
func forgedDSN(victim string) string {
	return "From: MAILER-DAEMON@mx.attacker.net\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"B\"\r\n" +
		"\r\n" +
		"--B\r\n" +
		"Content-Type: message/delivery-status\r\n" +
		"\r\n" +
		"Final-Recipient: rfc822; " + victim + "\r\n" +
		"Action: failed\r\n" +
		"Status: 5.1.1\r\n" +
		"--B--\r\n"
}

// reportRelay stands up the REAL authenticated report-intake HTTP surface the
// way the relay wires it: the same SharedSecretAuth gate as /submit, scoped
// per-account, behind suppression.IngressHandler over httptest.
type reportRelay struct {
	list *suppression.List
	reg  *relay.MemAccountRegistry
	auth *relay.SharedSecretAuth
	srv  *httptest.Server
}

func newReportRelay(t *testing.T) *reportRelay {
	t.Helper()
	list := suppression.NewList()
	reg := relay.NewMemAccountRegistry()
	auth := relay.NewSharedSecretAuth(reg)

	ih := suppression.NewIngressHandler(suppression.IngressConfig{
		List:          list,
		Authenticator: reportAuthAdapter{ra: relay.NewRequestAuthenticator(auth)},
		// A real per-IP limiter, mirroring production wiring.
		RateLimiter: relay.NewIPRateLimiter(60, time.Minute),
		ClientIP:    relay.ClientIP,
	})
	mux := http.NewServeMux()
	mux.Handle(suppression.IngressPath, ih)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &reportRelay{list: list, reg: reg, auth: auth, srv: srv}
}

// reportAuthAdapter adapts relay.RequestAuthenticator to the suppression
// ReportAuthenticator seam (same adapter the production wiring uses).
type reportAuthAdapter struct{ ra *relay.RequestAuthenticator }

func (a reportAuthAdapter) AuthenticateReport(r *http.Request) (string, error) {
	return a.ra.AuthenticateRequest(r)
}

// register adds an account with a shared secret and returns it.
func (rr *reportRelay) register(account string, secret []byte) {
	rr.reg.Register(relay.AccountRecord{AccountID: account, SharedSecret: secret})
}

// postReport POSTs a raw report. If account/secret are non-empty it signs a
// valid VulosShared HMAC credential (the same scheme /submit accepts).
func (rr *reportRelay) postReport(t *testing.T, account string, secret []byte, raw string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rr.srv.URL+suppression.IngressPath, bytes.NewReader([]byte(raw)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if account != "" {
		ts := time.Now().Unix()
		tok := relay.ComputeHMACToken(secret, account, "report-1", ts)
		req.Header.Set("Authorization", fmt.Sprintf("VulosShared %s:%s:%d:%s", tok.AccountID, tok.MessageID, tok.Timestamp, tok.Signature))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST report: %v", err)
	}
	return resp
}

// ATTACK (CRITICAL): an UNAUTHENTICATED stranger POSTs a forged DSN for a victim
// recipient. EXPECT: 401, and the victim is NOT suppressed for anyone — there is
// no global denial-of-delivery sink.
func TestReportIntake_UnauthenticatedForgedDSN_Rejected(t *testing.T) {
	rr := newReportRelay(t)
	rr.register("sender-acct", []byte("sender-secret"))

	victim := "ceo@bigcorp.example"
	resp := rr.postReport(t, "", nil, forgedDSN(victim)) // no credential
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated forged report must be 401, got %d", resp.StatusCode)
	}
	// The victim must not be suppressed for any account — nothing was applied.
	if rr.list.Len() != 0 {
		t.Fatalf("VULN: an unauthenticated forged report mutated the suppression list (len=%d)", rr.list.Len())
	}
	if _, ok := rr.list.IsSuppressed("sender-acct", victim); ok {
		t.Fatal("VULN: forged report suppressed the victim for a real account")
	}
}

// ATTACK (CRITICAL): an authenticated stranger account submits a forged report
// for a victim recipient. EXPECT: the suppression is scoped to the STRANGER's
// own account only — it must NOT suppress that recipient for any OTHER account
// (no cross-account poisoning / global block).
func TestReportIntake_AuthenticatedReport_ScopedToOwnAccountOnly(t *testing.T) {
	rr := newReportRelay(t)
	rr.register("stranger", []byte("stranger-secret"))
	rr.register("victim-tenant", []byte("victim-secret"))

	victim := "customer@partner.example"
	resp := rr.postReport(t, "stranger", []byte("stranger-secret"), forgedDSN(victim))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated report should be accepted (200), got %d", resp.StatusCode)
	}

	// It IS suppressed for the stranger's own account (their report, their scope).
	if _, ok := rr.list.IsSuppressed("stranger", victim); !ok {
		t.Fatal("the submitting account's own report should suppress within its own scope")
	}
	// CRITICAL: it must NOT be suppressed for the victim tenant or any other account.
	if _, ok := rr.list.IsSuppressed("victim-tenant", victim); ok {
		t.Fatal("VULN: a stranger's report suppressed a recipient for a DIFFERENT account (cross-account poisoning)")
	}

	// Prove the victim tenant can still deliver to that recipient.
	allowed, dropped := rr.list.FilterRecipients("victim-tenant", []string{victim})
	if len(allowed) != 1 || len(dropped) != 0 {
		t.Fatalf("VULN: stranger's report blocked delivery for victim-tenant; allowed=%v dropped=%v", allowed, dropped)
	}
}

// ATTACK: an authenticated account presents a tampered HMAC signature.
// EXPECT: 401, nothing suppressed.
func TestReportIntake_BadSignature_Rejected(t *testing.T) {
	rr := newReportRelay(t)
	rr.register("acct", []byte("the-secret"))

	// Sign with the WRONG secret — the signature will not verify.
	resp := rr.postReport(t, "acct", []byte("wrong-secret"), forgedDSN("x@y.example"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("report with a bad signature must be 401, got %d", resp.StatusCode)
	}
	if rr.list.Len() != 0 {
		t.Fatalf("VULN: a bad-signature report mutated the suppression list (len=%d)", rr.list.Len())
	}
}

// DURABILITY: the SQLite-backed store survives a "restart" (re-open of the same
// DB file). A hard-bounce suppressed before restart is still suppressed after,
// scoped to the same account.
func TestSuppression_SQLiteStore_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/suppression.db"

	store1, err := suppression.NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	list1 := suppression.NewListWithStore(store1)
	list1.Suppress("acct1", "dead@box.example", suppression.ReasonHardBounce, "5.1.1")
	if _, ok := list1.IsSuppressed("acct1", "dead@box.example"); !ok {
		t.Fatal("address should be suppressed before restart")
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// "Restart": re-open the same DB file.
	store2, err := suppression.NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()
	list2 := suppression.NewListWithStore(store2)
	if _, ok := list2.IsSuppressed("acct1", "dead@box.example"); !ok {
		t.Fatal("VULN: durable suppression was lost across restart")
	}
	// Still per-account scoped after restart.
	if _, ok := list2.IsSuppressed("acct2", "dead@box.example"); ok {
		t.Fatal("per-account scoping lost across restart")
	}
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}
