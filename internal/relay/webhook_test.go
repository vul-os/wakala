// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/relay"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

var webhookSecret = []byte("super-secret-webhook-key")

func testEnv() relay.InboundEnvelope {
	return relay.InboundEnvelope{
		From:         "sender@peer.example",
		To:           []string{"local@example.com"},
		RawRFC822:    []byte("Subject: test\r\n\r\nBody"),
		PeerEndpoint: "peer.example:587",
	}
}

// plainClient returns a basic http.Client that connects to test servers
// without the SSRF guard.  For use in webhook tests only.
func plainClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ─── Test 1: signed delivery — HMAC verified by receiver ────────────────────

func TestWebhookDeliverer_SignedDelivery(t *testing.T) {
	var receivedSig string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Vulos-Signature")
		b, _ := io.ReadAll(r.Body)
		receivedBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := relay.WebhookConfig{
		URL:        srv.URL + "/hook",
		Secret:     webhookSecret,
		HTTPClient: plainClient(),
	}
	d := relay.NewWebhookDeliverer(cfg)

	// Single attempt, no retries.
	if err := d.DeliverWithDelays(context.Background(), testEnv(), []time.Duration{}); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}

	if receivedSig == "" {
		t.Fatal("X-Vulos-Signature header not sent")
	}

	// Verify the signature using the public helper.
	if err := relay.VerifyWebhookSignature(webhookSecret, receivedSig, receivedBody); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}

	// Sanity: payload is JSON with expected fields.
	var payload map[string]interface{}
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	if payload["event_type"] != "inbound.envelope" {
		t.Errorf("unexpected event_type: %v", payload["event_type"])
	}
}

// ─── Test 2: retry on 5xx ────────────────────────────────────────────────────

func TestWebhookDeliverer_RetryOn5xx(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			// Fail first two attempts.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := relay.WebhookConfig{
		URL:        srv.URL + "/hook",
		Secret:     webhookSecret,
		HTTPClient: plainClient(),
	}
	d := relay.NewWebhookDeliverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Zero delays: retry immediately without sleeping.
	err := d.DeliverWithDelays(ctx, testEnv(), []time.Duration{0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("expected eventual success after retries, got: %v", err)
	}
	if n := int(calls.Load()); n != 3 {
		t.Errorf("expected 3 HTTP calls (2 failures + 1 success), got %d", n)
	}
}

// ─── Test 3: dead-letter after final attempt ─────────────────────────────────

func TestWebhookDeliverer_DeadLetterAfterFinalAttempt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always fail.
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := relay.WebhookConfig{
		URL:        srv.URL + "/hook",
		Secret:     webhookSecret,
		HTTPClient: plainClient(),
	}
	d := relay.NewWebhookDeliverer(cfg)

	env := testEnv()
	ctx := context.Background()
	// 5 zero-delay retries → 6 total attempts → dead-letter.
	err := d.DeliverWithDelays(ctx, env, []time.Duration{0, 0, 0, 0, 0})

	if !errors.Is(err, relay.ErrWebhookDeadLettered) {
		t.Fatalf("expected ErrWebhookDeadLettered, got: %v", err)
	}

	dl := d.DeadLetters()
	if len(dl) != 1 {
		t.Fatalf("expected 1 dead-letter entry, got %d", len(dl))
	}
	if dl[0].Envelope.From != env.From {
		t.Errorf("dead-letter From mismatch: got %q want %q", dl[0].Envelope.From, env.From)
	}
}

// ─── Test 4: SSRF — private IP rejected ──────────────────────────────────────

// TestWebhookDeliverer_SSRFPrivateIPRejected verifies that the SSRF guard
// (using the real SSRF-safe client, NOT plainClient) blocks private-range
// targets before any TCP connection is established.
func TestWebhookDeliverer_SSRFPrivateIPRejected(t *testing.T) {
	privateTargets := []string{
		"http://10.0.0.1/hook",
		"http://172.16.0.1/hook",
		"http://192.168.1.1/hook",
		"http://169.254.169.254/hook", // AWS metadata
		"http://127.0.0.1/hook",
		"http://localhost/hook",
	}

	for _, target := range privateTargets {
		target := target
		t.Run(target, func(t *testing.T) {
			// No HTTPClient override — use the real SSRF-safe client.
			cfg := relay.WebhookConfig{
				URL:    target,
				Secret: webhookSecret,
			}
			d := relay.NewWebhookDeliverer(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// No retries: one attempt, then dead-letter.
			err := d.DeliverWithDelays(ctx, testEnv(), []time.Duration{})
			if err == nil {
				t.Fatalf("expected SSRF rejection for %q, but got nil error", target)
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "ssrf") && !strings.Contains(msg, "blocked") &&
				!strings.Contains(msg, "dead-letter") {
				t.Errorf("expected SSRF-related error for %q, got: %v", target, err)
			}
		})
	}
}

// ─── Test 5: signature roundtrip via VerifyWebhookSignature ──────────────────

func TestWebhookSignatureRoundtrip(t *testing.T) {
	secret := []byte("roundtrip-test-secret")
	body := []byte(`{"event_type":"inbound.envelope","from":"a@b.com"}`)
	ts := int64(1_700_000_000)

	// Produce a signature the same way the deliverer does.
	sigHeader := relay.SignPayloadForTest(secret, ts, body)

	// Verify should pass.
	if err := relay.VerifyWebhookSignature(secret, sigHeader, body); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}

	// Wrong secret must fail.
	if err := relay.VerifyWebhookSignature([]byte("wrong"), sigHeader, body); err == nil {
		t.Error("expected signature verification to fail with wrong secret")
	}

	// Tampered body must fail.
	if err := relay.VerifyWebhookSignature(secret, sigHeader, []byte("tampered")); err == nil {
		t.Error("expected signature verification to fail with tampered body")
	}

	// Malformed header must fail.
	if err := relay.VerifyWebhookSignature(secret, "garbage", body); err == nil {
		t.Error("expected signature verification to fail with malformed header")
	}
}

// ─── Test: router wires webhook deliverer ────────────────────────────────────

func TestRouteInbound_WebhookDelivered(t *testing.T) {
	var received atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := relay.NewRouter(relay.RouterConfig{
		WebhookURL:        srv.URL + "/hook",
		WebhookSecret:     webhookSecret,
		WebhookHTTPClient: plainClient(),
	})

	env := relay.InboundEnvelope{
		From:      "sender@peer.example",
		To:        []string{"local@example.com"},
		RawRFC822: []byte("Subject: inbound\r\n\r\nHi"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.RouteInbound(ctx, env); err != nil {
		t.Fatalf("RouteInbound with valid webhook returned error: %v", err)
	}

	if n := int(received.Load()); n != 1 {
		t.Errorf("expected 1 webhook POST, got %d", n)
	}
}

// ─── Test: SSRF blocked in router path ───────────────────────────────────────

func TestRouteInbound_WebhookSSRFBlocked(t *testing.T) {
	// No WebhookHTTPClient: uses real SSRF-safe client.
	r := relay.NewRouter(relay.RouterConfig{
		WebhookURL:    "http://169.254.169.254/hook",
		WebhookSecret: webhookSecret,
	})
	env := relay.InboundEnvelope{
		From: "x@peer.test",
		To:   []string{"y@local.test"},
	}
	// Short context so any retry waits are bypassed immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := r.RouteInbound(ctx, env)
	if err == nil {
		t.Fatal("expected error for SSRF webhook URL, got nil")
	}
}

// ─── verify that SSRF guard catches IPv6 loopback ────────────────────────────

func TestSSRFGuard_IPv6Loopback(t *testing.T) {
	// Try to listen on ::1 to get a real address; skip if not available.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available:", err)
	}
	ln.Close()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	cfg := relay.WebhookConfig{
		URL:    "http://[::1]:" + port + "/hook",
		Secret: webhookSecret,
	}
	d := relay.NewWebhookDeliverer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = d.DeliverWithDelays(ctx, testEnv(), []time.Duration{})
	if err == nil {
		t.Fatal("expected SSRF rejection for ::1, got nil")
	}
}
