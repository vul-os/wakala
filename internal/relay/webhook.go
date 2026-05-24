// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// RELAY-17: webhook delivery for inbound envelopes.
//
// WebhookDeliverer POSTs a JSON delivery-status event to a configured HTTPS
// endpoint.  It enforces:
//   - SSRF protection: private/loopback CIDRs and reserved hostnames are
//     rejected before the TCP dial.
//   - HMAC-signed payloads: X-Vulos-Signature header with timestamp + digest.
//   - Retry with exponential back-off: 1m → 5m → 25m → 2h → 12h then dead-letter.
//   - No redirect following.
//   - 5-second connect/response timeout.
//   - Response body capped at 64 KiB.

package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── SSRF guard ──────────────────────────────────────────────────────────────

// blockedCIDRs lists private/reserved IPv4 and IPv6 ranges that MUST NOT be
// contacted by webhook deliveries.
//
// Blocked:
//   - 10.0.0.0/8        (RFC 1918 class-A private)
//   - 172.16.0.0/12     (RFC 1918 class-B private)
//   - 192.168.0.0/16    (RFC 1918 class-C private)
//   - 169.254.0.0/16    (link-local / AWS metadata)
//   - 127.0.0.0/8       (loopback IPv4)
//   - ::1/128           (loopback IPv6)
//   - fc00::/7          (unique-local IPv6)
//   - fe80::/10         (link-local IPv6)
var blockedCIDRs = func() []*net.IPNet {
	raw := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	cidrs := make([]*net.IPNet, 0, len(raw))
	for _, s := range raw {
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			panic("webhook: invalid built-in CIDR " + s + ": " + err.Error())
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}()

// blockedHostSuffixes lists hostname suffixes and exact names that are always
// refused regardless of DNS resolution outcome.
var blockedHostSuffixes = []string{
	"localhost",
	".local",
	".internal",
}

// isBlockedHost returns true when the hostname should be refused without
// dialling.
func isBlockedHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, suffix := range blockedHostSuffixes {
		if h == suffix || strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// isBlockedIP returns true when ip falls inside any blocked CIDR.
func isBlockedIP(ip net.IP) bool {
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ssrfSafeDialContext is a DialContext function that resolves the target
// hostname and checks every resulting IP against the blocked ranges before
// completing the TCP connection.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("webhook ssrf: cannot parse addr %q: %w", addr, err)
	}

	if isBlockedHost(host) {
		return nil, fmt.Errorf("webhook ssrf: host %q is blocked", host)
	}

	// Resolve to IPs and vet each one.
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("webhook ssrf: DNS lookup %q failed: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("webhook ssrf: no addresses for %q", host)
	}
	for _, a := range addrs {
		if isBlockedIP(a.IP) {
			return nil, fmt.Errorf("webhook ssrf: resolved IP %s for %q is in a blocked range", a.IP, host)
		}
	}

	// Dial using the first resolved address.
	target := net.JoinHostPort(addrs[0].IP.String(), port)
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, target)
}

// newSSRFSafeClient returns an *http.Client that:
//   - uses ssrfSafeDialContext for all connections
//   - does not follow redirects
//   - has a 5-second overall timeout
func newSSRFSafeClient() *http.Client {
	transport := &http.Transport{
		DialContext:         ssrfSafeDialContext,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		// Refuse to follow any redirect.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ─── HMAC signing ────────────────────────────────────────────────────────────

// signPayload produces the X-Vulos-Signature header value:
//
//	t=<unix-seconds>,v1=<hmac-sha256-hex>
//
// The HMAC cover string is: "<unix-seconds>.<body-bytes>"
func signPayload(secret []byte, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	digest := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,v1=%s", ts, digest)
}

// VerifyWebhookSignature verifies an X-Vulos-Signature header value against
// the provided secret and body.  It uses constant-time comparison to prevent
// timing oracles.  Returns nil on success.
func VerifyWebhookSignature(secret []byte, sigHeader string, body []byte) error {
	var ts int64
	var gotHex string
	// Parse "t=<ts>,v1=<hex>"
	for _, part := range strings.Split(sigHeader, ",") {
		if strings.HasPrefix(part, "t=") {
			if _, err := fmt.Sscanf(strings.TrimPrefix(part, "t="), "%d", &ts); err != nil {
				return fmt.Errorf("webhook sig: malformed t= field: %w", err)
			}
		} else if strings.HasPrefix(part, "v1=") {
			gotHex = strings.TrimPrefix(part, "v1=")
		}
	}
	if ts == 0 || gotHex == "" {
		return fmt.Errorf("webhook sig: missing t= or v1= fields in %q", sigHeader)
	}

	expected := signPayload(secret, ts, body)
	// Extract the v1= part from the expected string for comparison.
	var expectedHex string
	for _, part := range strings.Split(expected, ",") {
		if strings.HasPrefix(part, "v1=") {
			expectedHex = strings.TrimPrefix(part, "v1=")
		}
	}

	gotBytes, err := hex.DecodeString(gotHex)
	if err != nil {
		return fmt.Errorf("webhook sig: invalid hex in v1= field: %w", err)
	}
	expectedBytes, _ := hex.DecodeString(expectedHex)

	if subtle.ConstantTimeCompare(gotBytes, expectedBytes) != 1 {
		return fmt.Errorf("webhook sig: signature mismatch")
	}
	return nil
}

// ─── Retry schedule ──────────────────────────────────────────────────────────

// retryDelays defines the back-off schedule for failed webhook deliveries.
// After all delays are exhausted the delivery is dead-lettered.
//
//	Attempt 1 → retry after 1m
//	Attempt 2 → retry after 5m
//	Attempt 3 → retry after 25m
//	Attempt 4 → retry after 2h
//	Attempt 5 → retry after 12h
//	Attempt 6 → dead-letter
var retryDelays = []time.Duration{
	1 * time.Minute,
	5 * time.Minute,
	25 * time.Minute,
	2 * time.Hour,
	12 * time.Hour,
}

// ─── Delivery payload ────────────────────────────────────────────────────────

// deliveryEvent is the JSON payload POSTed to the webhook endpoint.
type deliveryEvent struct {
	EventType    string   `json:"event_type"`
	DeliveredAt  string   `json:"delivered_at"`
	From         string   `json:"from"`
	To           []string `json:"to"`
	PeerEndpoint string   `json:"peer_endpoint,omitempty"`
	// RawRFC822 is omitted intentionally: operators receive metadata only
	// to keep payloads small and avoid leaking content via webhook logs.
}

// ─── Dead-letter store ───────────────────────────────────────────────────────

// DeadLetterEntry records a delivery that exhausted all retry attempts.
type DeadLetterEntry struct {
	Envelope  InboundEnvelope
	LastError string
	FailedAt  time.Time
}

// ─── WebhookDeliverer ────────────────────────────────────────────────────────

// WebhookConfig holds configuration for a WebhookDeliverer.
type WebhookConfig struct {
	// URL is the HTTPS endpoint to POST delivery events to.
	URL string

	// Secret is the per-webhook HMAC-SHA256 signing key.  If empty, no
	// X-Vulos-Signature header is sent (not recommended for production).
	Secret []byte

	// HTTPClient overrides the HTTP client used for deliveries.  When nil,
	// an SSRF-safe client is created automatically.  This field is intended
	// for tests only; production code MUST leave it nil.
	HTTPClient *http.Client

	// now overrides time.Now for tests.
	now func() time.Time
}

// WebhookDeliverer delivers InboundEnvelopes to a configured webhook URL via
// signed HTTP POST, with automatic retry and dead-lettering.
//
// WebhookDeliverer is safe for concurrent use.
type WebhookDeliverer struct {
	cfg    WebhookConfig
	client *http.Client

	mu          sync.Mutex
	deadLetters []DeadLetterEntry
}

// NewWebhookDeliverer creates a WebhookDeliverer with the given configuration
// and an SSRF-safe HTTP client.  If cfg.HTTPClient is non-nil it is used
// instead of the SSRF-safe client (tests only).
func NewWebhookDeliverer(cfg WebhookConfig) *WebhookDeliverer {
	client := cfg.HTTPClient
	if client == nil {
		client = newSSRFSafeClient()
	}
	return &WebhookDeliverer{
		cfg:    cfg,
		client: client,
	}
}

func (d *WebhookDeliverer) now() time.Time {
	if d.cfg.now != nil {
		return d.cfg.now()
	}
	return time.Now()
}

// Deliver attempts to deliver env to the configured webhook URL.  It retries
// according to retryDelays, blocking between attempts.  After all retries are
// exhausted the envelope is dead-lettered and ErrWebhookDeadLettered is
// returned.
//
// For use in the router's hot path, callers should invoke Deliver in a
// goroutine.
func (d *WebhookDeliverer) Deliver(ctx context.Context, env InboundEnvelope) error {
	var lastErr error
	for attempt := 0; attempt <= len(retryDelays); attempt++ {
		lastErr = d.post(ctx, env)
		if lastErr == nil {
			return nil
		}

		if attempt < len(retryDelays) {
			delay := retryDelays[attempt]
			select {
			case <-ctx.Done():
				return fmt.Errorf("webhook: context cancelled during retry wait: %w", ctx.Err())
			case <-time.After(delay):
				// next attempt
			}
		}
	}

	// All attempts exhausted — dead-letter.
	entry := DeadLetterEntry{
		Envelope:  env,
		LastError: lastErr.Error(),
		FailedAt:  d.now(),
	}
	d.mu.Lock()
	d.deadLetters = append(d.deadLetters, entry)
	d.mu.Unlock()

	return fmt.Errorf("%w: %v", ErrWebhookDeadLettered, lastErr)
}

// post performs a single HTTP POST attempt.
func (d *WebhookDeliverer) post(ctx context.Context, env InboundEnvelope) error {
	event := deliveryEvent{
		EventType:    "inbound.envelope",
		DeliveredAt:  d.now().UTC().Format(time.RFC3339),
		From:         env.From,
		To:           env.To,
		PeerEndpoint: env.PeerEndpoint,
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("webhook: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if len(d.cfg.Secret) > 0 {
		ts := d.now().Unix()
		sig := signPayload(d.cfg.Secret, ts, body)
		req.Header.Set("X-Vulos-Signature", sig)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: HTTP request: %w", err)
	}
	defer resp.Body.Close()
	// Drain and cap the response body to prevent memory exhaustion.
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024)); err != nil {
		// Ignore drain error — we already have the status code.
		_ = err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("webhook: server returned HTTP %d", resp.StatusCode)
}

// DeadLetters returns a snapshot of all dead-lettered delivery entries.
func (d *WebhookDeliverer) DeadLetters() []DeadLetterEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DeadLetterEntry, len(d.deadLetters))
	copy(out, d.deadLetters)
	return out
}

// ErrWebhookDeadLettered is returned by Deliver when all retry attempts are
// exhausted and the envelope has been moved to the dead-letter store.
var ErrWebhookDeadLettered = fmt.Errorf("relay: webhook delivery dead-lettered")

// DeliverWithDelays is like Deliver but accepts an explicit retry-delay
// schedule, enabling tests to use zero-duration delays without waiting
// minutes.  Pass an empty slice for no retries (attempt once, then
// dead-letter on failure).
func (d *WebhookDeliverer) DeliverWithDelays(ctx context.Context, env InboundEnvelope, delays []time.Duration) error {
	var lastErr error
	maxAttempts := len(delays) + 1 // one initial attempt + one per delay
	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = d.post(ctx, env)
		if lastErr == nil {
			return nil
		}

		if attempt < len(delays) {
			if delays[attempt] > 0 {
				select {
				case <-ctx.Done():
					return fmt.Errorf("webhook: context cancelled during retry wait: %w", ctx.Err())
				case <-time.After(delays[attempt]):
				}
			}
		}
	}

	entry := DeadLetterEntry{
		Envelope:  env,
		LastError: lastErr.Error(),
		FailedAt:  d.now(),
	}
	d.mu.Lock()
	d.deadLetters = append(d.deadLetters, entry)
	d.mu.Unlock()

	return fmt.Errorf("%w: %v", ErrWebhookDeadLettered, lastErr)
}

// SignPayloadForTest is an exported wrapper around signPayload for use in
// tests that need to produce a valid X-Vulos-Signature value directly.
func SignPayloadForTest(secret []byte, ts int64, body []byte) string {
	return signPayload(secret, ts, body)
}
