// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// ─── Attack class 6: MTA-STS enforcement ─────────────────────────────────────
//
// Under an MTA-STS (RFC 8461) enforce policy, a delivery MUST go over TLS to an
// MX that matches the policy with a CA-valid cert. A network attacker who
// strips STARTTLS (downgrade), offers no STARTTLS, or substitutes a non-policy
// MX must cause the message to be DEFERRED — never delivered in plaintext.
// These tests put a hostile SMTP sink in front of the SMTPSender and prove no
// plaintext escapes.

// stsSink is a minimal SMTP server. If advertiseTLS is true it advertises
// STARTTLS but tears the connection on the handshake (a downgrade/MITM). It
// records whether it ever received DATA in the clear (the canary).
type stsSink struct {
	ln           net.Listener
	advertiseTLS bool

	mu            sync.Mutex
	plaintextData string
}

func newSTSSink(t *testing.T, advertiseTLS bool) *stsSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &stsSink{ln: ln, advertiseTLS: advertiseTLS}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *stsSink) addr() string { return s.ln.Addr().String() }

func (s *stsSink) capturedPlaintext() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plaintextData
}

func (s *stsSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *stsSink) handle(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	write := func(line string) { _, _ = fmt.Fprintf(w, "%s\r\n", line); _ = w.Flush() }

	write("220 sink.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			if s.advertiseTLS {
				write("250-sink.test")
				write("250 STARTTLS")
			} else {
				write("250-sink.test")
				write("250 OK")
			}
		case strings.HasPrefix(upper, "STARTTLS"):
			write("220 Go ahead")
			return // tear the connection: the client's TLS handshake fails (downgrade)
		case strings.HasPrefix(upper, "MAIL FROM"):
			write("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			write("250 OK")
		case upper == "DATA":
			write("354 End data")
			var b strings.Builder
			for {
				d, e := r.ReadString('\n')
				if e != nil {
					return
				}
				if strings.TrimRight(d, "\r\n") == "." {
					break
				}
				b.WriteString(d)
			}
			s.mu.Lock()
			s.plaintextData = b.String() // a plaintext delivery happened — the canary fired
			s.mu.Unlock()
			write("250 OK queued")
		case strings.HasPrefix(upper, "QUIT"):
			write("221 Bye")
			return
		default:
			write("500 unknown")
		}
	}
}

// stsDialer forces every dial to a fixed address (the sink).
type stsDialer struct{ addr string }

func (d stsDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.addr)
}

// stsMX resolves any domain to a fixed MX host.
type stsMX struct{ host string }

func (r stsMX) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return []*net.MX{{Host: r.host, Pref: 10}}, nil
}

// stsHTTP serves a fixed mta-sts.txt body so PolicyFor resolves an enforce
// policy without touching the network.
type stsHTTP struct{ body string }

func (g stsHTTP) Get(string) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(g.body))}, nil
}

func enforceCache(t *testing.T, body string) *sending.MTASTSCache {
	t.Helper()
	c := sending.NewMTASTSCache()
	c.HTTPClient = stsHTTP{body: body}
	return c
}

func mtastsSender(sink *stsSink, cache *sending.MTASTSCache, mxHost string) *sending.SMTPSender {
	return &sending.SMTPSender{
		DNSResolver: stsMX{host: mxHost},
		Dialer:      stsDialer{addr: sink.addr()},
		TLSPolicy:   sending.TLSPolicyOpportunistic, // MTA-STS must OVERRIDE this to enforce
		MTASTS:      cache,
	}
}

func sendOne(t *testing.T, s *sending.SMTPSender) sending.SendResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, sending.Message{
		ID:         "sts",
		Sender:     "alice@tenant.example",
		Recipients: []string{"bob@enforced.example"},
		RawRFC822:  []byte("From: alice@tenant.example\r\nSubject: hi\r\n\r\nbody\r\n"),
	})
	return res
}

// ─── MTA-STS downgrade gaps (well-known fetch) ────────────────────────────────

// failingGetter fails every fetch after the first N successful ones, returning
// a fixed body for the successes. It models a network attacker who can BLOCK the
// well-known re-fetch (DNS/TLS/connect failure) once a policy has been cached.
type failingGetter struct {
	body         string
	okBeforeFail int
	calls        int
}

func (g *failingGetter) Get(string) (*http.Response, error) {
	g.calls++
	if g.calls > g.okBeforeFail {
		return nil, fmt.Errorf("simulated blocked well-known fetch (MITM)")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(g.body))}, nil
}

// ATTACK: a network attacker REDIRECTS the well-known fetch (3xx) toward a
// weaker policy. RFC 8461 §3.3 forbids following redirects on the well-known
// resource. EXPECT: the production fetcher does NOT follow the redirect — the
// weaker policy at the redirect target is never read.
func TestMTASTS_WellKnownRedirect_NotFollowed(t *testing.T) {
	// The redirect TARGET would serve a (weaker) mode:none policy. If the client
	// followed the 302, this body would win.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "version: STSv1\nmode: none\n")
	}))
	defer target.Close()

	// The well-known origin issues a 302 to the weaker policy (the MITM redirect).
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	fetcher := sending.NewWellKnownFetcher()
	resp, err := fetcher.Get(origin.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer resp.Body.Close()
	// The redirect must be SURFACED (302), not followed to the 200 of the target.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("VULN: well-known fetch followed a 3xx redirect (status %d); RFC 8461 §3.3 forbids it", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "mode: none") {
		t.Fatal("VULN: well-known fetch read the weaker redirect-target policy")
	}
}

// ATTACK: once an ENFORCE policy is cached, the attacker BLOCKS the re-fetch
// (the well-known becomes unreachable). EXPECT: the relay keeps enforcing the
// cached policy rather than silently downgrading to opportunistic — a blocked
// fetch must not strip a known enforce policy.
func TestMTASTS_BlockedRefetch_KeepsCachedEnforce(t *testing.T) {
	cache := sending.NewMTASTSCache()
	getter := &failingGetter{
		body:         "version: STSv1\nmode: enforce\nmx: mail.enforced.example\nmax_age: 3600\n",
		okBeforeFail: 1, // first fetch succeeds (caches enforce), then all fail
	}
	cache.HTTPClient = getter

	// Drive the clock so we can expire the cached policy and force a re-fetch.
	base := time.Now()
	cur := base
	cache.SetClock(func() time.Time { return cur })

	// First call: caches the enforce policy.
	p, err := cache.PolicyFor(context.Background(), "enforced.example")
	if err != nil || p == nil || p.Mode != sending.MTASTSEnforce {
		t.Fatalf("first PolicyFor should cache an enforce policy, got %+v err=%v", p, err)
	}

	// Advance past max_age so the cached entry is expired and a re-fetch happens.
	cur = base.Add(2 * time.Hour)

	// Re-fetch is now BLOCKED (getter fails). The cached enforce policy must win.
	p2, _ := cache.PolicyFor(context.Background(), "enforced.example")
	if p2 == nil || p2.Mode != sending.MTASTSEnforce {
		t.Fatalf("VULN: a blocked well-known re-fetch downgraded a known enforce policy to %v (want enforce)", p2)
	}
	if getter.calls < 2 {
		t.Fatalf("expected a re-fetch attempt after expiry, got %d calls", getter.calls)
	}
}

// ATTACK: STARTTLS downgrade/MITM — the MX advertises STARTTLS but the handshake
// fails. EXPECT: deferred, NO plaintext delivery.
func TestMTASTS_StartTLSDowngrade_DefersNoPlaintext(t *testing.T) {
	sink := newSTSSink(t, true) // advertises STARTTLS but breaks the handshake
	host, _, _ := net.SplitHostPort(sink.addr())
	cache := enforceCache(t, "version: STSv1\nmode: enforce\nmx: "+host+"\nmax_age: 86400\n")

	res := sendOne(t, mtastsSender(sink, cache, host))
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred under enforce downgrade, got %s (%s)", res.State, res.Message)
	}
	if got := sink.capturedPlaintext(); got != "" {
		t.Fatalf("VULN: message delivered in plaintext despite MTA-STS enforce:\n%s", got)
	}
}

// ATTACK: the MX never offers STARTTLS at all under an enforce policy.
// EXPECT: deferred, no plaintext delivery.
func TestMTASTS_NoStartTLS_DefersNoPlaintext(t *testing.T) {
	sink := newSTSSink(t, false) // never advertises STARTTLS
	host, _, _ := net.SplitHostPort(sink.addr())
	cache := enforceCache(t, "version: STSv1\nmode: enforce\nmx: "+host+"\nmax_age: 86400\n")

	res := sendOne(t, mtastsSender(sink, cache, host))
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred when enforce MX offers no STARTTLS, got %s", res.State)
	}
	if got := sink.capturedPlaintext(); got != "" {
		t.Fatalf("VULN: plaintext delivery despite enforce + no STARTTLS:\n%s", got)
	}
}

// ATTACK: DNS substitutes an MX that is NOT listed in the enforce policy (an
// attacker-controlled server). EXPECT: deferred, never delivered to the
// off-policy MX.
func TestMTASTS_MXNotInPolicy_DefersNoPlaintext(t *testing.T) {
	sink := newSTSSink(t, false)
	host, _, _ := net.SplitHostPort(sink.addr())
	// The policy lists a DIFFERENT MX than DNS returns (the sink).
	cache := enforceCache(t, "version: STSv1\nmode: enforce\nmx: legit-mx.enforced.example\nmax_age: 86400\n")

	res := sendOne(t, mtastsSender(sink, cache, host))
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred when MX not in enforce policy, got %s", res.State)
	}
	if got := sink.capturedPlaintext(); got != "" {
		t.Fatalf("VULN: delivered to a non-policy MX despite enforce:\n%s", got)
	}
}
