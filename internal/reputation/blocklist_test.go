// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// ---- stub DNS resolver -------------------------------------------------------

// stubDNSResolver is a DNSResolver that returns preset answers.
type stubDNSResolver struct {
	// answers maps lookup name → addresses (nil or empty = NXDOMAIN).
	answers map[string][]string
}

func (r *stubDNSResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	addrs, ok := r.answers[name]
	if !ok || len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return addrs, nil
}

// ---- stub HTTP client --------------------------------------------------------

type stubHTTPResponse struct {
	statusCode int
	body       string
}

type stubHTTPClient struct {
	// responses maps URL prefix → response.
	responses map[string]stubHTTPResponse
	// calls records URLs that were requested.
	calls []string
}

func (c *stubHTTPClient) Get(url string) (*http.Response, error) {
	c.calls = append(c.calls, url)
	for prefix, resp := range c.responses {
		if strings.HasPrefix(url, prefix) {
			return &http.Response{
				StatusCode: resp.statusCode,
				Body:       io.NopCloser(strings.NewReader(resp.body)),
			}, nil
		}
	}
	return nil, fmt.Errorf("stub: no response configured for %s", url)
}

// ---- stub IPPool ------------------------------------------------------------

type stubPool struct {
	quarantined map[string]string // ip → reason
	cleared     map[string]bool
}

func newStubPool() *stubPool {
	return &stubPool{
		quarantined: make(map[string]string),
		cleared:     make(map[string]bool),
	}
}

func (p *stubPool) Quarantine(ip net.IP, reason string) {
	p.quarantined[ip.String()] = reason
}

func (p *stubPool) Unquarantine(ip net.IP) {
	delete(p.quarantined, ip.String())
	p.cleared[ip.String()] = true
}

// ---- helper: reverse-IP for building DNSBL query names ----------------------

func mustReverse(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

// ---- Spamhaus ----------------------------------------------------------------

func TestSpamhausSource_NotListed(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	resolver := &stubDNSResolver{answers: map[string][]string{}}
	src := &SpamhausSource{Resolver: resolver, Zone: "zen.spamhaus.org"}

	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Listed {
		t.Fatalf("expected not listed")
	}
}

func TestSpamhausSource_Listed(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	query := mustReverse("1.2.3.4") + ".zen.spamhaus.org"
	resolver := &stubDNSResolver{
		answers: map[string][]string{
			query: {"127.0.0.2"},
		},
	}
	src := &SpamhausSource{Resolver: resolver, Zone: "zen.spamhaus.org"}

	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Listed {
		t.Fatalf("expected listed")
	}
	if !strings.Contains(status.Reason, "SBL") {
		t.Errorf("reason should mention SBL, got %q", status.Reason)
	}
	if status.DelistURL == "" {
		t.Errorf("expected non-empty DelistURL")
	}
}

func TestSpamhausSource_Delist_IsNoError(t *testing.T) {
	src := &SpamhausSource{}
	err := src.Delist(context.Background(), net.ParseIP("1.2.3.4"))
	if err != nil {
		t.Fatalf("Delist should be a no-op stub, got error: %v", err)
	}
}

// ---- SORBS ------------------------------------------------------------------

func TestSORBSSource_NotListed(t *testing.T) {
	ip := net.ParseIP("5.6.7.8")
	src := &SORBSSource{
		Resolver: &stubDNSResolver{answers: map[string][]string{}},
		Zone:     "dnsbl.sorbs.net",
	}
	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Listed {
		t.Fatalf("expected not listed")
	}
}

func TestSORBSSource_Listed(t *testing.T) {
	ip := net.ParseIP("5.6.7.8")
	query := mustReverse("5.6.7.8") + ".dnsbl.sorbs.net"
	src := &SORBSSource{
		Resolver: &stubDNSResolver{answers: map[string][]string{
			query: {"127.0.0.6"},
		}},
		Zone: "dnsbl.sorbs.net",
	}
	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Listed {
		t.Fatalf("expected listed")
	}
}

// ---- Barracuda --------------------------------------------------------------

func TestBarracudaSource_NotListed(t *testing.T) {
	ip := net.ParseIP("9.10.11.12")
	src := &BarracudaSource{
		Resolver: &stubDNSResolver{answers: map[string][]string{}},
		Zone:     "b.barracudacentral.org",
	}
	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Listed {
		t.Fatalf("expected not listed")
	}
}

func TestBarracudaSource_Listed(t *testing.T) {
	ip := net.ParseIP("9.10.11.12")
	query := mustReverse("9.10.11.12") + ".b.barracudacentral.org"
	src := &BarracudaSource{
		Resolver: &stubDNSResolver{answers: map[string][]string{
			query: {"127.0.0.2"},
		}},
		Zone:          "b.barracudacentral.org",
		DelistBaseURL: "http://example.com/delist",
	}
	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Listed {
		t.Fatalf("expected listed")
	}
	if !strings.Contains(status.DelistURL, "9.10.11.12") {
		t.Errorf("DelistURL should contain IP, got %q", status.DelistURL)
	}
}

func TestBarracudaSource_Delist_HTTP(t *testing.T) {
	ip := net.ParseIP("9.10.11.12")
	client := &stubHTTPClient{
		responses: map[string]stubHTTPResponse{
			"http://example.com/delist": {statusCode: 200, body: "ok"},
		},
	}
	src := &BarracudaSource{
		Resolver:      &stubDNSResolver{},
		HTTPClient:    client,
		DelistBaseURL: "http://example.com/delist",
	}
	err := src.Delist(context.Background(), ip)
	if err != nil {
		t.Fatalf("Delist: %v", err)
	}
	if len(client.calls) == 0 {
		t.Fatalf("expected HTTP call to be made")
	}
}

func TestBarracudaSource_Delist_HTTPError(t *testing.T) {
	ip := net.ParseIP("9.10.11.12")
	client := &stubHTTPClient{
		responses: map[string]stubHTTPResponse{
			"http://example.com/delist": {statusCode: 500, body: "server error"},
		},
	}
	src := &BarracudaSource{
		HTTPClient:    client,
		DelistBaseURL: "http://example.com/delist",
	}
	err := src.Delist(context.Background(), ip)
	if err == nil {
		t.Fatalf("expected error on HTTP 500")
	}
}

// ---- SenderScore ------------------------------------------------------------

func TestSenderScoreSource_GoodScore(t *testing.T) {
	ip := net.ParseIP("203.0.113.1")
	client := &stubHTTPClient{
		responses: map[string]stubHTTPResponse{
			"http://fake-ss/": {statusCode: 200, body: "85"},
		},
	}
	src := &SenderScoreSource{
		HTTPClient:   client,
		APIBaseURL:   "http://fake-ss/{ip}",
		BadThreshold: 70,
	}
	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Listed {
		t.Fatalf("score 85 > threshold 70: should not be listed")
	}
}

func TestSenderScoreSource_BadScore(t *testing.T) {
	ip := net.ParseIP("203.0.113.2")
	client := &stubHTTPClient{
		responses: map[string]stubHTTPResponse{
			"http://fake-ss/": {statusCode: 200, body: "55"},
		},
	}
	src := &SenderScoreSource{
		HTTPClient:   client,
		APIBaseURL:   "http://fake-ss/{ip}",
		BadThreshold: 70,
	}
	status, err := src.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Listed {
		t.Fatalf("score 55 ≤ threshold 70: should be listed")
	}
	if status.Reason == "" {
		t.Errorf("expected non-empty reason for low score")
	}
}

func TestSenderScoreSource_Delist_IsNoError(t *testing.T) {
	src := &SenderScoreSource{}
	err := src.Delist(context.Background(), net.ParseIP("203.0.113.1"))
	if err != nil {
		t.Fatalf("Delist should be a no-op stub, got: %v", err)
	}
}

// ---- BlocklistMonitor -------------------------------------------------------

func TestBlocklistMonitor_NewListingQuarantinesIP(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	query := mustReverse("1.2.3.4") + ".zen.spamhaus.org"
	resolver := &stubDNSResolver{answers: map[string][]string{
		query: {"127.0.0.2"},
	}}

	pool := newStubPool()
	mon := NewBlocklistMonitor(pool, BlocklistMonitorConfig{})
	mon.AddSource(&SpamhausSource{Resolver: resolver, Zone: "zen.spamhaus.org"})
	mon.WatchIP(ip)

	mon.Poll(context.Background())

	if _, ok := pool.quarantined[ip.String()]; !ok {
		t.Fatalf("IP should be quarantined after new listing")
	}
}

func TestBlocklistMonitor_ClearListingUnquarantinesIP(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	query := mustReverse("1.2.3.4") + ".zen.spamhaus.org"

	// First poll: listed.
	listedResolver := &stubDNSResolver{answers: map[string][]string{
		query: {"127.0.0.2"},
	}}

	pool := newStubPool()
	mon := NewBlocklistMonitor(pool, BlocklistMonitorConfig{})
	src := &SpamhausSource{Resolver: listedResolver, Zone: "zen.spamhaus.org"}
	mon.AddSource(src)
	mon.WatchIP(ip)
	mon.Poll(context.Background())

	if _, ok := pool.quarantined[ip.String()]; !ok {
		t.Fatalf("IP should be quarantined after first poll")
	}

	// Second poll: no longer listed — swap to a resolver that returns NXDOMAIN.
	src.Resolver = &stubDNSResolver{answers: map[string][]string{}}
	mon.Poll(context.Background())

	if _, ok := pool.quarantined[ip.String()]; ok {
		t.Fatalf("IP should be unquarantined after clearing poll")
	}
	if !pool.cleared[ip.String()] {
		t.Fatalf("Unquarantine should have been called")
	}
}

func TestBlocklistMonitor_AddRemoveSource(t *testing.T) {
	ip := net.ParseIP("5.5.5.5")
	query := mustReverse("5.5.5.5") + ".zen.spamhaus.org"
	resolver := &stubDNSResolver{answers: map[string][]string{
		query: {"127.0.0.2"},
	}}

	pool := newStubPool()
	mon := NewBlocklistMonitor(pool, BlocklistMonitorConfig{})
	mon.WatchIP(ip)

	src := &SpamhausSource{Resolver: resolver, Zone: "zen.spamhaus.org"}
	mon.AddSource(src)
	mon.RemoveSource("spamhaus")

	// After removal, a poll should not quarantine (no sources).
	mon.Poll(context.Background())
	if _, ok := pool.quarantined[ip.String()]; ok {
		t.Fatalf("no sources registered; IP should not be quarantined")
	}
}

func TestBlocklistMonitor_WatchUnwatchIP(t *testing.T) {
	ip := net.ParseIP("7.7.7.7")
	query := mustReverse("7.7.7.7") + ".zen.spamhaus.org"
	resolver := &stubDNSResolver{answers: map[string][]string{
		query: {"127.0.0.2"},
	}}

	pool := newStubPool()
	mon := NewBlocklistMonitor(pool, BlocklistMonitorConfig{})
	mon.AddSource(&SpamhausSource{Resolver: resolver, Zone: "zen.spamhaus.org"})
	mon.WatchIP(ip)
	mon.UnwatchIP(ip)

	mon.Poll(context.Background())
	if _, ok := pool.quarantined[ip.String()]; ok {
		t.Fatalf("unwatched IP should not be quarantined")
	}
}

func TestBlocklistMonitor_ListingsReturnsAllRecords(t *testing.T) {
	ip := net.ParseIP("11.22.33.44")
	query := mustReverse("11.22.33.44") + ".zen.spamhaus.org"
	resolver := &stubDNSResolver{answers: map[string][]string{
		query: {"127.0.0.2"},
	}}

	pool := newStubPool()
	mon := NewBlocklistMonitor(pool, BlocklistMonitorConfig{})
	mon.AddSource(&SpamhausSource{Resolver: resolver, Zone: "zen.spamhaus.org"})
	mon.WatchIP(ip)
	mon.Poll(context.Background())

	listings := mon.Listings()
	if len(listings) == 0 {
		t.Fatalf("expected at least one listing record")
	}
}

func TestBlocklistSource_Interface(t *testing.T) {
	// Compile-time interface satisfaction checks.
	var _ BlocklistSource = (*SpamhausSource)(nil)
	var _ BlocklistSource = (*SORBSSource)(nil)
	var _ BlocklistSource = (*BarracudaSource)(nil)
	var _ BlocklistSource = (*SenderScoreSource)(nil)
}

func TestReverseDNSBL_IPv4(t *testing.T) {
	got, err := reverseDNSBL(net.ParseIP("1.2.3.4"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "4.3.2.1" {
		t.Fatalf("want 4.3.2.1 got %s", got)
	}
}

func TestReverseDNSBL_IPv6_Error(t *testing.T) {
	_, err := reverseDNSBL(net.ParseIP("::1"))
	if err == nil {
		t.Fatalf("expected error for IPv6 address")
	}
}
