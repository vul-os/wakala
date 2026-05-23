// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/vul-os/vulos-relay/internal/reputation"
)

// ---- stub HTTPClient -------------------------------------------------------

type stubHTTPClient struct {
	responses map[string]*http.Response
	err       error
}

func (s *stubHTTPClient) Get(url string) (*http.Response, error) {
	if s.err != nil {
		return nil, s.err
	}
	if resp, ok := s.responses[url]; ok {
		return resp, nil
	}
	// Default: 404
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

func newJSONResponse(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

// ---- PostmasterClient tests ------------------------------------------------

// TestPostmasterNoOpWhenNoCreds ensures missing APIKey → no-op + no crash.
func TestPostmasterNoOpWhenNoCreds(t *testing.T) {
	client := reputation.NewPostmasterClient(reputation.PostmasterConfig{
		// No APIKey — should be a no-op.
	})
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Signals store should be empty.
	sigs := client.SignalsByDomain("example.com")
	if len(sigs) != 0 {
		t.Errorf("expected 0 signals, got %d", len(sigs))
	}
}

// TestPostmasterSyncParsesResponse verifies that a mock API response is parsed
// into ProviderSignals accessible via SignalsByDomain.
func TestPostmasterSyncParsesResponse(t *testing.T) {
	const domain = "example.com"
	apiBody := `{
		"trafficStats": [
			{"name":"domains/example.com/trafficStats/20240601","userReportedSpamRatio":0.012,"domainReputation":"HIGH"},
			{"name":"domains/example.com/trafficStats/20240602","userReportedSpamRatio":0.005,"domainReputation":"HIGH"}
		]
	}`

	apiKey := "test-key"
	baseURL := "https://fake-postmaster.example"
	expectedURL := baseURL + "/domains/" + domain + "/trafficStats?key=" + apiKey

	stub := &stubHTTPClient{
		responses: map[string]*http.Response{
			expectedURL: newJSONResponse(http.StatusOK, apiBody),
		},
	}

	client := reputation.NewPostmasterClient(reputation.PostmasterConfig{
		APIKey:     apiKey,
		Domains:    []string{domain},
		BaseURL:    baseURL,
		HTTPClient: stub,
	})

	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("Sync returned error: %v", err)
	}

	sigs := client.SignalsByDomain(domain)
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(sigs))
	}
	if sigs[0].Provider != "google" {
		t.Errorf("expected provider google, got %s", sigs[0].Provider)
	}
	if sigs[0].SpamRate < 0.011 || sigs[0].SpamRate > 0.013 {
		t.Errorf("unexpected spam rate %f", sigs[0].SpamRate)
	}
}

// ---- SNDSClient tests -------------------------------------------------------

// TestSNDSNoOpWhenNoCreds ensures missing DataKey → no-op + no crash.
func TestSNDSNoOpWhenNoCreds(t *testing.T) {
	client := reputation.NewSNDSClient(reputation.SNDSConfig{})
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sigs := client.SignalsByIP(net.ParseIP("1.2.3.4"))
	if len(sigs) != 0 {
		t.Errorf("expected 0 signals, got %d", len(sigs))
	}
}

// TestSNDSSyncParsesCSV verifies that the SNDS CSV feed is parsed into
// ProviderSignals queryable by IP.
func TestSNDSSyncParsesCSV(t *testing.T) {
	// Simulate a SNDS tab-separated CSV response.
	csvBody := "IP Range\tActivity Start Date\tActivity End Date\tSending IP\tSpam Trap Hits\tFilter Result\tComplaint Rate\r\n" +
		"1.2.3.0/24\t2024-06-01\t2024-06-02\t1.2.3.4\t3\tGREEN\t0.50%\r\n" +
		"5.6.7.0/24\t2024-06-01\t2024-06-02\t5.6.7.8\t0\tGREEN\t0.00%\r\n"

	dataKey := "testdatakey"
	apiURL := "https://fake-snds.example/snds/data.aspx?key={key}"
	expectedURL := "https://fake-snds.example/snds/data.aspx?key=testdatakey"

	stub := &stubHTTPClient{
		responses: map[string]*http.Response{
			expectedURL: newJSONResponse(http.StatusOK, csvBody),
		},
	}

	client := reputation.NewSNDSClient(reputation.SNDSConfig{
		DataKey:    dataKey,
		APIURL:     apiURL,
		HTTPClient: stub,
	})

	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}

	sigs := client.SignalsByIP(net.ParseIP("1.2.3.4"))
	if len(sigs) == 0 {
		t.Fatal("expected signals for 1.2.3.4, got none")
	}
	if sigs[0].Provider != "microsoft-snds" {
		t.Errorf("expected provider microsoft-snds, got %s", sigs[0].Provider)
	}
	if sigs[0].FBLCount != 3 {
		t.Errorf("expected FBLCount 3, got %d", sigs[0].FBLCount)
	}
	// Complaint rate 0.50% → 0.005
	if sigs[0].ComplaintRate < 0.004 || sigs[0].ComplaintRate > 0.006 {
		t.Errorf("unexpected complaint rate %f", sigs[0].ComplaintRate)
	}
}

// TestSNDSSignalsByDomain verifies that domain-level signals are not returned
// for IP-only queries (SNDS is IP-level only).
func TestSNDSSignalsByDomain(t *testing.T) {
	client := reputation.NewSNDSClient(reputation.SNDSConfig{})
	sigs := client.SignalsByDomain("example.com")
	if len(sigs) != 0 {
		t.Errorf("expected 0 domain signals from SNDS, got %d", len(sigs))
	}
}
