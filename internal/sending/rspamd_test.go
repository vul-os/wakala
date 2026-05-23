// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// ---- stub HTTP client for Rspamd -------------------------------------------

type rspamdStubHTTP struct {
	status int
	body   string
	err    error
}

func (s *rspamdStubHTTP) Do(req *http.Request) (*http.Response, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(bytes.NewBufferString(s.body)),
	}, nil
}

// ---- tests ------------------------------------------------------------------

// TestRspamdPassThrough verifies that an empty endpoint results in VerdictPass
// with no error.
func TestRspamdPassThrough(t *testing.T) {
	scanner := sending.NewRspamdScanner(sending.RspamdConfig{
		// No Endpoint → pass-through.
	})
	verdict, err := scanner.Scan(context.Background(), []byte("Subject: test\r\n\r\nhello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != sending.VerdictPass {
		t.Errorf("expected VerdictPass, got %s", verdict.Action)
	}
}

// TestRspamdRejectVerdict verifies that a "reject" Rspamd action is mapped to
// VerdictReject and IsReject() returns true.
func TestRspamdRejectVerdict(t *testing.T) {
	stub := &rspamdStubHTTP{
		status: http.StatusOK,
		body:   `{"action":"reject","score":15.5,"symbols":{"SPAM_FLAG":{},"BAYES_SPAM":{}}}`,
	}
	scanner := sending.NewRspamdScanner(sending.RspamdConfig{
		Endpoint:   "http://rspamd.test",
		HTTPClient: stub,
	})

	verdict, err := scanner.Scan(context.Background(), []byte("Subject: spam\r\n\r\nbuy now"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != sending.VerdictReject {
		t.Errorf("expected VerdictReject, got %s", verdict.Action)
	}
	if !verdict.IsReject() {
		t.Error("IsReject() should return true for reject action")
	}
	if verdict.Score != 15.5 {
		t.Errorf("expected score 15.5, got %f", verdict.Score)
	}
	if len(verdict.Symbols) == 0 {
		t.Error("expected symbols to be populated")
	}
}

// TestRspamdSoftRejectVerdict verifies that "soft reject" maps to VerdictSoftReject.
func TestRspamdSoftRejectVerdict(t *testing.T) {
	stub := &rspamdStubHTTP{
		status: http.StatusOK,
		body:   `{"action":"soft reject","score":5.0,"symbols":{}}`,
	}
	scanner := sending.NewRspamdScanner(sending.RspamdConfig{
		Endpoint:   "http://rspamd.test",
		HTTPClient: stub,
	})

	verdict, err := scanner.Scan(context.Background(), []byte("Subject: maybe\r\n\r\nhello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != sending.VerdictSoftReject {
		t.Errorf("expected VerdictSoftReject, got %s", verdict.Action)
	}
	if !verdict.IsReject() {
		t.Error("IsReject() should return true for soft reject")
	}
}

// TestRspamdAddHeaderVerdict verifies that "add header" maps to VerdictAddHeader
// and IsSoft() returns true.
func TestRspamdAddHeaderVerdict(t *testing.T) {
	stub := &rspamdStubHTTP{
		status: http.StatusOK,
		body:   `{"action":"add header","score":3.2,"symbols":{"SOME_SYMBOL":{}}}`,
	}
	scanner := sending.NewRspamdScanner(sending.RspamdConfig{
		Endpoint:   "http://rspamd.test",
		HTTPClient: stub,
	})

	verdict, err := scanner.Scan(context.Background(), []byte("Subject: ok\r\n\r\nhello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != sending.VerdictAddHeader {
		t.Errorf("expected VerdictAddHeader, got %s", verdict.Action)
	}
	if !verdict.IsSoft() {
		t.Error("IsSoft() should return true for add header")
	}
}

// TestRspamdNoActionVerdict verifies that "no action" maps to VerdictNoAction.
func TestRspamdNoActionVerdict(t *testing.T) {
	stub := &rspamdStubHTTP{
		status: http.StatusOK,
		body:   `{"action":"no action","score":0.5,"symbols":{}}`,
	}
	scanner := sending.NewRspamdScanner(sending.RspamdConfig{
		Endpoint:   "http://rspamd.test",
		HTTPClient: stub,
	})

	verdict, err := scanner.Scan(context.Background(), []byte("Subject: clean\r\n\r\nhello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Action != sending.VerdictNoAction {
		t.Errorf("expected VerdictNoAction, got %s", verdict.Action)
	}
	if verdict.IsReject() {
		t.Error("IsReject() should return false for no action")
	}
	if verdict.IsSoft() {
		t.Error("IsSoft() should return false for no action")
	}
}

// TestRspamdHTTPError verifies that a network error is surfaced as a non-nil
// error (not silently swallowed).
func TestRspamdHTTPError(t *testing.T) {
	stub := &rspamdStubHTTP{
		err: io.EOF,
	}
	scanner := sending.NewRspamdScanner(sending.RspamdConfig{
		Endpoint:   "http://rspamd.test",
		HTTPClient: stub,
	})

	_, err := scanner.Scan(context.Background(), []byte("Subject: test\r\n\r\nhello"))
	if err == nil {
		t.Error("expected error on HTTP failure, got nil")
	}
}

// TestRspamdNonOKStatus verifies that a non-200 response is surfaced as error.
func TestRspamdNonOKStatus(t *testing.T) {
	stub := &rspamdStubHTTP{
		status: http.StatusInternalServerError,
		body:   "server error",
	}
	scanner := sending.NewRspamdScanner(sending.RspamdConfig{
		Endpoint:   "http://rspamd.test",
		HTTPClient: stub,
	})

	_, err := scanner.Scan(context.Background(), []byte("Subject: test\r\n\r\nhello"))
	if err == nil {
		t.Error("expected error for non-200 status, got nil")
	}
}
