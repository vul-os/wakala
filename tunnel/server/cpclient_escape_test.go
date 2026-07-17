package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCPClient_EntitlementAccountIDEscaped asserts the account_id is URL-escaped in
// the entitlement query (LOW hardening): an id containing reserved characters must
// arrive intact and must NOT be able to smuggle extra query parameters into the URL.
func TestCPClient_EntitlementAccountIDEscaped(t *testing.T) {
	const tricky = "acct 1&relay_allowed=true#x"

	var gotAccount string
	var gotSmuggled string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server decodes the query the standard way; a correctly-escaped id round-
		// trips exactly, and no injected "relay_allowed" parameter appears.
		gotAccount = r.URL.Query().Get("account_id")
		gotSmuggled = r.URL.Query().Get("relay_allowed")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":"` + "acct-ok" + `","relay_allowed":true}`))
	}))
	defer srv.Close()

	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	if _, err := cp.EntitlementForAccount(context.Background(), tricky); err != nil {
		t.Fatalf("entitlement: %v", err)
	}
	if gotAccount != tricky {
		t.Fatalf("account_id not round-tripped: got %q, want %q", gotAccount, tricky)
	}
	if gotSmuggled != "" {
		t.Fatalf("query-parameter injection: relay_allowed leaked as %q (account_id not escaped)", gotSmuggled)
	}
}
