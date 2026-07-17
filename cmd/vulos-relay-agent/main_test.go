package main

import "testing"

// TestServerIsLoopback checks the loopback classifier that decides how loud the
// -insecure warning is: a non-loopback (or unparseable) target is the dangerous case
// and must NOT be misclassified as loopback (never under-warn).
func TestServerIsLoopback(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"wss://localhost:8443", true},
		{"https://127.0.0.1:8443", true},
		{"wss://127.0.0.5", true},
		{"https://[::1]:8443", true},
		{"wss://relay.example.com", false},
		{"https://8.8.8.8", false},
		{"wss://box.internal", false},
		{"://bad url", false}, // unparseable/unknown ⇒ treat as non-loopback (louder)
		{"", false},
	}
	for _, c := range cases {
		if got := serverIsLoopback(c.url); got != c.want {
			t.Errorf("serverIsLoopback(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}
