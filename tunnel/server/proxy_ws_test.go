package server

import (
	"bufio"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestWriteRawError_ValidStatusLine guards the WS-upgrade error path: when the
// agent's response head cannot be read (bad gateway) the relay writes a RAW
// HTTP/1.1 response onto the hijacked client connection. A previous version
// omitted the numeric status code ("HTTP/1.1 Bad Gateway"), producing a status
// line the client's http.ReadResponse cannot parse. This asserts the line is a
// well-formed, parseable HTTP/1.1 response carrying the numeric code + reason.
func TestWriteRawError_ValidStatusLine(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		writeRawError(server, http.StatusBadGateway)
		server.Close()
	}()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("client could not parse the raw error response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	// "Connection: close" is a hop-by-hop header http.ReadResponse consumes into
	// resp.Close rather than surfacing on resp.Header — assert the parsed intent.
	if !resp.Close {
		t.Fatal("expected Connection: close (resp.Close) on the raw error response")
	}
}
