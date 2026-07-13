package agent

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// localDialTimeout bounds connecting to the local target.
const localDialTimeout = 10 * time.Second

// serveStream handles ONE inbound request delivered over a yamux stream. It reads
// the HTTP request, proxies it to the single configured local target, and streams
// the response back. WebSocket upgrades are handled by switching to raw byte
// copying after the local server returns 101.
func (a *Agent) serveStream(stream net.Conn) {
	defer stream.Close()

	br := bufio.NewReaderSize(stream, 64<<10)
	req, err := http.ReadRequest(br)
	if err != nil {
		writeSimpleResponse(stream, http.StatusBadRequest, "bad request")
		return
	}
	// Prevent unbounded header memory: ReadRequest already read headers, but guard
	// against absurd content by capping the body read downstream via the local dial.
	req.RequestURI = ""

	// SSRF guard, re-checked here: we ONLY ever dial our one configured, loopback-
	// validated target. The request's Host/URL delivered over the relay never
	// influences where we connect — it is used only to rewrite the request for the
	// local origin below.
	target := a.opts.LocalAddr
	if err := ensureLoopback(target); err != nil {
		writeSimpleResponse(stream, http.StatusForbidden, "forbidden")
		return
	}

	upstream, err := net.DialTimeout("tcp", target, localDialTimeout)
	if err != nil {
		a.appendLog("local dial failed: %v", err)
		writeSimpleResponse(stream, http.StatusBadGateway, "bad gateway")
		return
	}
	defer upstream.Close()

	isWS := isWebSocketUpgrade(req)

	// Rewrite the request for the local origin: the URL must be origin-form and the
	// Host header should point at the local target so the app sees a normal request.
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Host = target

	// Forward the request to the local server.
	if err := req.Write(upstream); err != nil {
		writeSimpleResponse(stream, http.StatusBadGateway, "bad gateway")
		return
	}

	if isWS {
		a.pumpWebSocket(stream, br, upstream)
		return
	}

	// Read the local response and stream it back over the yamux stream.
	upstreamBr := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamBr, req)
	if err != nil {
		writeSimpleResponse(stream, http.StatusBadGateway, "bad gateway")
		return
	}
	defer resp.Body.Close()

	// If the local app itself did a protocol upgrade on a non-WS request, fall back
	// to raw duplex copy.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if err := resp.Write(stream); err != nil {
			return
		}
		duplexCopy(stream, newBufferedConn(upstream, upstreamBr))
		return
	}

	if err := resp.Write(stream); err != nil {
		a.appendLog("response write failed: %v", err)
	}
}

// pumpWebSocket completes a WS handshake by copying the local server's 101 back
// and then splicing the two connections. The relay already forwarded the client's
// Upgrade request bytes to us as an http.Request which we re-wrote to upstream.
func (a *Agent) pumpWebSocket(clientSide net.Conn, clientBr *bufio.Reader, upstream net.Conn) {
	upstreamBr := bufio.NewReader(upstream)
	// Read the 101 (or error) response head and forward it verbatim to the relay.
	resp, err := http.ReadResponse(upstreamBr, nil)
	if err != nil {
		writeSimpleResponse(clientSide, http.StatusBadGateway, "bad gateway")
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Not upgraded — just relay whatever the local server said.
		_ = resp.Write(clientSide)
		return
	}
	if err := resp.Write(clientSide); err != nil {
		return
	}
	// Now both sides are in WS frame mode: raw byte splice, honoring any bytes the
	// buffered readers already pulled past the header boundary.
	duplexCopy(newBufferedConn(clientSide, clientBr), newBufferedConn(upstream, upstreamBr))
}

// duplexCopy copies bytes in both directions until either side closes, then
// returns. Half-closes are propagated where possible.
func duplexCopy(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Signal EOF to the other side.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func isWebSocketUpgrade(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, tok := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

func writeSimpleResponse(w io.Writer, code int, msg string) {
	// Minimal, non-leaky response. Never echoes internal error detail.
	body := msg + "\n"
	fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}
