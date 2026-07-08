package server

// directprobe.go — DIRECT-IP: reachability + endpoint-OWNERSHIP verification for
// a box's advertised direct-connect endpoint.
//
// A box may advertise a direct endpoint (a public https:// base URL) alongside
// its relay tunnel so clients can dial it DIRECTLY for near-native latency + full
// bandwidth, falling back to the relay tunnel when direct fails. The relay MUST
// NOT take the box's word for the endpoint: an attacker box could otherwise
// advertise someone else's IP/hostname to (a) hijack that victim's client traffic
// or (b) point the relay's probe at an internal service (SSRF). So before the
// relay surfaces a direct endpoint to any client, verifyDirectEndpoint proves two
// things by GETting {endpoint}{wire.DirectProbePath} over the public internet:
//
//   1. REACHABILITY — the endpoint answers over TLS from the relay's vantage; a
//      firewalled/NAT'd endpoint that does not answer is NOT advertised (the box
//      transparently stays on the relay path).
//   2. OWNERSHIP — the relay sends a fresh 256-bit nonce in the DirectProbeHeader
//      and requires the box to echo it back in the response body. Only the box
//      that actually serves that TLS endpoint sees the nonce, so echoing it proves
//      the advertiser controls the endpoint. A box cannot advertise an endpoint it
//      does not serve: the victim host would not echo our nonce.
//
// SSRF POSTURE (mirrors the agent-side loopback guard): the probe target host is
// screened BEFORE any dial. It must be a public (non-loopback, non-private, non
// link-local, non-CGNAT, non-metadata, non-unspecified) address, and the URL must
// be https on the default port set. The custom dialer re-screens the RESOLVED IP
// at connect time (control), defeating DNS-rebind: a hostname that resolves to an
// internal IP is refused at the socket, not just at parse time. Redirects are not
// followed (a redirect could bounce us to an internal target after the fact).

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

// directProbeTimeout bounds the whole reachability+ownership probe.
const directProbeTimeout = 8 * time.Second

// directProbeMaxBody caps how many bytes of the probe response we read (we only
// need the echoed nonce, which is 64 hex chars).
const directProbeMaxBody = 1 << 10 // 1 KiB

// directEndpointVerifier verifies a box-advertised direct endpoint. It is a small
// interface so tests can substitute an in-memory verifier (the real one performs a
// real internet GET, which unit tests must not do). The default is httpDirectVerifier.
type directEndpointVerifier interface {
	// verify returns the normalized endpoint (scheme://host[:port], no trailing
	// slash) on success, or a non-nil error whose message is a short, non-leaky
	// reason on failure.
	verify(ctx context.Context, endpoint string) (normalized string, err error)
}

// httpDirectVerifier probes over real HTTPS with an SSRF-guarded dialer.
type httpDirectVerifier struct {
	// allowInsecure, when true, permits http:// endpoints and skips the public-IP
	// screen — TEST-ONLY (an httptest server binds 127.0.0.1). Never set in prod.
	allowInsecure bool
	// nonce, when non-empty, is used instead of a random one — TEST-ONLY determinism.
	nonce string
}

// verifyDirectEndpoint validates + probes a box's advertised direct endpoint. On
// success it returns the normalized endpoint to advertise to clients; on any
// failure it returns a non-leaky error. It NEVER returns a partially-trusted
// endpoint: either the endpoint is fully verified (reachable + owned) or it is
// refused and the box stays on the relay path.
func (v *httpDirectVerifier) verify(ctx context.Context, endpoint string) (string, error) {
	norm, host, err := normalizeDirectEndpoint(endpoint, v.allowInsecure)
	if err != nil {
		return "", err
	}
	// Screen the host FORM before any dial (parse-time SSRF guard). The dialer
	// below re-screens the RESOLVED IP at connect (defeats DNS-rebind).
	if !v.allowInsecure {
		if err := screenPublicHost(host); err != nil {
			return "", err
		}
	}

	nonce := v.nonce
	if nonce == "" {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("probe nonce")
		}
		nonce = hex.EncodeToString(b[:])
	}

	probeURL := norm + wire.DirectProbePath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", fmt.Errorf("probe request")
	}
	req.Header.Set(wire.DirectProbeHeader, nonce)

	client := &http.Client{
		Timeout: directProbeTimeout,
		// Never follow redirects: a 30x could bounce the probe to an internal
		// target AFTER the parse-time screen. Treat any redirect as a failure.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirect not allowed")
		},
		Transport: &http.Transport{
			// DialContext re-screens the resolved IP of the ACTUAL connection at
			// connect time — the anti-DNS-rebind control. It resolves the host,
			// screens every candidate IP, and dials only a screened one.
			DialContext:           v.guardedDial,
			TLSHandshakeTimeout:   directProbeTimeout,
			ResponseHeaderTimeout: directProbeTimeout,
			DisableKeepAlives:     true,
			MaxIdleConns:          1,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unreachable")
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, directProbeMaxBody))
	got := strings.TrimSpace(string(body))
	// Ownership proof: constant-time compare of the echoed nonce. Only a box that
	// actually served our probe over TLS saw the nonce, so echoing it proves
	// control of the endpoint.
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return "", fmt.Errorf("ownership proof failed")
	}
	return norm, nil
}

// guardedDial resolves the target host, screens EVERY resolved IP as public
// (unless allowInsecure), and dials the first screened address. If any resolved
// IP is internal the whole dial is refused — a hostname must not resolve to a
// private/loopback/metadata address (DNS-rebind defense at connect time).
func (v *httpDirectVerifier) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("bad addr")
	}
	if v.allowInsecure {
		// TEST-ONLY: dial as-is (httptest binds loopback).
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve failed")
	}
	// Refuse if ANY resolved IP is internal (defense-in-depth: a rebind attacker
	// may return one public + one internal answer; we take no chances).
	for _, ip := range ips {
		if !isPublicIP(ip.IP) {
			return nil, fmt.Errorf("resolves to non-public address")
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// normalizeDirectEndpoint parses + normalizes an advertised endpoint to
// "scheme://host[:port]" (no path/query/fragment, no trailing slash) and returns
// the host portion for screening. It enforces https (unless allowInsecure) and
// rejects any endpoint carrying a path/userinfo (which could smuggle a probe path
// or credentials).
func normalizeDirectEndpoint(endpoint string, allowInsecure bool) (normalized, host string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", "", fmt.Errorf("empty endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("invalid endpoint")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return "", "", fmt.Errorf("not https")
		}
	default:
		return "", "", fmt.Errorf("not https")
	}
	if u.User != nil {
		return "", "", fmt.Errorf("userinfo not allowed")
	}
	// A direct endpoint is a BASE URL only. Reject a path/query/fragment so a box
	// cannot advertise "https://victim/some/path" or smuggle anything.
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("endpoint must be a bare origin")
	}
	h := u.Hostname()
	if h == "" {
		return "", "", fmt.Errorf("no host")
	}
	// Rebuild a canonical origin (drops any trailing slash + default-port noise is
	// preserved as given, which is fine for the probe URL).
	normalized = u.Scheme + "://" + u.Host
	return normalized, h, nil
}

// screenPublicHost rejects a host FORM that is (or literally is) a non-public
// address. A bare hostname is allowed here (it is re-screened at resolve time by
// guardedDial); an IP LITERAL must be public. This is the parse-time half of the
// SSRF guard; guardedDial is the connect-time half.
func screenPublicHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("non-public address")
		}
		return nil
	}
	// A hostname literal. Reject obvious internal names outright; the real defense
	// is guardedDial re-screening the resolved IP.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".local") {
		return fmt.Errorf("internal hostname")
	}
	return nil
}

// isPublicIP reports whether ip is a globally-routable public address: NOT
// loopback, private (RFC1918), link-local, CGNAT (RFC6598 100.64/10), the cloud
// metadata IP (169.254.169.254 is link-local so already covered), IPv6 ULA
// (fc00::/7), unspecified, or multicast.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if ip.IsPrivate() { // RFC1918 v4 + ULA fc00::/7 v6
		return false
	}
	// CGNAT / shared address space 100.64.0.0/10 (RFC6598) — not IsPrivate() in Go.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		// 0.0.0.0/8 "this network".
		if v4[0] == 0 {
			return false
		}
	}
	return true
}
