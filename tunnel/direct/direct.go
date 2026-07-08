// Package direct is the CLIENT half of DIRECT-IP high-performance mode: the
// ICE-like negotiation a client uses to reach a Vulos box by its fastest working
// transport.
//
// A box may be reachable two ways:
//
//   - DIRECT: the box has a public/static IP or hostname and serves the OS on a
//     public TLS listener. A client that dials it gets NEAR-NATIVE latency and
//     FULL bandwidth — traffic never touches the relay (unmetered-by-relay by
//     design, since it is peer-direct).
//   - RELAY: the box reaches the relay over an outbound tunnel and the relay
//     proxies public requests into it. This ALWAYS works, even for NAT'd/CGNAT
//     boxes with no inbound reachability. It is the fallback / TURN-equivalent.
//
// Resolve asks the relay which transport to prefer, then Endpoint() /
// BaseURL(preferDirect) give the client a base URL to use. The client attempts
// DIRECT first and falls back to the RELAY URL on failure — the same app, the
// same auth, just a faster transport. The fallback is seamless: both URLs speak
// the identical OS HTTP API with the identical auth stack, so a client can retry a
// failed direct request against the relay URL with no code change beyond swapping
// the base URL.
//
// SECURITY: the relay only ever advertises a direct endpoint it independently
// verified (reachable + ownership-proven). A client should still pin/verify TLS to
// the box normally; a direct endpoint is a public HTTPS origin and the box's OWN
// auth stack gates every request there (direct is NOT a security downgrade).
package direct

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// resolveTimeout bounds the discovery lookup against the relay.
const resolveTimeout = 6 * time.Second

// Transport names the wire the client should use to reach the box.
type Transport string

const (
	// TransportDirect means dial the box's public endpoint directly (fast path).
	TransportDirect Transport = "direct"
	// TransportRelay means route through the relay tunnel (always-works fallback).
	TransportRelay Transport = "relay"
)

// Resolution is the outcome of asking the relay how to reach a box. It always
// carries a usable RelayURL (the box is reachable through the relay whenever it is
// online); DirectURL is set only when the relay has a VERIFIED direct endpoint.
type Resolution struct {
	// Name is the tunnel name resolved.
	Name string
	// RelayURL is the always-works base URL through the relay (e.g.
	// https://box1.relay.vulos.dev). Never empty on success.
	RelayURL string
	// DirectURL is the verified direct base URL, or "" when the box has no usable
	// direct endpoint (NAT'd/CGNAT/opted-out).
	DirectURL string
}

// HasDirect reports whether a direct fast-path is available.
func (r Resolution) HasDirect() bool { return strings.TrimSpace(r.DirectURL) != "" }

// Preferred returns the transport a client should ATTEMPT FIRST: direct when a
// verified direct endpoint exists, else relay.
func (r Resolution) Preferred() Transport {
	if r.HasDirect() {
		return TransportDirect
	}
	return TransportRelay
}

// BaseURL returns the base URL for a transport. For TransportDirect it returns
// DirectURL when available and otherwise falls back to RelayURL, so a caller that
// asks for direct but hits a box with none transparently gets the relay path.
func (r Resolution) BaseURL(t Transport) string {
	if t == TransportDirect && r.HasDirect() {
		return r.DirectURL
	}
	return r.RelayURL
}

// OrderedBaseURLs returns the base URLs to try IN ORDER: direct first (if any),
// then relay. A client walks this list, using the first URL that yields a working
// response, which is the ICE-like fallback in its simplest form. When there is no
// direct endpoint the list is just [relay], so behavior is identical to a
// relay-only client.
func (r Resolution) OrderedBaseURLs() []string {
	if r.HasDirect() {
		return []string{r.DirectURL, r.RelayURL}
	}
	return []string{r.RelayURL}
}

// relayResolveResponse mirrors the relay's directResolveResponse JSON.
type relayResolveResponse struct {
	Name           string `json:"name"`
	DirectEndpoint string `json:"directEndpoint"`
	Direct         bool   `json:"direct"`
}

// Resolver discovers a box's reachability against a relay. relayBase is the
// tunnel's relay base URL (e.g. https://box1.relay.vulos.dev) — the SAME URL the
// client would use to reach the box through the relay. HTTP is injectable for
// tests + custom TLS.
type Resolver struct {
	// HTTP is the client used for the discovery lookup; nil => a bounded default.
	HTTP *http.Client
}

// Resolve asks the relay (at relayBase) whether the box has a verified direct
// endpoint and returns a Resolution. relayBase MUST be the box's relay URL — the
// resolve lookup is host-routed to the tunnel name exactly like a normal request,
// so the relay resolves the same name the client would otherwise proxy to.
//
// On ANY discovery failure (relay down, non-200, decode error) Resolve returns a
// Resolution with only RelayURL set and a nil error: the relay path always works,
// so a failed direct-discovery must NEVER break reachability — it just means "no
// direct fast-path this time". This is what makes the fallback seamless.
func (rv *Resolver) Resolve(ctx context.Context, relayBase string) (Resolution, error) {
	relayBase = strings.TrimRight(strings.TrimSpace(relayBase), "/")
	if relayBase == "" {
		return Resolution{}, fmt.Errorf("direct: relayBase is required")
	}
	res := Resolution{RelayURL: relayBase}

	u, err := url.Parse(relayBase)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return res, fmt.Errorf("direct: invalid relayBase %q", relayBase)
	}
	u.Path = "/_vulos-direct/resolve"
	u.RawQuery = ""

	cctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return res, nil // fall back to relay-only; discovery is best-effort
	}
	resp, err := rv.httpClient().Do(req)
	if err != nil {
		return res, nil // relay unreachable for discovery ⇒ still return relay URL
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return res, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	var rr relayResolveResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return res, nil
	}
	res.Name = rr.Name
	if rr.Direct && strings.TrimSpace(rr.DirectEndpoint) != "" {
		// Only trust an https direct endpoint (no cleartext fast-path).
		if du, derr := url.Parse(rr.DirectEndpoint); derr == nil && du.Scheme == "https" {
			res.DirectURL = strings.TrimRight(rr.DirectEndpoint, "/")
		}
	}
	return res, nil
}

func (rv *Resolver) httpClient() *http.Client {
	if rv.HTTP != nil {
		return rv.HTTP
	}
	return &http.Client{Timeout: resolveTimeout}
}
