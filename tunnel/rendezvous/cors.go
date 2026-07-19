package rendezvous

import (
	"net/http"
	"strconv"
	"strings"
)

// cors.go — the browser-access policy for the RENDEZVOUS surface, and ONLY the
// rendezvous surface.
//
// WHY THIS EXISTS
//
// The rendezvous role is documented as an open reachability substrate: "point any
// app at any relayd and get P2P". Browsers are the primary client. Without CORS
// headers that promise was false — a page on https://app.example served by one
// origin cannot `fetch()` https://relay.example/rendezvous/ice or /announce at
// all: the preflight is answered 405 and the simple request is blocked by the
// user agent before the app ever sees a response ("Failed to fetch"). Every app
// therefore had to ship its own same-origin proxy in front of the relay, which
// defeats the point of a shared public substrate.
//
// THE POLICY, AND WHY IT IS SAFE
//
// Default: allow ANY origin, WITHOUT credentials.
//
//	Access-Control-Allow-Origin: *          (or the echoed origin when an
//	                                         allow-list is configured)
//	Access-Control-Allow-Methods: GET, POST, OPTIONS
//	Access-Control-Allow-Headers: Content-Type
//	Access-Control-Max-Age: 600
//	(Access-Control-Allow-Credentials is NEVER sent)
//
// This is deliberate, not a reflexive allow-all. The reasoning:
//
//  1. ORIGIN IS NOT THE SECURITY BOUNDARY HERE. Every rendezvous WRITE
//     (announce/withdraw/deposit/poll/ack) is authorized by an Ed25519 signature
//     over a domain-separated canonical message with a fresh timestamp and a
//     replay-guarded nonce. Authority comes from possession of a private key
//     carried in the request body — never from ambient authority attached by the
//     browser. A hostile page that can reach this endpoint gains exactly nothing
//     it could not get from `curl`: it still cannot forge a signature. CORS would
//     protect nothing; it only blocked the honest case.
//
//  2. CREDENTIALS ARE REFUSED, SO THERE IS NO CSRF SURFACE TO PROTECT. Because
//     Allow-Credentials is never sent, the browser strips cookies and HTTP auth
//     from these cross-origin requests. There is no ambient-authority request a
//     malicious origin could ride. (Sending `Allow-Origin: *` together with
//     credentials is forbidden by the spec anyway; we do not want credentials on
//     this surface in the first place — it has no cookie/session concept.)
//
//  3. THE READS ARE ALREADY PUBLIC. /ice returns STUN URLs plus short-lived TURN
//     credentials, /resolve returns self-signed public presence, /healthz is
//     liveness. These are open, unauthenticated reads by design (and /resolve can
//     be closed entirely with DisablePublicResolve). CORS-blocking a browser from
//     data any HTTP client can already read protected nothing.
//
//  4. ABUSE IS BOUNDED BY RATE LIMITS, NOT BY ORIGIN. Announce/deposit/poll are
//     rate-limited per signing key plus a global aggregate cap, and queue/presence
//     caps bound memory. An origin string is trivially forged by a non-browser
//     client, so it was never a usable throttle dimension.
//
// WHAT THIS DOES NOT COVER — and this matters. This middleware is applied by the
// rendezvous Service to its OWN handler only. The relay's tunnel/proxy paths, the
// control plane, and the admin//metrics listener get NO CORS headers from here and
// must keep getting none: those DO carry ambient authority (agent tokens, operator
// credentials, and proxied app cookies belonging to the tunneled box), so
// cross-origin reads there are exactly what the same-origin policy should stop.
// tunnel/server mounts this Service under its prefix on the apex host only; the
// per-tunnel subdomains keep full control of their own paths.
//
// OPERATOR OVERRIDE. Config.AllowedOrigins narrows the default. When set, only a
// listed origin is echoed back (with `Vary: Origin` so a shared cache cannot serve
// one origin's response to another), and an unlisted origin simply gets no CORS
// headers — the browser then blocks it. This exists for operators who want their
// node used only by their own apps. It is a courtesy/traffic-shaping control, NOT
// a security control, for reason (1) above: a non-browser client ignores it
// entirely. Never treat an allow-list here as an access-control mechanism.

// corsMaxAgeSeconds is how long a browser may cache a preflight result. Ten
// minutes: long enough that a chatty polling client is not re-preflighting
// constantly, short enough that a policy change takes effect promptly.
const corsMaxAgeSeconds = 600

// allowedMethods / allowedHeaders are the fixed capability set of this surface.
// Every rendezvous route is a GET or a POST with a JSON body, so Content-Type is
// the only non-simple request header a client needs.
const (
	corsAllowMethods = "GET, POST, OPTIONS"
	corsAllowHeaders = "Content-Type"
)

// withCORS wraps h with the rendezvous CORS policy documented above and answers
// preflight requests itself.
//
// Preflight handling is done HERE rather than by registering `OPTIONS` routes on
// the mux because Go's ServeMux answers an unregistered method on a registered
// path with 405 — which is precisely the failure a browser reported. Any OPTIONS
// under this handler that carries Access-Control-Request-Method is answered 204
// with the policy headers. Acknowledging a preflight for a path that turns out not
// to exist is harmless: the browser then sends the real request and gets the
// normal 404/405 from the mux, with CORS headers attached so the app can actually
// SEE that status instead of an opaque network error.
func (s *Service) withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		allowed := s.corsAllowOrigin(origin)

		if allowed != "" {
			hdr := w.Header()
			hdr.Set("Access-Control-Allow-Origin", allowed)
			// NOTE: Access-Control-Allow-Credentials is intentionally never set.
			// See the policy note at the top of this file — this surface has no
			// cookie/session concept and must not accept ambient authority.
			if allowed != "*" {
				// The response now depends on the request's Origin, so any shared
				// cache must key on it.
				hdr.Add("Vary", "Origin")
			}
		}

		// Preflight: answer here, never fall through to the mux (405).
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if allowed == "" {
				// Origin not permitted by the operator's allow-list. Reply without
				// CORS headers; the browser fails the preflight, which is the
				// intended outcome.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			hdr := w.Header()
			hdr.Set("Access-Control-Allow-Methods", corsAllowMethods)
			hdr.Set("Access-Control-Allow-Headers", corsAllowHeaders)
			hdr.Set("Access-Control-Max-Age", strconv.Itoa(corsMaxAgeSeconds))
			hdr.Add("Vary", "Access-Control-Request-Method")
			hdr.Add("Vary", "Access-Control-Request-Headers")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// corsAllowOrigin decides the Access-Control-Allow-Origin value for a request.
// Returns "" when no CORS headers should be emitted at all.
//
//   - No Origin header (a non-browser client, or a same-origin navigation): "" —
//     nothing to negotiate, and emitting a wildcard on every response would be
//     noise.
//   - No allow-list configured (the default): "*" — any origin, no credentials.
//   - Allow-list configured: the origin echoed back if it matches exactly
//     (case-insensitive on scheme/host, as origins are), else "".
func (s *Service) corsAllowOrigin(origin string) string {
	if origin == "" {
		return ""
	}
	if len(s.corsOrigins) == 0 {
		return "*"
	}
	for _, a := range s.corsOrigins {
		if strings.EqualFold(a, origin) {
			return origin
		}
	}
	return ""
}

// normalizeOrigins trims and drops empty entries from a configured allow-list. A
// literal "*" anywhere collapses to the permissive default (nil).
func normalizeOrigins(in []string) []string {
	out := make([]string, 0, len(in))
	for _, o := range in {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if o == "*" {
			return nil
		}
		out = append(out, strings.TrimSuffix(o, "/"))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
