package server

// direct.go — DIRECT-IP: the client-facing direct-endpoint DISCOVERY surface on
// the relay's public listener, plus helpers.
//
// A client that is about to reach a box THROUGH the relay first asks the relay
// "does this tunnel have a verified direct endpoint I can dial instead?". If so it
// attempts a direct connection (near-native latency + full bandwidth) and falls
// back to the relay tunnel on any failure (ICE-like: try direct, fall back to
// relay-as-TURN). This file serves that lookup. The negotiation/fallback CLIENT
// logic lives in tunnel/direct (a separate package clients import).
//
// The relay NEVER returns an endpoint it did not itself verify: session
// .directEndpoint is only ever set from verifyDirectEndpoint at register time.
// So a box cannot get the relay to hand clients an endpoint it doesn't control.

import (
	"encoding/json"
	"net/http"
)

// wireDirectResolvePath is the relay route a client GETs (host-routed to a tunnel
// name, like any public request) to discover the tunnel's verified direct
// endpoint. Kept distinct from wire.DirectProbePath (which the RELAY calls on the
// BOX). It is served on the public listener but returns only public routing info.
const wireDirectResolvePath = "/_vulos-direct/resolve"

// directResolveResponse is the JSON a client receives from the resolve endpoint.
type directResolveResponse struct {
	// Name is the resolved tunnel name (echoed for clarity).
	Name string `json:"name"`
	// DirectEndpoint is the box's VERIFIED direct endpoint, or "" when the box has
	// none (NAT'd/CGNAT/opted-out) — in which case the client uses the relay tunnel.
	DirectEndpoint string `json:"directEndpoint,omitempty"`
	// Direct reports whether a usable direct endpoint is available (== DirectEndpoint
	// != ""). A client reads this to decide whether to attempt a direct dial at all.
	Direct bool `json:"direct"`
}

// handleDirectResolve answers the direct-endpoint discovery lookup. It resolves
// the tunnel name from the request (same host/path routing as any public request)
// and returns the session's verified direct endpoint, if any. Unknown/offline
// tunnels return direct=false (never an error the caller must special-case — the
// client just falls back to the relay path).
func (s *Server) handleDirectResolve(w http.ResponseWriter, r *http.Request) {
	// Direct negotiation disabled ⇒ always report "no direct" so clients use the
	// relay path unchanged (config-gated off => pure relay behavior).
	if s.directVerifier == nil {
		writeDirectResolve(w, directResolveResponse{Direct: false})
		return
	}
	name, _, matched := s.route(r)
	if !matched {
		writeDirectResolve(w, directResolveResponse{Direct: false})
		return
	}
	resp := directResolveResponse{Name: name}
	if sess, ok := s.registry.lookup(name); ok && sess.directEndpoint != "" {
		resp.DirectEndpoint = sess.directEndpoint
		resp.Direct = true
	}
	writeDirectResolve(w, resp)
}

func writeDirectResolve(w http.ResponseWriter, resp directResolveResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
