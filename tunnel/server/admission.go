package server

import (
	"net/http"
)

// admission.go — CONNECTION-FLOOD ADMISSION CONTROL for the internet-facing relay.
//
// The relay carries STATEFUL, sticky yamux tunnels: setting one up costs a WS
// upgrade, a register-frame read, a token-authorize (constant-time), a CP
// entitlement round-trip, and a yamux session with its buffers. A FLOOD of connect
// attempts — malicious (DoS) OR self-inflicted (a mass reconnect storm when a peer
// PoP drains/dies) — must therefore be rejected on the CHEAPEST possible path,
// BEFORE any of that work is spent, or a PoP can be driven to OOM / collapse.
//
// This file layers admission on top of the existing per-IP control limiter and the
// hard MaxAgents cap, in strict cheap→expensive order:
//
//	 (pre-upgrade, no bytes read yet)
//	  1. per-source-IP NEW-connection rate  (ctrlLimiter)      → 429
//	  2. aggregate NEW-connection rate       (globalConnLimiter)→ 429  (bounds a
//	     distributed flood from many IPs, each under the per-IP limit)
//	  3. missing bearer                                          → 401
//	  4. hard MaxAgents cap reached          (registry.count)   → 503 shed (retryable)
//	  5. saturation shed threshold reached   (SoftCapacity)     → 503 shed (retryable)
//	  6. PoP draining                                           → 503 shed (retryable)
//	 (post-auth, account known, still BEFORE yamux setup)
//	  7. per-ACCOUNT NEW-connection rate     (acctConnLimiter)  → 429
//
// A "shed" (4/5/6) is a graceful, RETRYABLE refusal: the ack carries Retryable=true
// so the agent re-resolves its assigned PoP (the CP steers new tunnels elsewhere,
// because the saturation/draining signal is in the heartbeat) and retries with
// jittered backoff — no thundering herd, no OOM, and every LIVE tunnel stays up.
//
// All limiters are memory-bounded (token buckets with idle eviction + a max-keys
// cap) and every check is O(1), so the admission path itself cannot be turned into
// an amplification vector.

// admitVerdict is the outcome of the cheap pre-upgrade admission gate. When ok is
// false the caller must reject WITHOUT upgrading the connection.
type admitVerdict struct {
	ok         bool
	httpStatus int              // status for the pre-upgrade HTTP rejection
	message    string           // short client-facing reason (never leaks internals)
	reason     authFailReason   // auth-failure metric bucket
	surface    ctrlLimitSurface // rate-limit surface (only set for a rate-limit reject)
	retryAfter string           // Retry-After header value ("" => none)
}

// admitControlConn is the CHEAP pre-upgrade admission gate. It runs before the WS
// upgrade + register read so a flood is shed for the price of a map lookup and a
// couple of atomic loads — never a tunnel/yamux setup. A nil/zero limiter is a
// no-op (self-host is unchanged).
func (s *Server) admitControlConn(r *http.Request) admitVerdict {
	ip := s.clientIP(r)

	// 1. Per-source-IP NEW-connection rate. Throttles one abusive source before we
	//    spend anything on it.
	if !s.ctrlLimiter.allow(ip) {
		return admitVerdict{httpStatus: http.StatusTooManyRequests, message: "too many control-connection attempts", reason: authFailRateLimited, surface: limitControl, retryAfter: "1"}
	}

	// 2. Aggregate NEW-connection rate across ALL sources. A distributed flood (many
	//    IPs, each under the per-IP limit) is bounded here so the PoP cannot be made
	//    to spend an upgrade + register-read per attempt.
	if !s.globalConnLimiter.allow() {
		return admitVerdict{httpStatus: http.StatusTooManyRequests, message: "relay busy (connection rate limited)", reason: authFailRateLimited, surface: limitGlobalConn, retryAfter: "1"}
	}

	// 3. Missing bearer: reject before the upgrade (anonymous clients cost nothing).
	if bearer(r) == "" {
		return admitVerdict{httpStatus: http.StatusUnauthorized, message: "unauthorized", reason: authFailNoBearer}
	}

	// 4. Hard MaxAgents cap: if we are already full, SHED cheaply (503, retryable)
	//    rather than upgrade + read + authorize only to fail in registry.add. The
	//    agent re-resolves to another PoP. registry.add re-checks under its lock as a
	//    race backstop.
	if s.atHardCap() {
		return admitVerdict{httpStatus: http.StatusServiceUnavailable, message: "relay at capacity, try another PoP", reason: authFailCapacity, retryAfter: "2"}
	}

	// 5. Saturation shed: at/above the soft threshold, protect the node by refusing
	//    NEW tunnels while keeping live ones up. Fires before the hard cap so the
	//    autoscaler (fed by the same saturation signal) has time to add a node.
	if s.saturationShed() {
		return admitVerdict{httpStatus: http.StatusServiceUnavailable, message: "relay saturated, try another PoP", reason: authFailSaturation, retryAfter: "2"}
	}

	// 6. Draining: a PoP being decommissioned refuses new tunnels (retryable). This
	//    mirrors the explicit draining check that also runs post-register; doing it
	//    here too sheds a drain-time flood before the upgrade.
	if s.draining.Load() {
		return admitVerdict{httpStatus: http.StatusServiceUnavailable, message: "relay draining, try another PoP", reason: authFailDraining, retryAfter: "2"}
	}

	return admitVerdict{ok: true}
}

// atHardCap reports whether the live agent count has reached the hard MaxAgents cap.
// Cheap (an RLock + len). MaxAgents<=0 means "no cap" (never full).
func (s *Server) atHardCap() bool {
	return s.cfg.MaxAgents > 0 && s.registry.count() >= s.cfg.MaxAgents
}

// saturationShed reports whether the node is at/above its shedding threshold. It is
// only meaningful when a SoftCapacity is configured (otherwise SaturationRatio is 0)
// and the threshold is enabled (>0). Keeping live tunnels up while refusing new ones
// is the graceful-degradation contract.
func (s *Server) saturationShed() bool {
	if s.cfg.SheddingThreshold <= 0 {
		return false
	}
	return s.SaturationRatio() >= s.cfg.SheddingThreshold
}

// recordAdmissionReject records the metrics + a debug log for a pre-upgrade
// admission rejection. Rate-limit rejects bump both the rate-limit surface counter
// and the auth-fail bucket; sheds bump only the auth-fail bucket. Nothing
// attacker-controlled is logged as a metric label (cardinality stays bounded).
func (s *Server) recordAdmissionReject(r *http.Request, v admitVerdict) {
	if v.surface != "" {
		s.metrics.rateLimitReject(v.surface)
	}
	s.metrics.authFail(v.reason)
	s.logDebug("control connection rejected at admission", logFields{
		Remote: s.clientIP(r),
		Reason: string(v.reason),
	})
}

// admitAccountConnect applies the per-ACCOUNT NEW-connection rate limit. It runs
// AFTER the token authorizes (so the account is known) but BEFORE yamux setup, so a
// single tenant's reconnect burst is bounded without spending a session on it. An
// empty account (unbilled/self-host token) is not keyed. Returns true to admit.
func (s *Server) admitAccountConnect(accountID string) bool {
	if accountID == "" {
		return true
	}
	return s.acctConnLimiter.allow(accountID)
}

// allowDirectProbe applies the per-account (per-name for unbilled) direct-endpoint
// probe budget — the probe-reflection guard. It bounds how often a box can make the
// relay emit an outbound endpoint-verification GET on its behalf, so a re-register
// loop advertising a fresh endpoint each time cannot use the relay as a GET reflector
// (the probe is already SSRF-screened to public hosts; this bounds its RATE). Keyed
// on the account when billed, else the tunnel name so unbilled self-host is also
// bounded. A nil/disabled limiter allows everything. Returns true to permit the probe.
func (s *Server) allowDirectProbe(accountID, name string) bool {
	key := accountID
	if key == "" {
		key = "name:" + name
	}
	return s.directProbeLimiter.allow(key)
}
