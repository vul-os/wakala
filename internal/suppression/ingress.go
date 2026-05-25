// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package suppression

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

// IngressPath is the HTTP path the report-intake handler is mounted at.
const IngressPath = "/reports"

// ReportAuthenticator authenticates an inbound report submission and returns the
// account the submitter is allowed to file reports for. A non-empty accountID
// with a nil error means the request is authenticated AND scoped to that
// account: a report may ONLY suppress recipients for that account, never another
// account's and never globally.
//
// The relay wires this to the SAME shared-secret/HMAC (or operator-allowlist)
// surface the rest of the cp↔relay HTTP API uses, so the report intake is no
// longer an unauthenticated, globally-scoped suppression sink (the CRITICAL
// denial-of-delivery / suppression-poisoning finding).
type ReportAuthenticator interface {
	// AuthenticateReport verifies the request and returns the scoping account ID.
	// On failure it returns a non-nil error and the handler responds 401.
	AuthenticateReport(r *http.Request) (accountID string, err error)
}

// RateLimiter is the minimal per-IP limiter seam. *relay.IPRateLimiter
// satisfies it; the relay wiring reuses that limiter so the report intake shares
// the same anonymous-flood protection as /submit.
type RateLimiter interface {
	// Allow reports whether a request from ip may proceed (and counts it).
	Allow(ip string) bool
}

// ClientIPFunc extracts the client IP from a request for rate limiting. The
// relay wires this to relay.ClientIP (connection RemoteAddr, never a spoofable
// X-Forwarded-For).
type ClientIPFunc func(r *http.Request) string

// IngressConfig configures the report-intake HTTP handler.
type IngressConfig struct {
	// List is the suppression list reports feed into. REQUIRED.
	List *List

	// Authenticator authenticates the request and returns the scoping account.
	// REQUIRED for the HTTP path: without it the handler refuses every request
	// (fail-closed) so the report intake is never an open suppression sink.
	// ProcessReport (the mailbox-processor path) does not consult it.
	Authenticator ReportAuthenticator

	// RateLimiter, when non-nil, caps report submissions per client IP BEFORE
	// authentication, mirroring the /submit gate.
	RateLimiter RateLimiter

	// ClientIP extracts the client IP for the rate limiter. Defaults to the
	// connection RemoteAddr host.
	ClientIP ClientIPFunc

	// MaxBodyBytes caps the inbound report body size. 0 → 1 MiB default.
	MaxBodyBytes int64

	// Logger is used for operational messages. If nil, the standard logger.
	Logger *log.Logger
}

// IngressHandler is the http.Handler that accepts inbound DSN/ARF reports and
// feeds the suppression list. It accepts a raw RFC-822 report POSTed as
// message/rfc822 (or any body — the parser sniffs the content).
//
// The HTTP path is AUTHENTICATED and per-account scoped: the request must carry
// a valid credential for the SAME cp↔relay surface as /submit, and the report
// only ever suppresses recipients for the authenticated account. Operators who
// instead pull reports from a postmaster@/abuse@ mailbox call ProcessReport
// directly per message, supplying the owning account explicitly.
type IngressHandler struct {
	cfg IngressConfig
}

// NewIngressHandler builds an IngressHandler. It panics if List is nil — wiring
// an intake with no destination is a programmer error.
func NewIngressHandler(cfg IngressConfig) *IngressHandler {
	if cfg.List == nil {
		panic("suppression: IngressHandler requires a non-nil List")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20 // 1 MiB
	}
	return &IngressHandler{cfg: cfg}
}

func (h *IngressHandler) logger() *log.Logger {
	if h.cfg.Logger != nil {
		return h.cfg.Logger
	}
	return log.Default()
}

func (h *IngressHandler) clientIP(r *http.Request) string {
	if h.cfg.ClientIP != nil {
		return h.cfg.ClientIP(r)
	}
	return r.RemoteAddr
}

// ingressResponse is the JSON response shape.
type ingressResponse struct {
	Account      string     `json:"account"`
	Kind         ReportKind `json:"kind"`
	Suppressed   int        `json:"suppressed"`
	HardBounces  []string   `json:"hard_bounces,omitempty"`
	Complaints   []string   `json:"complaints,omitempty"`
	SoftFailures []string   `json:"soft_failures,omitempty"`
}

// ServeHTTP implements http.Handler. Only authenticated POSTs are accepted.
func (h *IngressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is accepted", http.StatusMethodNotAllowed)
		return
	}

	// 0. Per-IP rate cap — enforced BEFORE authentication so an unauthenticated
	// flood from one source cannot exhaust the relay or the auth/parse path.
	if h.cfg.RateLimiter != nil {
		ip := h.clientIP(r)
		if !h.cfg.RateLimiter.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "per-IP report rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	// 1. Authenticate + scope. Fail closed: no authenticator wired → refuse
	// everything (never an open, globally-scoped suppression sink).
	if h.cfg.Authenticator == nil {
		h.logger().Printf("suppression: report intake rejected — no authenticator configured (fail-closed)")
		http.Error(w, "report intake not configured for authenticated access", http.StatusUnauthorized)
		return
	}
	account, authErr := h.cfg.Authenticator.AuthenticateReport(r)
	if authErr != nil || account == "" {
		msg := "unauthenticated report submission refused"
		if authErr != nil {
			msg = authErr.Error()
		}
		http.Error(w, msg, http.StatusUnauthorized)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxBodyBytes+1))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if int64(len(raw)) > h.cfg.MaxBodyBytes {
		http.Error(w, "report body too large", http.StatusRequestEntityTooLarge)
		return
	}

	report, n, perr := h.ProcessReport(account, raw)
	if perr != nil {
		// A parse failure is a client problem (malformed report) — 400.
		h.logger().Printf("suppression: report parse failed (account=%s): %v", account, perr)
		http.Error(w, "report parse failed: "+perr.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ingressResponse{
		Account:      account,
		Kind:         report.Kind,
		Suppressed:   n,
		HardBounces:  report.HardBounces,
		Complaints:   report.Complaints,
		SoftFailures: report.SoftFailures,
	})
}

// ProcessReport parses a single raw report and applies it to the suppression
// list SCOPED to account, returning the parsed report and the number of
// addresses newly suppressed. It is the mailbox-processor entry point (call it
// per message fetched from a postmaster@/abuse@ mailbox, passing the account the
// mailbox belongs to). A report applied this way can never suppress a recipient
// for any other account.
func (h *IngressHandler) ProcessReport(account string, raw []byte) (ParsedReport, int, error) {
	report, err := ParseReport(raw)
	if err != nil {
		return report, 0, err
	}
	n := report.ApplyTo(account, h.cfg.List)
	if n > 0 {
		h.logger().Printf("suppression: %s report suppressed %d recipient(s) for account %s (hard_bounces=%d complaints=%d)",
			report.Kind, n, account, len(report.HardBounces), len(report.Complaints))
	}
	return report, n, nil
}
