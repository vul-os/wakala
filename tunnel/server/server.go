// Package server is the sovereign Vulos relay: the public half of the reverse
// tunnel. It replaces a third-party frp server with our own, self-hostable relay.
//
// It runs TWO logical surfaces on one HTTPS listener:
//
//  1. Control endpoint (wire.ControlPath): agents dial in over wss, authenticate
//     with a bearer token, and register a token-authorized name. The server then
//     becomes the yamux CLIENT over that connection and opens one stream per
//     inbound public request.
//
//  2. Public proxy: inbound HTTPS requests are routed to an agent session by
//     subdomain (<name>.<relay-domain>, the primary mode, needs wildcard DNS) or by
//     path prefix (/t/<name>/…, the fallback when no wildcard DNS). Matched
//     requests are forwarded over a fresh yamux stream and the response streamed
//     back, including WebSocket-upgrade passthrough.
//
// The server is internet-facing and fails closed: no token store => refuses to
// run; unknown/unauthorized tokens are rejected; names cannot be hijacked; request
// sizes, header sizes, stream counts, and agent counts are all bounded.
package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config configures a relay Server.
type Config struct {
	// Domain is the base relay domain, e.g. "relay.vulos.dev". In subdomain mode a
	// name "box1" is served at "box1.relay.vulos.dev". Used to derive names from the
	// inbound Host and to build public URLs. Required.
	Domain string
	// Tokens is the authorization store. Required — a nil store means "run open",
	// which is refused.
	Tokens TokenStore

	// EnablePathMode serves the /t/<name>/ fallback in addition to subdomain mode.
	// Enable when you cannot provision wildcard DNS. Default false.
	EnablePathMode bool

	// TLS is the public listener's TLS. If nil, ServeTLS/certFile is expected, or
	// the caller runs behind a TLS-terminating proxy and uses Serve (plain h1). For
	// a directly-internet-facing relay, provide TLS or use ListenAndServeTLS.
	TLSConfig *tls.Config

	// Public URL scheme for building agent-facing URLs. Default "https".
	PublicScheme string

	// Limits (0 => sane defaults applied in New).
	MaxAgents          int           // max concurrent agents
	MaxStreamsPerAgent int           // max concurrent in-flight streams per agent
	MaxHeaderBytes     int           // request header size cap
	MaxRequestBytes    int64         // request body size cap
	IdleTimeout        time.Duration // control-conn idle timeout / keepalive budget
	RequestTimeout     time.Duration // per public request forward timeout

	// CP (WAVE24-RELAY-BILLING, optional) links this relay to Vulos Cloud so that
	// account-bound tokens are gated against their relay entitlement and their
	// traffic is metered to POST /api/relay/usage. When nil, the relay runs
	// UNBILLED (self-host): tokens are still authorized (name grants) but no
	// account gating or metering happens.
	CP *CPClient
	// GateTTL is the entitlement-cache TTL (default 30s). EntitlementFlush is the
	// usage-report cadence (default 45s).
	GateTTL          time.Duration
	MeterFlushPeriod time.Duration

	// Rate limiting (WAVE34-RELAY-HARDEN). All optional; 0 => sane defaults are
	// applied in New. Set a rate to a negative value to DISABLE that limiter
	// (useful for tests or a trusted-edge deployment). These are ON TOP OF the
	// existing hard caps (MaxAgents, MaxStreamsPerAgent), which stay intact.

	// ControlConnRate / ControlConnBurst throttle control-connection attempts per
	// source IP (token bucket). Defaults: 5/s, burst 20.
	ControlConnRate  float64
	ControlConnBurst float64
	// PublicReqRate / PublicReqBurst throttle inbound public requests per
	// agent/session (token bucket). Defaults: 50/s, burst 100.
	PublicReqRate  float64
	PublicReqBurst float64
	// GlobalReqRate / GlobalReqBurst cap the AGGREGATE inbound public request rate
	// across all tunnels. Defaults: 500/s, burst 1000.
	GlobalReqRate  float64
	GlobalReqBurst float64
	// RateLimitIdleTTL evicts a per-key bucket unused for this long (bounds
	// memory). Default 10m.
	RateLimitIdleTTL time.Duration
	// RateLimitMaxKeys caps distinct buckets per limiter (bounds memory).
	// Default 100_000.
	RateLimitMaxKeys int
}

// rateLimitField resolves a configured rate: 0 => the supplied default, a
// negative value => 0 (disabled).
func rateLimitField(v, def float64) float64 {
	switch {
	case v < 0:
		return 0
	case v == 0:
		return def
	default:
		return v
	}
}

func (c *Config) applyDefaults() {
	if c.PublicScheme == "" {
		c.PublicScheme = "https"
	}
	if c.MaxAgents == 0 {
		c.MaxAgents = 256
	}
	if c.MaxStreamsPerAgent == 0 {
		c.MaxStreamsPerAgent = 128
	}
	if c.MaxHeaderBytes == 0 {
		c.MaxHeaderBytes = 64 << 10 // 64 KiB
	}
	if c.MaxRequestBytes == 0 {
		c.MaxRequestBytes = 32 << 20 // 32 MiB
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 90 * time.Second
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 60 * time.Second
	}
	// Rate-limit defaults (WAVE34-RELAY-HARDEN). A negative value means "disabled"
	// and is normalized to 0 by rateLimitField at construction time.
	c.ControlConnRate = rateLimitField(c.ControlConnRate, 5)
	c.ControlConnBurst = rateLimitField(c.ControlConnBurst, 20)
	c.PublicReqRate = rateLimitField(c.PublicReqRate, 50)
	c.PublicReqBurst = rateLimitField(c.PublicReqBurst, 100)
	c.GlobalReqRate = rateLimitField(c.GlobalReqRate, 500)
	c.GlobalReqBurst = rateLimitField(c.GlobalReqBurst, 1000)
	if c.RateLimitIdleTTL == 0 {
		c.RateLimitIdleTTL = 10 * time.Minute
	}
	if c.RateLimitMaxKeys == 0 {
		c.RateLimitMaxKeys = 100_000
	}
}

// Server is the relay. Construct with New, then use Handler() / ListenAndServe*.
type Server struct {
	cfg      Config
	registry *registry
	gate     *entitlementGate // account relay-entitlement gate (no-op when CP nil)
	meter    *meter           // per-account usage meter (no-op when CP nil)

	// Rate limiters (WAVE34-RELAY-HARDEN). Nil => disabled (allow all).
	ctrlLimiter   *rateLimiter       // control-conn attempts per source IP
	reqLimiter    *rateLimiter       // public requests per agent/session
	globalLimiter *globalRateLimiter // aggregate public request cap
}

// New validates config and returns a Server. It fails closed: a missing token
// store or domain is an error rather than an open relay.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, fmt.Errorf("relay: Domain is required")
	}
	if cfg.Tokens == nil {
		return nil, fmt.Errorf("relay: a TokenStore is required (refusing to run open)")
	}
	cfg.applyDefaults()
	s := &Server{
		cfg:      cfg,
		registry: newRegistry(cfg.MaxAgents),
		gate:     newEntitlementGate(cfg.CP, cfg.GateTTL),
		meter:    newMeter(cfg.CP, cfg.MeterFlushPeriod),

		ctrlLimiter:   newRateLimiter(cfg.ControlConnRate, cfg.ControlConnBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		reqLimiter:    newRateLimiter(cfg.PublicReqRate, cfg.PublicReqBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		globalLimiter: newGlobalRateLimiter(cfg.GlobalReqRate, cfg.GlobalReqBurst),
	}
	// WAVE34-RELAY-HARDEN: let the usage-flush loop feed the CP's over-quota
	// verdict straight into the entitlement gate, so an over-cap account is cut
	// on its next request (402) rather than surviving until the gate TTL lapses.
	s.meter.onOverQuota = s.gate.markOverQuota
	// Start the background usage-flush loop (no-op when unbilled).
	s.meter.run()
	return s, nil
}

// Close stops background loops and performs a final usage flush. Safe to call
// once after the HTTP server has stopped accepting new connections.
func (s *Server) Close() {
	if s.meter != nil {
		s.meter.stopAndFlush()
	}
}

// Handler returns the http.Handler serving BOTH the control endpoint and the
// public proxy. Mount it directly, or wrap it (e.g. access logging).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wireControlPath, s.handleControl)
	mux.HandleFunc("/", s.handlePublic)
	return mux
}

// httpServer builds an *http.Server with the security-relevant timeouts/caps set.
func (s *Server) httpServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		TLSConfig:         s.cfg.TLSConfig,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       s.cfg.IdleTimeout,
		// No WriteTimeout: tunneled responses (SSE, WS, downloads) are long-lived.
	}
}

// ListenAndServeTLS runs the relay as a directly-internet-facing HTTPS server.
func (s *Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	return s.httpServer(addr).ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServe runs the relay as plain HTTP — ONLY for use behind a TLS-
// terminating proxy/CDN (which is the recommended edge-friendly deployment) or in
// tests. Do not expose this directly to the internet.
func (s *Server) ListenAndServe(addr string) error {
	return s.httpServer(addr).ListenAndServe()
}

// AgentCount returns the number of live agent sessions (for /healthz or metrics).
func (s *Server) AgentCount() int { return s.registry.count() }
