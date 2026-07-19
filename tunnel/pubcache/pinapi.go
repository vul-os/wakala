package pubcache

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/keyauth"
)

// pinapi.go — the pin MANAGEMENT surface.
//
//	POST {p}/pin          signed   pin an announce/manifest (+ its chunk set)
//	POST {p}/unpin        signed   remove a pin, reclaim unreferenced bytes
//	GET  {p}/pins         public   what this holder retains
//	GET  {p}/pins/status  public   usage vs budget, and the billing counters
//
// ── Why writes are signed and reads are not ─────────────────────────────────
//
// § 22 reads are anonymous by protocol requirement: a public object is public,
// and a holder that demanded identity to serve one would be adding a gate the
// spec does not have. So the read surface — including reads of PINNED objects —
// stays exactly as open as it was.
//
// A write is different in kind. `pin` spends the operator's disk, durably, and
// disk is the scarce thing this role sells. An unauthenticated pin endpoint is a
// remote "fill this disk" primitive. So writes carry the same signed-request
// discipline as the rendezvous role's writes — an Ed25519 signature over a
// domain-separated, length-prefixed canonical message, with a timestamp inside
// the clock-skew window and a nonce that has not been seen — via the shared
// tunnel/internal/keyauth, so the two surfaces cannot drift apart.
//
// Signature alone is not authorisation, though: any key can produce a valid
// signature over its own request. Authorisation is an operator-configured
// ALLOWLIST of pinner keys (PinKeys), and it is empty by default, so a node that
// turns on durable pinning without naming anyone still refuses every write. That
// allowlist is also the seam a billing layer drives: the control plane adds a
// key when a customer buys storage and drops it when they stop paying. No
// billing logic lives here — this daemon only ever answers "is this key on the
// list?".
//
// ── The listing views are public on purpose ─────────────────────────────────
//
// `pins` and `pins/status` expose content addresses, sizes, owner keys, and
// aggregate usage. Every one of those is already a public fact about public
// objects — anyone can discover what a holder serves by asking it for things —
// so authenticating the view would buy no confidentiality while making the role
// harder to monitor. Operators and clients both benefit from a holder that is
// legible about what it retains.

// pin API canonical signing domains. They must match docs/PINNING.md exactly.
const (
	domainPin   = "vulos-pub/pin/1"
	domainUnpin = "vulos-pub/unpin/1"
)

// maxPinRequestBody bounds a management request body. These carry a key, an
// address, a nonce, and a signature — nothing large — so the cap is tight.
const maxPinRequestBody = 8 << 10

// keyEq is the constant-time canonical-key comparison used for pin ownership.
func keyEq(a, b string) bool { return keyauth.KeyEqual(a, b) }

// pinRequest is the body of both POST {p}/pin and POST {p}/unpin.
type pinRequest struct {
	// Key is the base64url Ed25519 public key of the requester (and, for a pin,
	// the owner recorded against it).
	Key string `json:"key"`
	// Kind is "announce" or "manifest". A chunk cannot be pinned on its own:
	// chunks are pinned as part of the manifest that gives them meaning, so a
	// pin is always a complete, self-contained object.
	Kind string `json:"kind"`
	// Addr is the canonical unpadded-base64url content address of the root.
	Addr      string `json:"addr"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"ts"`
	Sig       string `json:"sig"`
}

// pinSigningMessage builds the canonical message a pin/unpin signature covers.
// Field order: key, ts, nonce, kind, addr. Reproduced byte-for-byte by any
// client per docs/PINNING.md.
func pinSigningMessage(domain string, req *pinRequest) []byte {
	return keyauth.CanonicalMessage(domain,
		req.Key, strconv.FormatInt(req.Timestamp, 10), req.Nonce, req.Kind, req.Addr)
}

// parseKind maps the wire kind name onto a Kind. Only the two ROOT kinds are
// pinnable (see pinRequest.Kind).
func parseKind(s string) (Kind, bool) {
	switch s {
	case "announce":
		return KindAnnounce, true
	case "manifest":
		return KindManifest, true
	}
	return 0, false
}

// pinErrorCode maps a pin failure onto a stable, machine-readable code so a
// client (or a billing layer) can distinguish "you are out of quota" from "you
// are not allowed" without parsing prose. This is the typed refusal the budget
// design promises: a full store says so, explicitly.
func pinErrorCode(err error) (int, string) {
	switch {
	case errors.Is(err, ErrPinBudget):
		// 507 Insufficient Storage is the honest status: the request was valid
		// and the node simply has no room. Nothing was evicted to make some.
		return http.StatusInsufficientStorage, "pin_budget_exceeded"
	case errors.Is(err, ErrPinNotFound):
		return http.StatusNotFound, "pin_not_found"
	case errors.Is(err, ErrPinForbidden):
		return http.StatusForbidden, "pin_not_owned"
	case errors.Is(err, ErrPinDisabled):
		return http.StatusNotImplemented, "pin_disabled"
	case errors.Is(err, ErrAddrMismatch), errors.Is(err, ErrMalformedObject), errors.Is(err, ErrManifestKeyPresent):
		return http.StatusUnprocessableEntity, "object_failed_verification"
	case errors.Is(err, ErrNotServed):
		return http.StatusNotFound, "object_not_retrievable"
	}
	return http.StatusInternalServerError, "pin_failed"
}

func writePinErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": code, "message": msg})
}

func writePinJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// authorizePin runs the full signed-write gate and returns the canonical key on
// success. Every failure is a refusal; none of them is recoverable by retrying
// the same bytes.
func (s *Service) authorizePin(w http.ResponseWriter, r *http.Request, domain string, req *pinRequest) (string, bool) {
	if s.pins == nil {
		writePinErr(w, http.StatusNotImplemented, "pin_disabled", "this holder does not offer durable pinning")
		return "", false
	}
	if len(s.pinKeys) == 0 {
		// Durable serving is on but no key is authorised to add to it. Refusing
		// is the fail-closed default: enabling storage must never imply
		// enabling anyone to fill it.
		writePinErr(w, http.StatusForbidden, "pin_not_authorized", "this holder accepts no pin requests")
		return "", false
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPinRequestBody)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		writePinErr(w, http.StatusBadRequest, "bad_request", "malformed request body")
		return "", false
	}

	pub, err := keyauth.DecodeKey(req.Key)
	if err != nil {
		writePinErr(w, http.StatusBadRequest, "bad_key", "invalid key")
		return "", false
	}
	key := keyauth.B64.EncodeToString(pub)

	// Signature BEFORE authorisation: an unsigned request from an allowlisted
	// key must not be honoured just because the key string was quoted correctly.
	if err := keyauth.VerifySig(pub, req.Sig, pinSigningMessage(domain, req)); err != nil {
		writePinErr(w, http.StatusUnauthorized, "bad_signature", "signature verification failed")
		return "", false
	}
	if !s.pinReplay.CheckAndRecord(key, req.Nonce, req.Timestamp, s.clock()) {
		writePinErr(w, http.StatusConflict, "stale_or_replayed", "stale or replayed request")
		return "", false
	}
	if !s.pinKeyAllowed(key) {
		writePinErr(w, http.StatusForbidden, "pin_not_authorized", "this key is not authorized to pin here")
		return "", false
	}
	return key, true
}

// pinKeyAllowed reports whether a key is on the operator's allowlist, comparing
// in constant time so the endpoint is not a key-guessing oracle.
func (s *Service) pinKeyAllowed(key string) bool {
	allowed := false
	for _, k := range s.pinKeys {
		if keyEq(k, key) {
			allowed = true
		}
	}
	return allowed
}

func (s *Service) clock() time.Time {
	if s.cfg.now != nil {
		return s.cfg.now()
	}
	return time.Now()
}

// handlePin serves POST {p}/pin.
func (s *Service) handlePin(w http.ResponseWriter, r *http.Request) {
	var req pinRequest
	owner, ok := s.authorizePin(w, r, domainPin, &req)
	if !ok {
		return
	}
	kind, ok := parseKind(req.Kind)
	if !ok {
		writePinErr(w, http.StatusBadRequest, "bad_kind", "kind must be announce or manifest")
		return
	}
	addr, err := ParseAddr(req.Addr)
	if err != nil {
		writePinErr(w, http.StatusBadRequest, "bad_addr", "invalid content address")
		return
	}

	rec, err := s.pins.pin(kind, addr, owner, s.pinSource(r))
	if err != nil {
		status, code := pinErrorCode(err)
		s.log.Warn("pubcache: pin refused", "kind", req.Kind, "addr", req.Addr, "code", code, "err", err)
		writePinErr(w, status, code, err.Error())
		return
	}
	s.log.Info("pubcache: pinned", "kind", rec.Kind, "addr", rec.Addr, "objects", len(rec.Objects), "bytes", rec.Bytes)
	writePinJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"kind":    rec.Kind,
		"addr":    rec.Addr,
		"objects": len(rec.Objects),
		"bytes":   rec.Bytes,
		"usage":   s.pins.stats(),
	})
}

// handleUnpin serves POST {p}/unpin.
func (s *Service) handleUnpin(w http.ResponseWriter, r *http.Request) {
	var req pinRequest
	owner, ok := s.authorizePin(w, r, domainUnpin, &req)
	if !ok {
		return
	}
	kind, ok := parseKind(req.Kind)
	if !ok {
		writePinErr(w, http.StatusBadRequest, "bad_kind", "kind must be announce or manifest")
		return
	}
	addr, err := ParseAddr(req.Addr)
	if err != nil {
		writePinErr(w, http.StatusBadRequest, "bad_addr", "invalid content address")
		return
	}

	rec, err := s.pins.unpin(kind, addr, owner)
	if err != nil {
		status, code := pinErrorCode(err)
		writePinErr(w, status, code, err.Error())
		return
	}
	s.log.Info("pubcache: unpinned", "kind", rec.Kind, "addr", rec.Addr, "bytes", rec.Bytes)
	writePinJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"kind":  rec.Kind,
		"addr":  rec.Addr,
		"bytes": rec.Bytes,
		"usage": s.pins.stats(),
	})
}

// handlePinList serves GET {p}/pins.
func (s *Service) handlePinList(w http.ResponseWriter) {
	if s.pins == nil {
		writePinErr(w, http.StatusNotImplemented, "pin_disabled", "this holder does not offer durable pinning")
		return
	}
	writePinJSON(w, http.StatusOK, map[string]any{"pins": s.pins.list()})
}

// handlePinStatus serves GET {p}/pins/status — the usage view.
//
// It reports bytes used, the configured budget, and the operation counters. A
// billing layer reads exactly this and does the rest elsewhere: metering,
// pricing, and charging are control-plane concerns, and putting any of them in
// the daemon that serves the role would make self-hosting the same code
// impossible.
func (s *Service) handlePinStatus(w http.ResponseWriter) {
	if s.pins == nil {
		writePinErr(w, http.StatusNotImplemented, "pin_disabled", "this holder does not offer durable pinning")
		return
	}
	st := s.pins.stats()
	writePinJSON(w, http.StatusOK, map[string]any{
		"role":            "dmtap-pub-pin",
		"usage":           st,
		"authorized_keys": len(s.pinKeys),
	})
}

// pinSource is the verified-retrieval path a pin acquires bytes through. It
// reuses the ordinary read path — pinned store, then cache, then upstream — so
// there is exactly ONE way an object enters this node, and it has Verify in it.
func (s *Service) pinSource(r *http.Request) objectSource {
	return func(kind Kind, addr Addr) ([]byte, error) {
		body, ok := s.lookup(r, kind, cacheKey(kind, addr), addr)
		if !ok {
			return nil, ErrNotServed
		}
		return body, nil
	}
}
