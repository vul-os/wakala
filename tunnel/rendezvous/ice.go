package rendezvous

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// ice.go — ICE server configuration for the rendezvous role.
//
// A client that has SIGNALed an offer/answer still needs STUN (to discover its
// reflexive address) and, for hard-NAT peers, TURN (a media relay of last resort).
// The rendezvous node hands clients an ICE server list in the W3C RTCIceServer
// shape. STUN entries are static public/self-hosted URLs. TURN entries, when a TURN
// secret is configured, carry SHORT-LIVED credentials minted with the coturn REST
// scheme (RFC 7635 / "TURN REST API"): username = "<expiry-unix>:<hint>", password =
// base64(HMAC-SHA1(secret, username)). This means the long-term TURN secret is never
// handed to a client and a leaked credential self-expires — the node stays honest
// even though TURN itself is not content-blind.
//
// TURN is optional; a self-host with no TURN configured returns only STUN (P2P still
// works for the large majority of NAT pairings — TURN carries the hard-NAT residual).

// ICEServer is the W3C RTCIceServer shape returned to clients.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
	// TTL is the remaining lifetime (seconds) of the credential — advisory, so a
	// client knows when to re-fetch. Omitted for credential-free STUN entries.
	TTL int `json:"ttl,omitempty"`
}

// ICEConfig configures the ICE surface. All fields optional: an empty config yields
// only the built-in public STUN list (unless disabled).
type ICEConfig struct {
	// STUNURLs are static STUN URLs to advertise (e.g. "stun:stun.example.org:3478").
	// When empty AND DisablePublicSTUN is false, a public default list is used.
	STUNURLs []string
	// DisablePublicSTUN drops the built-in public STUN fallback (sovereign
	// deployments that only want their own STUN/TURN).
	DisablePublicSTUN bool
	// TURNURLs are the TURN relay URLs (e.g. "turn:turn.example.org:3478?transport=udp").
	// TURN entries are only emitted when both TURNURLs and TURNSecret are set.
	TURNURLs []string
	// TURNSecret is the coturn static-auth-secret used to mint ephemeral credentials.
	// Kept server-side; never sent to a client. Empty => no TURN entries.
	TURNSecret string
	// TURNCredentialTTL is how long a minted TURN credential is valid. 0 => 12h.
	TURNCredentialTTL time.Duration
}

// defaultPublicSTUN is the built-in fallback STUN list (public, credential-free). It
// is used only when an operator configures no STUN of their own and has not opted
// out with DisablePublicSTUN.
var defaultPublicSTUN = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun1.l.google.com:19302",
}

// iceProvider builds ICE server lists from an ICEConfig.
type iceProvider struct {
	cfg ICEConfig
}

func newICEProvider(cfg ICEConfig) *iceProvider {
	if cfg.TURNCredentialTTL <= 0 {
		cfg.TURNCredentialTTL = 12 * time.Hour
	}
	return &iceProvider{cfg: cfg}
}

// servers returns the ICE server list for a client. `hint` is an opaque,
// non-authenticating label folded into the TURN username (coturn allows an
// arbitrary suffix after the expiry); pass the requesting key or "" — it is NOT a
// gate, only a coturn bookkeeping field. `now` is injectable for tests.
func (p *iceProvider) servers(hint string, now time.Time) []ICEServer {
	out := make([]ICEServer, 0, 4)

	stun := p.cfg.STUNURLs
	if len(stun) == 0 && !p.cfg.DisablePublicSTUN {
		stun = defaultPublicSTUN
	}
	if len(stun) > 0 {
		out = append(out, ICEServer{URLs: append([]string(nil), stun...)})
	}

	if len(p.cfg.TURNURLs) > 0 && p.cfg.TURNSecret != "" {
		user, cred, ttl := p.turnCredential(hint, now)
		out = append(out, ICEServer{
			URLs:       append([]string(nil), p.cfg.TURNURLs...),
			Username:   user,
			Credential: cred,
			TTL:        ttl,
		})
	}
	return out
}

// turnCredential mints a short-lived coturn REST credential. username =
// "<expiry-unix>[:<hint>]"; credential = base64(HMAC-SHA1(secret, username)).
func (p *iceProvider) turnCredential(hint string, now time.Time) (username, credential string, ttlSeconds int) {
	ttl := p.cfg.TURNCredentialTTL
	exp := now.Add(ttl).Unix()
	username = fmt.Sprintf("%d", exp)
	if h := sanitizeTURNHint(hint); h != "" {
		username = username + ":" + h
	}
	mac := hmac.New(sha1.New, []byte(p.cfg.TURNSecret))
	mac.Write([]byte(username))
	credential = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return username, credential, int(ttl.Seconds())
}

// sanitizeTURNHint strips characters that would break the "expiry:hint" username
// grammar (a colon or whitespace) and bounds the length.
func sanitizeTURNHint(hint string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return ""
	}
	hint = strings.NewReplacer(":", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(hint)
	if len(hint) > 48 {
		hint = hint[:48]
	}
	return hint
}
