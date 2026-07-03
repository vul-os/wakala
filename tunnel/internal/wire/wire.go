// Package wire defines the small control-plane message set exchanged between a
// Vulos relay agent and the sovereign relay server over the WebSocket control
// connection, BEFORE yamux takes over the same net.Conn for request multiplexing.
//
// The handshake is a single JSON request/response:
//
//	agent  --> server : Register{Name, Token}
//	server --> agent  : RegisterAck{OK, PublicURL, Error}
//
// After a successful ack, both sides hand the connection to yamux: the server is
// the yamux *client* (it opens streams, one per inbound HTTP request); the agent
// is the yamux *server* (it accepts streams and proxies each to its one local
// target). Each stream carries a plain HTTP/1.1 request and response — no extra
// framing — so http.ReadRequest / Request.Write / http.ReadResponse can be used
// directly, which also gives us transparent WebSocket-upgrade passthrough.
package wire

// Protocol constants shared by agent and server.
const (
	// ControlPath is the server route the agent dials for control/registration.
	ControlPath = "/_vulos-relay/control"

	// Subprotocol identifies the Vulos tunnel control protocol on the wss handshake.
	Subprotocol = "vulos-relay.v1"

	// MaxControlMessage bounds a single handshake JSON message (bytes).
	MaxControlMessage = 8 << 10 // 8 KiB
)

// Register is the agent's first message: it claims a name and presents its token.
// The server treats the token as authoritative for which names are permitted; the
// Name is only honored if the token grants it.
type Register struct {
	Type  string `json:"type"` // always "register"
	Name  string `json:"name"`
	Token string `json:"token"`
	// AgentVersion is informational (for server logs); never trusted.
	AgentVersion string `json:"agentVersion,omitempty"`
}

// RegisterAck is the server's reply. On failure OK is false and Error carries a
// short, non-leaky reason.
type RegisterAck struct {
	Type      string `json:"type"` // always "register_ack"
	OK        bool   `json:"ok"`
	PublicURL string `json:"publicUrl,omitempty"`
	Error     string `json:"error,omitempty"`
}
