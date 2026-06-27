/**
 * signaling.js — Vulos RELAY signaling client for vulos-office.
 *
 * Opens a WebSocket to the Vulos OS signaling stream
 * (GET /api/peering/stream) and multiplexes offer/answer/ICE frames
 * over the "signal" channel defined by the OS ws.go Hub.
 *
 * Frame envelope (mirrors ws.go):
 *   { channel: "signal", from: <userID>, payload: <SignalPayload> }
 *
 * SignalPayload:
 *   { type: "offer"|"answer"|"ice"|"join"|"leave",
 *     session: <sessionID>,
 *     to: <peerID>,          // targeted delivery (optional; omit = broadcast)
 *     sdp: <string>,         // offer / answer
 *     candidate: <RTCIceCandidateInit>,
 *   }
 */

const RECONNECT_BASE_MS = 1_000
const RECONNECT_MAX_MS = 30_000
const RECONNECT_MAX_ATTEMPTS = 10  // after this many failures emit 'offline'
const SIGNAL_CHANNEL = 'signal'

// Prefix for carrying the auth JWT as a WebSocket subprotocol token. The full
// JWT is base64url (chars A-Za-z0-9-_ plus '.' segment separators) and unpadded,
// so `vula.token.<jwt>` is a valid RFC 6455 / RFC 7230 subprotocol token.
//
// ─── Server contract (audit MED — JWT in WS query string) ───────────────────
//   Default transport: the JWT is sent in the `Sec-WebSocket-Protocol` request
//   header, NOT the URL query string (which leaks into access logs, the browser
//   history/Referer, and proxies). The server MUST, during the WS upgrade:
//     1. Read `Sec-WebSocket-Protocol` (a comma-separated list of offered
//        subprotocols).
//     2. Find the entry beginning with `vula.token.`, strip that prefix, and
//        validate the remaining string as the Bearer JWT.
//     3. Complete the upgrade. Echoing a selected subprotocol back is optional
//        for browsers (an omitted response header still completes the
//        handshake); if the server does echo, it should echo a stable protocol
//        name and not the token value.
//   Tokens remain short-lived regardless of transport.
//
//   Legacy fallback: backends that cannot yet read the header may opt the
//   client back into the `?token=` query string by constructing the client with
//   `tokenTransport: 'query'`. This is OFF by default and exists only as a
//   migration shim.
const TOKEN_SUBPROTOCOL_PREFIX = 'vula.token.'

export class SignalingClient extends EventTarget {
  /**
   * @param {object} opts
   * @param {string}   opts.signalingUrl     - WebSocket URL, e.g. "ws://localhost:8080/api/peering/stream"
   * @param {string}   opts.sessionId        - fabric session / document id
   * @param {string}   opts.peerId           - this client's identity token (injected by auth)
   * @param {string}  [opts.authToken]       - Bearer JWT (if auth is enabled)
   * @param {'subprotocol'|'query'} [opts.tokenTransport='subprotocol']
   *        - how the auth JWT is delivered. 'subprotocol' (default) sends it in
   *          the Sec-WebSocket-Protocol header so it never appears in the URL.
   *          'query' is a legacy migration shim that appends ?token=<jwt> for
   *          backends that cannot yet read the header — see the server contract
   *          note at the top of this file.
   * @param {number}  [opts.maxAttempts]     - max reconnect attempts before 'offline' (default 10)
   * @param {() => (string|null)} [opts.getDepositPubKey]
   *        - optional callback returning this peer's base64 raw deposit signing
   *          public key. When it returns a non-null value, the key is published
   *          in the "join" frame so the server can bind it to the authenticated
   *          peerId and verify deposit signatures.
   */
  constructor({ signalingUrl, sessionId, peerId, authToken = null, tokenTransport = 'subprotocol', maxAttempts = RECONNECT_MAX_ATTEMPTS, getDepositPubKey = null }) {
    super()
    this._url = signalingUrl
    this._session = sessionId
    this._peerId = peerId
    this._authToken = authToken
    this._tokenTransport = tokenTransport === 'query' ? 'query' : 'subprotocol'
    this._getDepositPubKey = getDepositPubKey
    this._ws = null
    this._reconnectDelay = RECONNECT_BASE_MS
    this._reconnectAttempts = 0
    this._maxAttempts = maxAttempts
    this._stopped = false
    this._degraded = false
  }

  /** Connect (or reconnect) to the signaling WebSocket. */
  connect() {
    if (this._stopped) return

    // Default: carry the JWT as a WebSocket subprotocol so it never lands in the
    // URL (and thus access logs / Referer / history). 'query' is a legacy shim.
    let ws
    if (this._authToken && this._tokenTransport === 'subprotocol') {
      ws = new WebSocket(this._url, [TOKEN_SUBPROTOCOL_PREFIX + this._authToken])
    } else if (this._authToken && this._tokenTransport === 'query') {
      ws = new WebSocket(`${this._url}?token=${encodeURIComponent(this._authToken)}`)
    } else {
      ws = new WebSocket(this._url)
    }
    this._ws = ws

    ws.addEventListener('open', () => {
      this._reconnectDelay = RECONNECT_BASE_MS
      this._reconnectAttempts = 0
      this._degraded = false
      this.dispatchEvent(new CustomEvent('signaling-open'))
      // Announce ourselves to the session room. Publish the deposit signing
      // public key (when available) so the server can bind it to our
      // authenticated peerId and verify relay deposit signatures.
      const join = { type: 'join', session: this._session }
      const depositPubKey = this._getDepositPubKey?.()
      if (depositPubKey) join.depositPubKey = depositPubKey
      this._send(join)
    })

    ws.addEventListener('message', (ev) => {
      let frame
      try { frame = JSON.parse(ev.data) } catch { return }
      if (frame.channel !== SIGNAL_CHANNEL) return
      // Only deliver frames addressed to this session and this peer (or broadcast).
      const p = frame.payload
      if (!p) return
      if (p.session && p.session !== this._session) return
      if (p.to && p.to !== this._peerId) return
      this.dispatchEvent(new CustomEvent('signal', { detail: { from: frame.from, payload: p } }))
    })

    ws.addEventListener('close', () => {
      if (this._stopped) return
      this.dispatchEvent(new CustomEvent('signaling-close'))
      this._scheduleReconnect()
    })

    ws.addEventListener('error', () => {
      // 'close' will follow; handled there.
    })
  }

  /** Send a signal payload to a specific peer (or broadcast to session). */
  signal(type, toId, data = {}) {
    this._send({ type, session: this._session, to: toId, ...data })
  }

  /** Cleanly stop reconnecting and close the socket. */
  close() {
    this._stopped = true
    if (this._ws) {
      this._send({ type: 'leave', session: this._session })
      this._ws.close()
      this._ws = null
    }
  }

  // ─── private ───────────────────────────────────────────────────────────────

  _send(payload) {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) return
    const frame = JSON.stringify({
      channel: SIGNAL_CHANNEL,
      payload,
    })
    this._ws.send(frame)
  }

  _scheduleReconnect() {
    this._reconnectAttempts++

    // Once the budget is exhausted, emit a terminal 'offline' event so
    // consumers can show a degraded-mode banner rather than waiting forever.
    if (this._reconnectAttempts >= this._maxAttempts) {
      if (!this._degraded) {
        this._degraded = true
        this.dispatchEvent(new CustomEvent('offline', {
          detail: { attempts: this._reconnectAttempts },
        }))
      }
      // Continue trying — but at the max delay — so the connection recovers
      // automatically when the network comes back, while consumers know we are
      // in degraded mode.
    }

    const delay = this._reconnectDelay
    this._reconnectDelay = Math.min(this._reconnectDelay * 2, RECONNECT_MAX_MS)
    setTimeout(() => this.connect(), delay)
  }
}
