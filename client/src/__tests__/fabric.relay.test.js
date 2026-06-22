/**
 * fabric.relay.test.js — relay-circuit auth header contract.
 *
 * Regression coverage for the relay pickup auth header bug:
 *   When an authToken is configured, _relayPoll must send
 *   "Authorization: Bearer <token>", NOT the unauthenticated
 *   "Vula-Relay <peerId>.<ts>" scheme.  Previously the Vula-Relay
 *   header was emitted unconditionally via object spread, silently
 *   overwriting the Bearer JWT.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'

// Minimal SignalingClient stub — we only test the relay path here.
class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  constructor() {
    this.readyState = FakeWebSocket.CONNECTING
    this._listeners = {}
    this.sent = []
    FakeWebSocket.instances.push(this)
  }
  addEventListener(ev, fn) {
    if (!this._listeners[ev]) this._listeners[ev] = []
    this._listeners[ev].push(fn)
  }
  send(data) { this.sent.push(data) }
  close() { this.readyState = 0 }
  _fire(ev, payload) {
    for (const fn of (this._listeners[ev] || [])) fn(payload)
  }
  _open() { this.readyState = FakeWebSocket.OPEN; this._fire('open', {}) }
}
FakeWebSocket.instances = []

// Silence console output from FabricClient internals.
beforeEach(() => {
  FakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', FakeWebSocket)
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

/**
 * Build a minimal FabricClient, force one peer into 'relay' state,
 * run one poll tick, and capture the Authorization header sent.
 */
async function capturePollAuthHeader({ authToken, allowUnsignedRelayAuth = false }) {
  let capturedHeader

  vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
    if (String(url).includes('/api/peering/relay/pickup')) {
      capturedHeader = opts?.headers?.['Authorization']
      // Return an empty blobs array so poll completes cleanly.
      return { ok: true, json: async () => ({ blobs: [] }) }
    }
    // ICE endpoint
    return { ok: true, json: async () => ({ ice_servers: [] }) }
  }))

  const fc = new FabricClient({
    sessionId: 'test-session',
    peerId: 'local-peer',
    signalingUrl: 'ws://localhost/api/peering/stream',
    iceUrl: '/api/peering/ice',
    relayBaseUrl: '',
    authToken,
    allowUnsignedRelayAuth,
  })

  // Force a peer into relay state so the poll actually fires.
  fc._peers.set('remote-peer', {
    id: 'remote-peer',
    state: 'relay',
    dc: null,
    pc: null,
    relayTimer: null,
    pendingCandidates: [],
    reset() {},
  })

  await fc._relayPoll()

  return capturedHeader
}

describe('FabricClient relay pickup — Authorization header', () => {
  it('sends Bearer JWT when authToken is configured', async () => {
    const header = await capturePollAuthHeader({ authToken: 'my-jwt-token' })
    expect(header).toBe('Bearer my-jwt-token')
  })

  it('falls back to Vula-Relay scheme when no authToken is set and unsigned auth is opted in', async () => {
    const header = await capturePollAuthHeader({ authToken: null, allowUnsignedRelayAuth: true })
    expect(header).toMatch(/^Vula-Relay local-peer\.\d+$/)
  })

  it('sends NO Authorization header when no authToken and unsigned auth is not opted in (default)', async () => {
    // The unsigned "Vula-Relay <peerId>.<ts>" header is forgeable, so it must
    // not be emitted by default — only behind the allowUnsignedRelayAuth flag.
    const header = await capturePollAuthHeader({ authToken: null })
    expect(header).toBeUndefined()
  })

  it('Bearer JWT is not overwritten by the Vula-Relay scheme', async () => {
    // Regression: previously the spread { ...headers, Authorization: 'Vula-Relay ...' }
    // silently overwrote the Bearer token.
    const header = await capturePollAuthHeader({ authToken: 'sensitive-jwt' })
    expect(header).not.toMatch(/^Vula-Relay/)
    expect(header).toBe('Bearer sensitive-jwt')
  })
})

describe('FabricClient — deposit public key publication (integrity wiring)', () => {
  it('join() eagerly generates the deposit key and publishes it in the join frame', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))

    const fc = new FabricClient({
      sessionId: 'test-session',
      peerId: 'local-peer',
      signalingUrl: 'ws://localhost/api/peering/stream',
      iceUrl: '/api/peering/ice',
    })

    await fc.join()

    // The deposit key must be generated up front so its public key is ready.
    expect(typeof fc._depositPubKeyB64).toBe('string')
    expect(fc._depositPubKeyB64.length).toBeGreaterThan(0)

    // Drive the signaling socket open and inspect the join frame.
    const ws = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]
    ws._open()
    const join = JSON.parse(ws.sent[0])
    expect(join.payload.type).toBe('join')
    expect(join.payload.session).toBe('test-session')
    // The crux of the fix: the public key is now actually sent.
    expect(join.payload.depositPubKey).toBe(fc._depositPubKeyB64)

    fc.leave()
  })
})
