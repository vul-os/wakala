/**
 * rendezvousSignaling.test.js — integration tests for the OS-free signaling
 * transport (RendezvousSignalingClient) and FabricClient's rendezvous-native
 * signaling + relay-mailbox fallback.
 *
 * These use REAL Ed25519 (rendezvous envelope) and REAL ECDSA-P256 (per-session
 * peer-auth handshake) against an in-memory relay that faithfully models the Go
 * node's queue semantics (non-destructive peek on poll, delete-on-ack), so the
 * end-to-end identity bridging is exercised, not mocked away.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  RendezvousClient,
  RendezvousIdentity,
  b64urlDecode,
} from '../rendezvous.js'
import {
  RendezvousSignalingClient,
  deriveRoomIdentity,
} from '../rendezvousSignaling.js'
import { FabricClient } from '../fabric.js'

// ── In-memory relay modelling the rendezvous wire (peek-on-poll, delete-on-ack) ─

function jsonResponse(status, obj) {
  return { ok: status >= 200 && status < 300, status, statusText: '', json: async () => obj }
}

function makeMockRelay() {
  const presence = new Map() // key → record
  const signal = new Map()   // recipient key → [blob]
  const mailbox = new Map()  // recipient key → [blob]
  const calls = []
  let seq = 0

  const push = (store, to, from, payloadB64) => {
    const id = 'blob' + (++seq)
    const arr = store.get(to) || []
    arr.push({ id, from, payload: payloadB64, ts: 1, exp: 9 })
    store.set(to, arr)
    return id
  }

  const fetchImpl = vi.fn(async (url, opts = {}) => {
    const u = new URL(url)
    const path = u.pathname
    const method = opts.method || 'GET'
    const body = opts.body ? JSON.parse(opts.body) : null
    calls.push({ url, path, method, body })

    if (path.endsWith('/announce')) {
      presence.set(body.key, { endpoints: body.endpoints || [], meta: body.meta || '', expires_at: 9 })
      return jsonResponse(200, { ok: true, key: body.key, ttl: 300, expires_at: 9 })
    }
    if (path.endsWith('/withdraw')) { presence.delete(body.key); return jsonResponse(200, { ok: true }) }
    if (path.endsWith('/ice')) return jsonResponse(200, { ice_servers: [] })

    const seg = path.replace(/^.*\/rendezvous\//, '').split('/')
    if (seg[0] === 'resolve') {
      const k = decodeURIComponent(seg[1])
      const r = presence.get(k)
      return r ? jsonResponse(200, { key: k, online: true, ...r }) : jsonResponse(404, { key: k, online: false })
    }
    const store = seg[0] === 'signal' ? signal : seg[0] === 'mailbox' ? mailbox : null
    if (store) {
      if (seg.length === 2) {
        const to = decodeURIComponent(seg[1])
        const id = push(store, to, body.from, body.payload)
        return jsonResponse(201, { ok: true, id, expires_at: 9 })
      }
      const k = decodeURIComponent(seg[1])
      if (seg[2] === 'poll') return jsonResponse(200, { key: k, blobs: (store.get(k) || []).slice() })
      if (seg[2] === 'ack') {
        const del = new Set(body.ids)
        store.set(k, (store.get(k) || []).filter((b) => !del.has(b.id)))
        return jsonResponse(200, { deleted: body.ids.length })
      }
    }
    return jsonResponse(404, { error: 'not found' })
  })

  return { fetchImpl, calls, presence, signal, mailbox }
}

// Real ECDSA-P256 identity (the per-session peer-auth key, unchanged end to end).
async function makeEcdsa() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
  const raw = await crypto.subtle.exportKey('raw', kp.publicKey)
  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(raw)))
  const sign = async (msg) => {
    const s = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new TextEncoder().encode(msg))
    return btoa(String.fromCharCode(...new Uint8Array(s)))
  }
  return { pubB64, sign }
}

function makeSignaling({ peerId, sessionId, fetchImpl, ecdsa, extra = {} }) {
  const selfClient = new RendezvousClient({
    baseUrl: 'https://relay.test',
    identity: RendezvousIdentity.generate(),
    fetch: fetchImpl,
  })
  return new RendezvousSignalingClient({
    selfClient,
    sessionId,
    peerId,
    getDepositPubKey: () => ecdsa.pubB64,
    signFrame: (m) => ecdsa.sign(m),
    requirePeerAuth: true,
    pollLoop: false,
    ...extra,
  })
}

function collect(target, type) {
  const out = []
  target.addEventListener(type, (e) => out.push(e.detail))
  return out
}

// ── deriveRoomIdentity ─────────────────────────────────────────────────────────

describe('deriveRoomIdentity', () => {
  it('is deterministic per sessionId and distinct across sessions', () => {
    expect(deriveRoomIdentity('sess-1').key).toBe(deriveRoomIdentity('sess-1').key)
    expect(deriveRoomIdentity('sess-1').key).not.toBe(deriveRoomIdentity('sess-2').key)
    expect(b64urlDecode(deriveRoomIdentity('sess-1').key).length).toBe(32)
  })
})

// ── Identity bridging + presence discovery + full offer/answer/ice ──────────────

describe('RendezvousSignalingClient — signaling lifecycle over rendezvous', () => {
  let relay, A, B, ecdsaA, ecdsaB

  beforeEach(async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    relay = makeMockRelay()
    ecdsaA = await makeEcdsa()
    ecdsaB = await makeEcdsa()
    A = makeSignaling({ peerId: 'peerA', sessionId: 'sess', fetchImpl: relay.fetchImpl, ecdsa: ecdsaA })
    B = makeSignaling({ peerId: 'peerB', sessionId: 'sess', fetchImpl: relay.fetchImpl, ecdsa: ecdsaB })
  })
  afterEach(() => vi.restoreAllMocks())

  it('uses two distinct identities: Ed25519 rendezvous address ≠ ECDSA peer key', () => {
    expect(b64urlDecode(A.key).length).toBe(32)      // Ed25519 rendezvous address
    expect(A.key).not.toBe(ecdsaA.pubB64)            // != ECDSA-P256 peer-auth key
    // Both peers derive the same session room address.
    expect(A.roomKey).toBe(B.roomKey)
    expect(A.roomKey).toBe(deriveRoomIdentity('sess').key)
  })

  it('dispatches signaling-open after connect() announces + deposits its join', async () => {
    const opens = collect(A, 'signaling-open')
    await A.connect()
    expect(opens.length).toBe(1)
    // Presence announced, and the signed join was deposited onto the room board.
    expect(relay.presence.has(A.key)).toBe(true)
    expect((relay.signal.get(A.roomKey) || []).length).toBe(1)
  })

  it('deposits a signed join whose OUTER envelope is Ed25519 and INNER payload carries the ECDSA key', async () => {
    await A.connect()
    const deposit = relay.calls.find((c) => c.method === 'POST' && c.path.endsWith('/signal/' + encodeURIComponent(A.roomKey)))
    expect(deposit).toBeTruthy()
    // Outer rendezvous envelope: signed by the Ed25519 address.
    expect(deposit.body.from).toBe(A.key)
    expect(typeof deposit.body.sig).toBe('string')
    // Inner opaque payload: routing identity + the WS-identical signed join.
    const wrapper = JSON.parse(new TextDecoder().decode(b64urlDecode(deposit.body.payload)))
    expect(wrapper.from).toBe('peerA')
    expect(wrapper.rdvKey).toBe(A.key)
    expect(wrapper.payload.type).toBe('join')
    expect(wrapper.payload.depositPubKey).toBe(ecdsaA.pubB64) // the ECDSA identity rides inside
    expect(typeof wrapper.payload.sig).toBe('string')         // ECDSA-signed join commitment
  })

  it('discovers a peer from the room board and learns its rendezvous address', async () => {
    const aSignals = collect(A, 'signal')
    await A.connect()
    await B.connect()
    await A._pollBoardOnce()
    const join = aSignals.find((s) => s.from === 'peerB' && s.payload.type === 'join')
    expect(join).toBeTruthy()
    expect(A.rdvKeyFor('peerB')).toBe(B.key)
    expect(A.hasPeerKey('peerB')).toBe(true) // ECDSA key TOFU-imported from the join
  })

  it('completes a full offer → answer → ice exchange with verified peer-auth', async () => {
    await A.connect(); await B.connect()
    await A._pollBoardOnce()   // A learns B (key + rdvKey)
    await B._pollBoardOnce()   // B learns A

    const bSignals = collect(B, 'signal')
    const aSignals = collect(A, 'signal')

    // A (impolite) → offer to B, signed with A's ECDSA key, verified by B.
    await A.signal('offer', 'peerB', { sdp: 'v=0 offer-sdp', pubKey: ecdsaA.pubB64 })
    await B._pollInboxOnce()
    const offer = bSignals.find((s) => s.from === 'peerA' && s.payload.type === 'offer')
    expect(offer).toBeTruthy()
    expect(offer.payload.sdp).toBe('v=0 offer-sdp')

    // B → answer back to A.
    await B.signal('answer', 'peerA', { sdp: 'v=0 answer-sdp', pubKey: ecdsaB.pubB64 })
    await A._pollInboxOnce()
    const answer = aSignals.find((s) => s.from === 'peerB' && s.payload.type === 'answer')
    expect(answer.payload.sdp).toBe('v=0 answer-sdp')

    // Trickle ICE A → B.
    await A.signal('ice', 'peerB', { candidate: { candidate: 'a=x', sdpMid: '0' } })
    const before = bSignals.length
    await B._pollInboxOnce()
    expect(bSignals.length).toBeGreaterThan(before)
    expect(bSignals[bSignals.length - 1].payload.type).toBe('ice')
  })

  it('drops an unsigned offer from an unknown peer when requirePeerAuth is on', async () => {
    await B.connect()
    const bSignals = collect(B, 'signal')
    // Attacker deposits a wrapped offer claiming peerId 'peerC' with no ECDSA key/sig.
    const attacker = new RendezvousClient({
      baseUrl: 'https://relay.test', identity: RendezvousIdentity.generate(), fetch: relay.fetchImpl,
    })
    const wrapped = new TextEncoder().encode(JSON.stringify({
      from: 'peerC', rdvKey: attacker.key,
      payload: { type: 'offer', session: 'sess', to: 'peerB', sdp: 'evil' },
    }))
    await attacker.signalDeposit(B.key, wrapped)
    await B._pollInboxOnce()
    expect(bSignals.find((s) => s.payload.type === 'offer')).toBeUndefined() // dropped
  })

  it('propagates a leave tombstone and inbox acks consume signals', async () => {
    await A.connect(); await B.connect()
    await A._pollBoardOnce(); await B._pollBoardOnce()
    const aSignals = collect(A, 'signal')

    B.close() // deposits a leave tombstone + acks own board blob + withdraws
    await A._pollBoardOnce()
    expect(aSignals.find((s) => s.from === 'peerB' && s.payload.type === 'leave')).toBeTruthy()

    // Inbox ack deletes consumed blobs (delete-on-ack): a second poll is empty.
    await A.signal('ice', 'peerB', { candidate: { candidate: 'c' } }) // (B already left; harmless)
    await B.connect()
    await A.signal('ice', 'peerB', { candidate: { candidate: 'c2' } })
    const seen1 = await B._pollInboxOnce()
    const seen2 = await B._pollInboxOnce()
    expect(seen1).toBeGreaterThan(0)
    expect(seen2).toBe(0) // acked away
  })
})

// ── FabricClient wiring + relay-mailbox fallback (OS-free) ───────────────────────

describe('FabricClient — rendezvous transport selection', () => {
  afterEach(() => vi.restoreAllMocks())

  it('uses RendezvousSignalingClient when rendezvousBaseUrl is set', () => {
    const fc = new FabricClient({
      sessionId: 's', peerId: 'p',
      signalingUrl: 'wss://host/api/peering/stream',
      rendezvousBaseUrl: 'https://relay.test',
    })
    expect(fc._signaling).toBeInstanceOf(RendezvousSignalingClient)
    expect(typeof fc._signaling.rdvKeyFor).toBe('function')
  })

  it('uses the host-box SignalingClient (WebSocket) when rendezvousBaseUrl is absent', async () => {
    const { SignalingClient } = await import('../signaling.js')
    const fc = new FabricClient({
      sessionId: 's', peerId: 'p',
      signalingUrl: 'wss://host/api/peering/stream',
    })
    expect(fc._signaling).toBeInstanceOf(SignalingClient)
    expect(fc._signaling).not.toBeInstanceOf(RendezvousSignalingClient)
  })
})

describe('FabricClient — relay fallback over the rendezvous mailbox', () => {
  let relay
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    relay = makeMockRelay()
    vi.stubGlobal('fetch', relay.fetchImpl)
  })
  afterEach(() => vi.restoreAllMocks())

  it('delivers a forward-secret, content-blind message A→B through the mailbox', async () => {
    const mk = (peerId) => new FabricClient({
      sessionId: 'sess', peerId,
      signalingUrl: 'wss://host/api/peering/stream',
      rendezvousBaseUrl: 'https://relay.test',
      requirePeerAuth: true,
    })
    const A = mk('peerA'), B = mk('peerB')

    // Generate the ECDSA/box/X3DH material so the join announcements carry them.
    for (const fc of [A, B]) { await fc._ensureDepositKey(); await fc._ensurePreKeys() }
    // Don't spin up WebRTC on join discovery (we're testing the mailbox path only).
    A._initiatePeer = async () => {}
    B._initiatePeer = async () => {}

    // Publish joins onto the shared board, then cross-discover (imports box key +
    // signed prekey + rendezvous address for each peer).
    await A._signaling._announceAndJoin()
    await B._signaling._announceAndJoin()
    await A._signaling._pollBoardOnce()
    await B._signaling._pollBoardOnce()

    expect(A._signaling.rdvKeyFor('peerB')).toBe(B._rendezvous.key)
    expect(A._signaling.getPeerBoxKey('peerB')).toBeTruthy()

    const bMsgs = collect(B, 'message')

    // A deposits into B's content-blind rendezvous mailbox (relay never sees plaintext).
    await A._relayDeposit('peerB', { hello: 'world' })
    const blobs = await B._relayFetch()
    expect(blobs.length).toBe(1)
    const ackId = await B._processRelayBlob(blobs[0])
    expect(ackId).toBeTruthy()

    expect(bMsgs).toEqual([{ from: 'peerA', data: { hello: 'world' } }])

    // The relay stored only opaque ciphertext (no plaintext 'world').
    const stored = JSON.stringify([...relay.mailbox.values()])
    expect(stored).not.toContain('world')

    // Meter counted the outbound + inbound payload bytes.
    expect(A.relayByteCount.out).toBeGreaterThan(0)
    expect(B.relayByteCount.in).toBeGreaterThan(0)

    A.leave(); B.leave()
  })
})
