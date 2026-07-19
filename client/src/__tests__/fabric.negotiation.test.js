/**
 * fabric.negotiation.test.js — perfect-negotiation GLARE tie-break, persistent
 * reconnect back-off, and relay-circuit symmetry.
 *
 * Regression coverage for three fixes that only surfaced on the rendezvous
 * transport, where BOTH peers observe each other's `join` on a shared presence
 * board (unlike the host-box WebSocket path, where one side initiates):
 *
 *   • GLARE — both sides offer, both reset()ted to answer, both offers were
 *     abandoned and the negotiation deadlocked until the 8s relay timer.
 *     The impolite side must now ignore a colliding offer.
 *   • RECONNECT — a single 2s retry after a data-channel close was often spent
 *     while the network was still down and nothing ever tried again. Retries
 *     now back off 2s → 16s and stop on connect / `leave` / teardown.
 *   • RELAY SYMMETRY — relay polling only began once WE gave up, so a peer that
 *     fell back first deposited into a mailbox we never read. Polling now starts
 *     with the negotiation, covers 'connecting' peers, and a decryptable blob
 *     adopts the relay circuit for our own sends too.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'
import { makeRelayBlob } from './_relayTestUtil.js'

// ── Shared fake stubs (same shape as fabric.reconnect.test.js) ───────────────

class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  static CLOSED = 3
  static instances = []

  constructor(url, protocols) {
    this.url = url
    this.protocols = protocols
    this.readyState = FakeWebSocket.CONNECTING
    this.sent = []
    this._listeners = {}
    FakeWebSocket.instances.push(this)
    FakeWebSocket.last = this
  }

  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }

  send(data) { this.sent.push(data) }
  close() { this.readyState = FakeWebSocket.CLOSED; this._fire('close', {}) }
  _fire(evt, p) { for (const fn of (this._listeners[evt] || [])) fn(p) }
  _open() { this.readyState = FakeWebSocket.OPEN; this._fire('open', {}) }
  _message(frame) { this._fire('message', { data: JSON.stringify(frame) }) }
}

class FakeDC {
  constructor() {
    this.readyState = 'connecting'
    this.binaryType = 'arraybuffer'
    this.sent = []
    this._listeners = {}
  }
  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }
  send(d) { this.sent.push(d) }
  close() { this.readyState = 'closed'; this._fire('close', {}) }
  _fire(evt, p) { for (const fn of (this._listeners[evt] || [])) fn(p) }
  _open() { this.readyState = 'open'; this._fire('open', {}) }
}

/**
 * FakePC tracks `signalingState` the way a real RTCPeerConnection does — the
 * GLARE guard keys off 'have-local-offer', so the stub must model it.
 */
class FakePC {
  static instances = []
  constructor() {
    this._listeners = {}
    this.connectionState = 'connecting'
    this.signalingState = 'stable'
    this.localDescription = null
    this.remoteDescription = null
    this.closed = false
    this._dc = new FakeDC()
    FakePC.instances.push(this)
    FakePC.last = this
  }
  addEventListener(evt, fn) {
    if (!this._listeners[evt]) this._listeners[evt] = []
    this._listeners[evt].push(fn)
  }
  _fire(evt, p) { for (const fn of (this._listeners[evt] || [])) fn(p) }
  createOffer() { return Promise.resolve({ type: 'offer', sdp: 'v=0-local-offer' }) }
  createAnswer() { return Promise.resolve({ type: 'answer', sdp: 'v=0-local-answer' }) }
  setLocalDescription(d) {
    this.localDescription = d
    this.signalingState = d.type === 'offer' ? 'have-local-offer' : 'stable'
    return Promise.resolve()
  }
  setRemoteDescription(d) {
    this.remoteDescription = d
    this.signalingState = d.type === 'offer' ? 'have-remote-offer' : 'stable'
    return Promise.resolve()
  }
  addIceCandidate() { return Promise.resolve() }
  close() {
    this.closed = true
    this.connectionState = 'closed'
    this.signalingState = 'closed'
    this._fire('connectionstatechange', {})
  }
  createDataChannel() { return this._dc }
  _connect() { this.connectionState = 'connected'; this._fire('connectionstatechange', {}) }
}

function makeFabric(peerId) {
  return new FabricClient({
    sessionId: 'sess-1',
    peerId,
    signalingUrl: 'ws://localhost/sig',
    iceUrl: '/api/peering/ice',
    relayBaseUrl: '',
  })
}

function flush() { return new Promise(r => setTimeout(r, 0)) }

beforeEach(() => {
  FakeWebSocket.instances = []
  FakeWebSocket.last = null
  FakePC.instances = []
  FakePC.last = null

  vi.stubGlobal('WebSocket', FakeWebSocket)
  vi.stubGlobal('RTCPeerConnection', FakePC)
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ ice_servers: [] }) })))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

/** Bring a fabric up with an open signaling socket and a signal() spy. */
async function bootFabric(peerId) {
  const fc = makeFabric(peerId)
  await fc.join()
  const ws = FakeWebSocket.last
  ws._open()
  const signal = vi.spyOn(fc._signaling, 'signal').mockResolvedValue(undefined)
  return { fc, ws, signal }
}

const sentTypes = (signal) => signal.mock.calls.map(c => c[0])

// ── 1. GLARE ────────────────────────────────────────────────────────────────

describe('FabricClient — GLARE tie-break on colliding offers', () => {
  it('impolite side (peerId < remote) IGNORES a colliding offer and keeps its own negotiation', async () => {
    // 'a-local' < 'z-remote' → polite === false → this side is impolite.
    const { fc, ws, signal } = await bootFabric('a-local')

    // Its own offer goes out first and is left in flight.
    ws._message({ channel: 'signal', from: 'z-remote', payload: { type: 'join', session: 'sess-1' } })
    await flush()

    const ps = fc._peers.get('z-remote')
    const ownPc = ps.pc
    expect(ownPc.signalingState).toBe('have-local-offer')
    expect(sentTypes(signal)).toEqual(['offer'])
    const pcCountBefore = FakePC.instances.length

    // The colliding offer arrives.
    await fc._onSignal({ from: 'z-remote', payload: { type: 'offer', sdp: 'v=0-their-offer' } })
    await flush()

    // Ignored: same pc, not reset, not closed, no new pc, and no answer sent.
    expect(fc._peers.get('z-remote').pc).toBe(ownPc)
    expect(ownPc.closed).toBe(false)
    expect(ownPc.signalingState).toBe('have-local-offer')
    expect(ownPc.remoteDescription).toBeNull()
    expect(FakePC.instances.length).toBe(pcCountBefore)
    expect(sentTypes(signal)).toEqual(['offer'])   // still only our own offer

    fc.leave()
  })

  it('polite side (peerId > remote) rolls back its own offer and answers', async () => {
    // 'z-local' > 'a-remote' → polite === true.
    const { fc, signal } = await bootFabric('z-local')

    // Put a local offer in flight by hand (over rendezvous both sides offer).
    const ps = fc._getOrCreatePeer('a-remote')
    const ownPc = fc._buildPC('a-remote', ps)
    ps.pc = ownPc
    await ownPc.setLocalDescription(await ownPc.createOffer())
    expect(ownPc.signalingState).toBe('have-local-offer')

    await fc._onSignal({ from: 'a-remote', payload: { type: 'offer', sdp: 'v=0-their-offer' } })
    await flush()

    // Rolled back: the old pc was reset()/closed and replaced, and we answered.
    expect(ownPc.closed).toBe(true)
    expect(fc._peers.get('a-remote').pc).not.toBe(ownPc)
    expect(sentTypes(signal)).toContain('answer')
    expect(fc._peers.get('a-remote').state).toBe('connecting')

    fc.leave()
  })

  it('exactly one of the two colliding offers survives (both sides together)', async () => {
    // The whole point of the tie-break: run both roles over the same collision
    // and assert precisely one side answers and precisely one keeps its offer.
    const impolite = await bootFabric('a-peer')     // 'a-peer' < 'z-peer'
    const polite = await bootFabric('z-peer')       // 'z-peer' > 'a-peer'

    // Both put an offer in flight.
    impolite.ws._message({ channel: 'signal', from: 'z-peer', payload: { type: 'join', session: 'sess-1' } })
    await flush()
    const impolitePs = impolite.fc._peers.get('z-peer')
    const impolitePc = impolitePs.pc

    const politePs = polite.fc._getOrCreatePeer('a-peer')
    const politePc = polite.fc._buildPC('a-peer', politePs)
    politePs.pc = politePc
    await politePc.setLocalDescription(await politePc.createOffer())

    // Each receives the other's offer.
    await impolite.fc._onSignal({ from: 'z-peer', payload: { type: 'offer', sdp: 'from-z' } })
    await polite.fc._onSignal({ from: 'a-peer', payload: { type: 'offer', sdp: 'from-a' } })
    await flush()

    const answered = [
      sentTypes(impolite.signal).includes('answer'),
      sentTypes(polite.signal).includes('answer'),
    ]
    expect(answered.filter(Boolean)).toHaveLength(1)   // exactly one answers
    expect(answered).toEqual([false, true])            // and it is the polite one

    // The impolite side's own offer is the survivor.
    expect(impolite.fc._peers.get('z-peer').pc).toBe(impolitePc)
    expect(impolitePc.closed).toBe(false)
    expect(politePc.closed).toBe(true)

    impolite.fc.leave()
    polite.fc.leave()
  })

  it('a non-colliding offer is still answered (host-box WebSocket path unchanged)', async () => {
    // Impolite side, but with NO local offer in flight — the guard must not fire.
    const { fc, signal } = await bootFabric('a-local')

    await fc._onSignal({ from: 'z-remote', payload: { type: 'offer', sdp: 'v=0-their-offer' } })
    await flush()

    expect(sentTypes(signal)).toEqual(['answer'])
    const ps = fc._peers.get('z-remote')
    expect(ps.pc).not.toBeNull()
    expect(ps.state).toBe('connecting')

    fc.leave()
  })

  it('an offer arriving on a settled (non have-local-offer) pc is answered, not ignored', async () => {
    // Renegotiation after a completed handshake must still be honoured on the
    // impolite side — only 'have-local-offer' counts as a collision.
    const { fc, signal } = await bootFabric('a-local')

    const ps = fc._getOrCreatePeer('z-remote')
    const stalePc = fc._buildPC('z-remote', ps)
    ps.pc = stalePc
    stalePc.signalingState = 'stable'

    await fc._onSignal({ from: 'z-remote', payload: { type: 'offer', sdp: 'v=0-renegotiate' } })
    await flush()

    expect(sentTypes(signal)).toContain('answer')
    expect(stalePc.closed).toBe(true)

    fc.leave()
  })
})

// ── 2. RECONNECT ────────────────────────────────────────────────────────────

/** Connect a peer end-to-end and hand back the pieces the tests poke at. */
async function bootConnectedPeer(peerId = 'a-local', remoteId = 'z-remote') {
  const { fc, ws, signal } = await bootFabric(peerId)
  ws._message({ channel: 'signal', from: remoteId, payload: { type: 'join', session: 'sess-1' } })
  await flush()
  const pc = FakePC.last
  const dc = pc._dc
  dc._open()
  expect(fc._peers.get(remoteId).state).toBe('connected')
  return { fc, ws, signal, pc, dc, ps: fc._peers.get(remoteId) }
}

describe('FabricClient — persistent reconnect with exponential back-off', () => {
  it('a data-channel close triggers MORE THAN ONE reinitiate, with growing back-off', async () => {
    const { fc, dc, ps } = await bootConnectedPeer()
    const attempts = vi.spyOn(fc, '_initiatePeer').mockResolvedValue(undefined)

    vi.useFakeTimers()
    dc.close()
    expect(ps.state).toBe('disconnected')

    // Nothing before the first 2s window.
    vi.advanceTimersByTime(1_999)
    expect(attempts).toHaveBeenCalledTimes(0)

    vi.advanceTimersByTime(1)
    expect(attempts).toHaveBeenCalledTimes(1)
    expect(ps.reinitDelay).toBe(4_000)          // next window has doubled

    // The second attempt does NOT fire on another 2s — the back-off grew.
    vi.advanceTimersByTime(2_000)
    expect(attempts).toHaveBeenCalledTimes(1)
    vi.advanceTimersByTime(2_000)
    expect(attempts).toHaveBeenCalledTimes(2)   // > 1 attempt: the regression
    expect(ps.reinitDelay).toBe(8_000)

    vi.advanceTimersByTime(8_000)
    expect(attempts).toHaveBeenCalledTimes(3)
    expect(ps.reinitDelay).toBe(16_000)

    // Back-off caps at 16s rather than growing without bound.
    vi.advanceTimersByTime(16_000)
    expect(attempts).toHaveBeenCalledTimes(4)
    expect(ps.reinitDelay).toBe(16_000)

    fc.leave()
  })

  it('attempts stop once the peer is connected again', async () => {
    const { fc, dc, ps } = await bootConnectedPeer()
    const attempts = vi.spyOn(fc, '_initiatePeer').mockResolvedValue(undefined)

    vi.useFakeTimers()
    dc.close()
    vi.advanceTimersByTime(2_000)
    expect(attempts).toHaveBeenCalledTimes(1)

    // The retry succeeded out-of-band.
    ps.state = 'connected'
    vi.advanceTimersByTime(4_000)
    expect(attempts).toHaveBeenCalledTimes(1)   // short-circuited, not rescheduled
    expect(ps.reinitDelay).toBe(0)              // back-off reset for next time

    vi.advanceTimersByTime(60_000)
    expect(attempts).toHaveBeenCalledTimes(1)

    fc.leave()
  })

  it('a data channel re-opening cancels the pending reinitiate and resets the back-off', async () => {
    const { fc, dc, ps } = await bootConnectedPeer()
    const attempts = vi.spyOn(fc, '_initiatePeer').mockResolvedValue(undefined)

    vi.useFakeTimers()
    dc.close()
    vi.advanceTimersByTime(2_000)
    expect(attempts).toHaveBeenCalledTimes(1)

    // The real success path: the data channel's 'open' handler fires.
    dc._open()
    expect(ps.state).toBe('connected')
    expect(ps.reinitDelay).toBe(0)

    vi.advanceTimersByTime(60_000)
    expect(attempts).toHaveBeenCalledTimes(1)

    fc.leave()
  })

  it('attempts stop on an explicit peer "leave"', async () => {
    const { fc, ws, dc, ps } = await bootConnectedPeer()
    const attempts = vi.spyOn(fc, '_initiatePeer').mockResolvedValue(undefined)

    vi.useFakeTimers()
    dc.close()
    vi.advanceTimersByTime(2_000)
    expect(attempts).toHaveBeenCalledTimes(1)

    ws._message({ channel: 'signal', from: 'z-remote', payload: { type: 'leave', session: 'sess-1' } })
    expect(ps.left).toBe(true)

    // A departed peer is not chased.
    vi.advanceTimersByTime(60_000)
    expect(attempts).toHaveBeenCalledTimes(1)

    fc.leave()
  })

  it('attempts stop when the client is torn down', async () => {
    const { fc, dc } = await bootConnectedPeer()
    const attempts = vi.spyOn(fc, '_initiatePeer').mockResolvedValue(undefined)

    vi.useFakeTimers()
    dc.close()
    vi.advanceTimersByTime(2_000)
    expect(attempts).toHaveBeenCalledTimes(1)

    fc.leave()   // _stopped = true + clearTimeout(ps.reinitTimer)

    vi.advanceTimersByTime(60_000)
    expect(attempts).toHaveBeenCalledTimes(1)
  })

  it('leave() clears pending reinit timers for every peer', async () => {
    const { fc, dc, ps } = await bootConnectedPeer()
    vi.spyOn(fc, '_initiatePeer').mockResolvedValue(undefined)

    vi.useFakeTimers()
    dc.close()
    expect(ps.reinitTimer).not.toBeNull()

    const cleared = vi.spyOn(globalThis, 'clearTimeout')
    fc.leave()
    expect(cleared).toHaveBeenCalledWith(ps.reinitTimer)
  })
})

// ── 3. RELAY SYMMETRY ───────────────────────────────────────────────────────

/** A plain peer-state literal, as the other relay tests use. */
function relayPeerLiteral(id, state) {
  return {
    id, state, dc: null, pc: null,
    relayTimer: null, reinitTimer: null, reinitDelay: 0, left: false,
    pendingCandidates: [], reset() {},
  }
}

describe('FabricClient — relay-circuit symmetry', () => {
  it('relay polling starts as soon as a negotiation is armed (not only after we give up)', async () => {
    const fc = makeFabric('a-local')
    await fc.join()

    const ps = relayPeerLiteral('z-remote', 'connecting')
    fc._peers.set('z-remote', ps)

    expect(fc._relayPollTimer).toBeFalsy()   // nothing armed yet
    fc._setRelayTimer('z-remote', ps)

    // The peer is still merely 'connecting' — polling must already be running,
    // because the far side may have fallen back before us and be depositing.
    expect(ps.state).toBe('connecting')
    expect(fc._relayPollTimer).toBeTruthy()

    fc.leave()
  })

  it('a peer in "connecting" is still polled for', async () => {
    const fc = makeFabric('local-peer')
    await fc.join()

    const pickups = []
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('pickup')) {
        pickups.push(String(url))
        return { ok: true, json: async () => ({ blobs: [] }) }
      }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    fc._peers.set('z-remote', relayPeerLiteral('z-remote', 'connecting'))
    fc._relayPollTimer = 999

    await fc._relayPoll()

    expect(pickups).toHaveLength(1)
    expect(fc._relayPollTimer).toBe(999)   // poll NOT torn down

    fc.leave()
  })

  it('polling still stops when every peer is connected or gone', async () => {
    const fc = makeFabric('local-peer')
    await fc.join()

    fc._peers.set('z-remote', relayPeerLiteral('z-remote', 'connected'))
    fc._relayPollTimer = 999
    await fc._relayPoll()
    expect(fc._relayPollTimer).toBeNull()

    fc.leave()
  })

  it('a decryptable blob from a "connecting" peer adopts the relay circuit for our sends', async () => {
    const fc = makeFabric('local-peer')
    await fc._ensureDepositKey()

    const { blob_b64, epk } = makeRelayBlob({
      recipientBoxPubB64: fc._boxPubKeyB64, to: 'local-peer', from: 'remote-peer',
      session: 'sess-1', data: 'over-the-circuit',
    })

    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('pickup')) {
        return { ok: true, json: async () => ({ blobs: [{ id: 'b-1', from: 'remote-peer', blob_b64, epk }] }) }
      }
      if (String(url).includes('ack')) return { ok: true }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const ps = relayPeerLiteral('remote-peer', 'connecting')
    ps.relayTimer = setTimeout(() => {}, 60_000)
    fc._peers.set('remote-peer', ps)

    const states = []
    fc.addEventListener('state', ({ detail }) => states.push(detail))
    const received = []
    fc.addEventListener('message', ({ detail }) => received.push(detail))

    await fc._relayPoll()

    expect(received).toEqual([{ from: 'remote-peer', data: 'over-the-circuit' }])
    expect(ps.state).toBe('relay')
    expect(states).toContainEqual({ peerId: 'remote-peer', state: 'relay' })

    // The point of adopting it: our own sends now take the circuit instead of
    // being silently dropped against a peer we still believed was connecting.
    const deposit = vi.spyOn(fc, '_relayDeposit').mockResolvedValue(undefined)
    fc.sendTo('remote-peer', 'reply')
    expect(deposit).toHaveBeenCalledWith('remote-peer', 'reply')

    fc.leave()
  })

  it('an already-connected peer is NOT demoted to relay by a stray blob', async () => {
    const fc = makeFabric('local-peer')
    await fc._ensureDepositKey()

    const { blob_b64, epk } = makeRelayBlob({
      recipientBoxPubB64: fc._boxPubKeyB64, to: 'local-peer', from: 'remote-peer',
      session: 'sess-1', data: 'late-blob',
    })

    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('pickup')) {
        return { ok: true, json: async () => ({ blobs: [{ id: 'b-2', from: 'remote-peer', blob_b64, epk }] }) }
      }
      if (String(url).includes('ack')) return { ok: true }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    const ps = relayPeerLiteral('remote-peer', 'connected')
    fc._peers.set('remote-peer', ps)

    await fc._relayPoll()

    expect(ps.state).toBe('connected')   // direct path wins
    fc.leave()
  })
})
