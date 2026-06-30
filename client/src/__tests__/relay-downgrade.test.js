/**
 * relay-downgrade.test.js — forward-secrecy DOWNGRADE protection (security audit).
 *
 * THREAT: the signaling/relay server is untrusted transport.  The peer's "join"
 * frame carries its security-establishing fields — depositPubKey (identity),
 * boxPubKey (X25519), and signedPreKey (the X3DH prekey that enables FORWARD
 * SECRECY).  Forgery of the signedPreKey is already blocked (it carries its own
 * ECDSA signature, verified before storage).  But OMISSION was not: a malicious
 * server could simply STRIP the signedPreKey field from a v2-capable peer's join
 * → the receiver stored no prekey → the SENDER silently fell back to the v1
 * static-static path (NO forward secrecy).  This was undetectable.
 *
 * FIX under test:
 *   1. The join now carries a SIGNED `supportsV2:true` capability commitment
 *      (ECDSA over supportsV2 + depositPubKey + boxPubKey + nonce + ts).
 *   2. A receiver that verifies it PINS the peer as v2-capable.  The mutable
 *      signedPreKey is authenticated separately (its own sig), so STRIPPING it
 *      leaves the capability commitment intact → the peer is still pinned v2 but
 *      has no stored prekey.
 *   3. FabricClient._sealForPeer FAILS CLOSED for a pinned-v2 peer with no prekey
 *      (refuses v1) — so the stripped SPK is caught as an attack, not legacy.
 *   4. Genuine legacy v1 peers (no signed supportsV2) are never pinned → v1 stays
 *      available for them.
 *
 * Mock transport (FakeWebSocket); REAL WebCrypto so signatures are genuine.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'
import { relayBlobVersion } from '../relayBox.js'

// ── Canonical JOIN capability commitment — must match signaling.js _canonicalJoin
// EXACTLY (supportsV2 + depositPubKey + boxPubKey + nonce + ts; NO signedPreKey).
function canonicalJoin({ session, from, depositPubKey, boxPubKey, supportsV2, nonce, ts }) {
  return JSON.stringify({
    type: 'join',
    session,
    from,
    depositPubKey: depositPubKey ?? null,
    boxPubKey: boxPubKey ?? null,
    supportsV2: !!supportsV2,
    nonce,
    ts,
  })
}

// ── Fake WebSocket ────────────────────────────────────────────────────────────
class FakeWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  static CLOSED = 3
  static instances = []
  static last = null

  constructor(url, protocols) {
    this.url = url
    this.protocols = protocols || []
    this.readyState = FakeWebSocket.CONNECTING
    this.sent = []
    this._listeners = {}
    FakeWebSocket.instances.push(this)
    FakeWebSocket.last = this
  }
  addEventListener(evt, fn) { (this._listeners[evt] ||= []).push(fn) }
  send(data) { this.sent.push(data) }
  close() { this.readyState = FakeWebSocket.CLOSED; this._fire('close', {}) }
  _fire(evt, payload) { for (const fn of (this._listeners[evt] || [])) fn(payload) }
  _open() { this.readyState = FakeWebSocket.OPEN; this._fire('open', {}) }
  _message(frame) { this._fire('message', { data: typeof frame === 'string' ? frame : JSON.stringify(frame) }) }
}

class FakePC {
  static instances = []
  static last = null
  constructor() {
    this._listeners = {}
    this.connectionState = 'connecting'
    this.localDescription = null
    this.remoteDescription = null
    FakePC.instances.push(this)
    FakePC.last = this
  }
  addEventListener(evt, fn) { (this._listeners[evt] ||= []).push(fn) }
  _fire(evt, payload) { for (const fn of (this._listeners[evt] || [])) fn(payload) }
  createOffer()  { return Promise.resolve({ type: 'offer',  sdp: 'v=0 fake-offer' }) }
  createAnswer() { return Promise.resolve({ type: 'answer', sdp: 'v=0 fake-answer' }) }
  setLocalDescription(d)  { this.localDescription  = d; return Promise.resolve() }
  setRemoteDescription(d) { this.remoteDescription = d; return Promise.resolve() }
  addIceCandidate()       { return Promise.resolve() }
  close()                 { this.connectionState = 'closed' }
  createDataChannel() {
    return { readyState: 'connecting', binaryType: 'arraybuffer', sent: [], addEventListener() {}, send(d) { this.sent.push(d) }, close() {} }
  }
}

async function waitFor(condition, { timeout = 700, interval = 5 } = {}) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (await condition()) return
    await new Promise(r => setTimeout(r, interval))
  }
  throw new Error('waitFor: condition never true within ' + timeout + 'ms')
}
const sleep = ms => new Promise(r => setTimeout(r, ms))

function makeFabric(peerId, sessionId = 'sess-1') {
  return new FabricClient({ sessionId, peerId, signalingUrl: 'ws://localhost/sig', iceUrl: '/api/peering/ice', relayBaseUrl: '' })
}

/**
 * Build a v2-capable peer (real ECDSA identity, box key, signed prekey) and a
 * factory for its signed-join frame.  `stripSpk` omits signedPreKey; `tamperSig`
 * corrupts the join signature.
 */
async function makeV2Peer(peerId, sessionId = 'sess-1') {
  const fc = makeFabric(peerId, sessionId)
  await fc._ensurePreKeys()  // generates deposit key, box key, signed prekey
  async function signedJoin({ stripSpk = false, tamperSig = false } = {}) {
    const nonce = crypto.randomUUID()
    const ts = Date.now()
    const canon = canonicalJoin({
      session: sessionId, from: peerId,
      depositPubKey: fc._depositPubKeyB64, boxPubKey: fc._boxPubKeyB64,
      supportsV2: true, nonce, ts,
    })
    let sig = await fc._signDeposit(canon)
    if (tamperSig) {
      // Flip a byte so the signature no longer verifies under the real key.
      const raw = Uint8Array.from(atob(sig), c => c.charCodeAt(0))
      raw[0] ^= 0xff
      sig = btoa(String.fromCharCode(...raw))
    }
    const payload = {
      type: 'join', session: sessionId,
      depositPubKey: fc._depositPubKeyB64, boxPubKey: fc._boxPubKeyB64,
      supportsV2: true, nonce, ts, sig,
    }
    if (!stripSpk) payload.signedPreKey = fc._signedPreKeyPublic
    return { channel: 'signal', from: peerId, payload }
  }
  return { fc, signedJoin }
}

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
afterEach(() => { vi.restoreAllMocks() })

// ── D. Normal v2 round-trip still passes (signed join → pin + store SPK → v2) ──
describe('Downgrade protection — normal v2 path', () => {
  it('a valid signed join pins v2 capability, stores the SPK, and seals v2', async () => {
    const alice = makeFabric('alice')           // 'alice' < 'bob' → impolite/offerer
    const { fc: bob, signedJoin } = await makeV2Peer('bob')
    await alice.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message(await signedJoin())
    await waitFor(() => alice._signaling.isPeerV2Capable('bob'))
    await waitFor(() => alice._signaling._peerSignedPreKeys.has('bob'))

    expect(alice._signaling.isPeerV2Capable('bob')).toBe(true)
    expect(alice._signaling.getPeerSignedPreKey('bob')).toBeTruthy()

    // Seal a relay payload → must choose v2 (X3DH).  Host serves an OPK claim.
    const bobBundle = bob._preKeys.publicBundle('bob')
    let depositBody
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      const u = String(url)
      if (u.includes('prekeys/claim')) {
        return { ok: true, json: async () => ({ identity_vula_id: 'bob', signed_prekey: bob._signedPreKeyPublic, one_time_prekey: bobBundle.one_time_prekeys[0] }) }
      }
      if (u.includes('deposit')) { depositBody = JSON.parse(opts.body); return { ok: true } }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    await alice._relayDeposit('bob', { op: 'insert', text: 'fs-edit' })
    expect(depositBody).toBeTruthy()
    expect(relayBlobVersion(depositBody.blob_b64)).toBe(2)   // forward-secret path
    alice.leave(); bob.leave()
  })
})

// ── A. Stripped SPK from a v2-capable peer is DETECTED → no silent v1 downgrade ─
describe('Downgrade protection — stripped signed prekey', () => {
  it('pins v2 from the surviving capability commitment but stores NO prekey', async () => {
    const alice = makeFabric('alice')
    const { fc: bob, signedJoin } = await makeV2Peer('bob')
    await alice.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Server strips signedPreKey; supportsV2 commitment + sig survive (SPK is not
    // covered by the join signature) → still verifies → peer pinned v2-capable.
    ws._message(await signedJoin({ stripSpk: true }))
    await waitFor(() => alice._signaling.isPeerV2Capable('bob'))

    expect(alice._signaling.isPeerV2Capable('bob')).toBe(true)
    expect(alice._signaling.getPeerSignedPreKey('bob')).toBeNull()   // SPK stripped
    expect(alice._signaling.getPeerBoxKey('bob')).toBeTruthy()       // box key intact
    alice.leave(); bob.leave()
  })

  it('FAILS CLOSED on seal: no deposit (never falls back to v1 static-static)', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const alice = makeFabric('alice')
    const { fc: bob, signedJoin } = await makeV2Peer('bob')
    await alice.join()
    const ws = FakeWebSocket.last
    ws._open()

    ws._message(await signedJoin({ stripSpk: true }))
    await waitFor(() => alice._signaling.isPeerV2Capable('bob'))

    // Server also withholds the SPK from the claim endpoint (full strip).
    const deposits = []
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      const u = String(url)
      if (u.includes('prekeys/claim')) return { ok: false }      // no SPK via claim
      if (u.includes('deposit')) { deposits.push(JSON.parse(opts.body)); return { ok: true } }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    await alice._relayDeposit('bob', 'must-stay-forward-secret')

    // The seal aborted → NO blob deposited (no silent v1 downgrade, no plaintext).
    expect(deposits).toHaveLength(0)
    // And the abort was surfaced as a downgrade warning.
    const sawDowngradeWarn = warn.mock.calls.some(args => args.some(a => typeof a === 'string' && /downgrade/i.test(a)))
    expect(sawDowngradeWarn).toBe(true)
    alice.leave(); bob.leave()
  })
})

// ── B. A tampered join signature is rejected (capability NOT honored) ──────────
describe('Downgrade protection — tampered join signature', () => {
  it('does not pin v2 when the join signature fails to verify', async () => {
    const alice = makeFabric('alice')
    const { fc: bob, signedJoin } = await makeV2Peer('bob')
    await alice.join()
    const ws = FakeWebSocket.last
    ws._open()

    // supportsV2:true claimed, signedPreKey stripped, but the join sig is corrupt.
    // An unverifiable commitment must NOT be honored → peer not pinned v2.
    ws._message(await signedJoin({ stripSpk: true, tamperSig: true }))
    // Let the (failing) async verification settle.
    await waitFor(() => alice._signaling.hasPeerKey('bob'))   // identity TOFU still happens
    await sleep(60)

    expect(alice._signaling.isPeerV2Capable('bob')).toBe(false)
    expect(alice._signaling.getPeerSignedPreKey('bob')).toBeNull()
    alice.leave(); bob.leave()
  })
})

// ── C. Genuine legacy v1 peer still interoperates ─────────────────────────────
describe('Downgrade protection — legacy v1 peer', () => {
  it('an unsigned legacy join is not pinned v2, and seals over v1 (encrypted)', async () => {
    const alice = makeFabric('alice')
    const legacyBox = (await makeV2Peer('legacy')).fc._boxPubKeyB64  // borrow a real X25519 key
    await alice.join()
    const ws = FakeWebSocket.last
    ws._open()

    // Legacy peer: no sig, no supportsV2, no signedPreKey — just identity + box key.
    ws._message({
      channel: 'signal', from: 'legacy',
      payload: { type: 'join', session: 'sess-1', depositPubKey: 'unused', boxPubKey: legacyBox },
    })
    await waitFor(() => alice._signaling.getPeerBoxKey('legacy') !== null)
    await sleep(30)

    expect(alice._signaling.isPeerV2Capable('legacy')).toBe(false)

    let depositBody
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      const u = String(url)
      if (u.includes('prekeys/claim')) return { ok: false }     // legacy host: no prekeys
      if (u.includes('deposit')) { depositBody = JSON.parse(opts.body); return { ok: true } }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    await alice._relayDeposit('legacy', 'still-secret')
    expect(depositBody).toBeTruthy()
    expect(relayBlobVersion(depositBody.blob_b64)).toBe(1)        // v1 allowed for legacy
    expect(atob(depositBody.blob_b64)).not.toContain('still-secret')  // still encrypted
    alice.leave()
  })
})
