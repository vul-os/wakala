/**
 * relay-forward-secrecy.test.js — X3DH (v2) on the wire at the FabricClient layer.
 *
 * Asserts the forward-secrecy property the relay path now provides end-to-end:
 *   1. alice→relay→bob round-trips over the v2 (X3DH) path, claiming a per-sender
 *      one-time prekey; the deposited blob is version 2.
 *   2. FORWARD SECRECY — once bob has picked the message up (consuming + deleting
 *      the one-time prekey), re-delivering the SAME captured blob yields nothing:
 *      the key material needed to re-derive SK is gone.
 *   3. A different peer (eve) cannot decrypt the captured v2 blob.
 *   4. NEGOTIATION — with no signed prekey available the sender stays on v1
 *      (still encrypted), never plaintext (fail-closed preserved).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FabricClient } from '../fabric.js'
import { relayBlobVersion } from '../relayBox.js'

function makeFabric(peerId, sessionId = 'sess-1') {
  return new FabricClient({ sessionId, peerId, signalingUrl: 'ws://localhost/sig', relayBaseUrl: '' })
}
function relayPeer(id) {
  return { id, state: 'relay', dc: null, pc: null, relayTimer: null, pendingCandidates: [], reset() {} }
}

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('Relay fallback — X3DH (v2) forward secrecy', () => {
  it('v2 round-trips, then the captured blob is undecryptable after pickup (FS)', async () => {
    const alice = makeFabric('alice')
    const bob = makeFabric('bob')
    const eve = makeFabric('eve')
    await alice._ensurePreKeys()
    await bob._ensurePreKeys()
    await eve._ensurePreKeys()

    // Exchange the box (identity) key + signed prekey, as the signaling 'join'
    // frames would. Set them directly (already-verified) to drive the v2 path.
    alice._signaling._peerBoxKeys.set('bob', bob._boxPubKeyB64)
    alice._signaling._peerSignedPreKeys.set('bob', bob._signedPreKeyPublic)

    // The host serves a per-sender one-time prekey from bob's published pool.
    const bobBundle = bob._preKeys.publicBundle('bob')
    const claimedOpk = bobBundle.one_time_prekeys[0]
    expect(claimedOpk).toBeTruthy()

    // Capture the deposit; answer the OPK claim with one of bob's real OPKs.
    let depositBody
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      const u = String(url)
      if (u.includes('prekeys/claim')) {
        return { ok: true, json: async () => ({
          identity_vula_id: 'bob',
          signed_prekey: bob._signedPreKeyPublic,
          one_time_prekey: claimedOpk,
        }) }
      }
      if (u.includes('deposit')) { depositBody = JSON.parse(opts.body); return { ok: true } }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    await alice._relayDeposit('bob', { op: 'insert', text: 'forward-secret edit' })
    expect(depositBody).toBeTruthy()
    expect(relayBlobVersion(depositBody.blob_b64)).toBe(2)   // X3DH path chosen

    // bob picks up → decrypts via v2 and consumes the one-time prekey.
    bob._peers.set('alice', relayPeer('alice'))
    const got = []
    bob.addEventListener('message', ({ detail }) => got.push(detail))
    const pickup = (body) => vi.stubGlobal('fetch', vi.fn(async (url) => {
      const u = String(url)
      if (u.includes('pickup')) return { ok: true, json: async () => ({ blobs: [body] }) }
      if (u.includes('ack')) return { ok: true }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))
    const blobMsg = { id: 'b1', from: 'alice', blob_b64: depositBody.blob_b64, epk: depositBody.epk, nonce: depositBody.nonce, sig: depositBody.sig }

    pickup(blobMsg)
    await bob._relayPoll()
    expect(got).toHaveLength(1)
    expect(got[0].data).toEqual({ op: 'insert', text: 'forward-secret edit' })

    // FORWARD SECRECY: the one-time prekey is now deleted; re-delivering the SAME
    // captured blob produces NOTHING (its SK can no longer be re-derived).
    expect(bob._preKeys.oneTimePreKeyPriv(claimedOpk.id)).toBe(null)
    got.length = 0
    pickup({ ...blobMsg, id: 'b2' })
    await bob._relayPoll()
    expect(got).toHaveLength(0)

    // A different peer cannot decrypt the captured v2 blob either.
    eve._peers.set('alice', relayPeer('alice'))
    const eveGot = []
    eve.addEventListener('message', ({ detail }) => eveGot.push(detail))
    pickup({ ...blobMsg, id: 'b3' })
    await eve._relayPoll()
    expect(eveGot).toHaveLength(0)

    alice.leave(); bob.leave(); eve.leave()
  })

  it('negotiation: no signed prekey → stays on v1 (encrypted), never plaintext', async () => {
    const alice = makeFabric('alice')
    const bob = makeFabric('bob')
    await alice._ensurePreKeys()
    await bob._ensurePreKeys()
    // Only the box key is known — NO signed prekey → v2 cannot be established.
    alice._signaling._peerBoxKeys.set('bob', bob._boxPubKeyB64)

    let depositBody
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      const u = String(url)
      if (u.includes('prekeys/claim')) return { ok: false }   // host has no bundle
      if (u.includes('deposit')) { depositBody = JSON.parse(opts.body); return { ok: true } }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))

    await alice._relayDeposit('bob', 'still-secret')
    expect(depositBody).toBeTruthy()
    expect(relayBlobVersion(depositBody.blob_b64)).toBe(1)   // v1 fallback
    // The relay still sees only ciphertext, not the plaintext envelope.
    expect(atob(depositBody.blob_b64)).not.toContain('still-secret')

    alice.leave(); bob.leave()
  })

  it('fail-closed: no recipient box key → deposit skipped (no plaintext), even with prekeys', async () => {
    const alice = makeFabric('alice')
    await alice._ensurePreKeys()
    const deposits = []
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      const u = String(url)
      if (u.includes('deposit')) deposits.push(JSON.parse(opts.body))
      if (u.includes('prekeys/claim')) return { ok: false }
      return { ok: true, json: async () => ({ ice_servers: [] }) }
    }))
    await alice._relayDeposit('bob', 'must-not-leak')
    expect(deposits).toHaveLength(0)
    alice.leave()
  })
})
