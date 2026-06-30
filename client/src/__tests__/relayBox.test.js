/**
 * relayBox.test.js — unit tests for the relay-fallback E2E sealing primitives
 * (Fix 1: confidentiality).  Uses the real @noble/* primitives; no mocks.
 *
 * Properties asserted:
 *   • seal → open round-trips for the legitimate recipient.
 *   • The sealed blob is ciphertext: it does not contain the plaintext bytes
 *     and does not decode to JSON (the relay/host cannot read it).
 *   • A different recipient key cannot open the blob (X25519-ECDH binding).
 *   • The AAD binds {from, to, session}: changing any of them on open fails.
 *   • Tampering with the ciphertext is detected (Poly1305 auth tag).
 */

import { describe, it, expect } from 'vitest'
import {
  generateBoxKeyPair,
  sealRelayBlob,
  openRelayBlob,
  bytesToB64,
  b64ToBytes,
} from '../relayBox.js'

const enc = (s) => new TextEncoder().encode(s)
const dec = (b) => new TextDecoder().decode(b)

function seal(senderKP, recipientKP, { from = 'alice', to = 'bob', session = 'sess-1', data = 'secret' } = {}) {
  return sealRelayBlob({
    plaintext: enc(JSON.stringify({ session, data })),
    senderBoxPriv: senderKP.privateKey,
    recipientBoxPubB64: recipientKP.publicKeyB64,
    from, to, session,
  })
}

describe('relayBox — seal/open round-trip', () => {
  it('the legitimate recipient recovers the plaintext', () => {
    const alice = generateBoxKeyPair()
    const bob = generateBoxKeyPair()
    const blob = seal(alice, bob, { data: 'live-doc-edit' })

    const pt = openRelayBlob({
      blobB64: blob,
      recipientBoxPriv: bob.privateKey,
      senderBoxPubB64: alice.publicKeyB64,
      from: 'alice', to: 'bob', session: 'sess-1',
    })
    expect(JSON.parse(dec(pt))).toEqual({ session: 'sess-1', data: 'live-doc-edit' })
  })

  it('produces ciphertext — the relay sees no plaintext / no JSON', () => {
    const alice = generateBoxKeyPair()
    const bob = generateBoxKeyPair()
    const blob = seal(alice, bob, { data: 'TOP-SECRET-CURSOR' })

    const raw = b64ToBytes(blob)
    // Not parseable as JSON, and the marker string is absent from the bytes.
    let parsed = false
    try { JSON.parse(new TextDecoder().decode(raw)); parsed = true } catch { /* expected */ }
    expect(parsed).toBe(false)
    expect(dec(raw)).not.toContain('TOP-SECRET-CURSOR')
    // Version byte present.
    expect(raw[0]).toBe(0x01)
  })
})

describe('relayBox — confidentiality boundaries', () => {
  it('a different recipient key cannot open the blob', () => {
    const alice = generateBoxKeyPair()
    const bob = generateBoxKeyPair()
    const mallory = generateBoxKeyPair()
    const blob = seal(alice, bob)

    expect(() => openRelayBlob({
      blobB64: blob,
      recipientBoxPriv: mallory.privateKey,   // wrong key
      senderBoxPubB64: alice.publicKeyB64,
      from: 'alice', to: 'bob', session: 'sess-1',
    })).toThrow()
  })

  it('AAD binds the sender identity (wrong from fails)', () => {
    const alice = generateBoxKeyPair()
    const bob = generateBoxKeyPair()
    const blob = seal(alice, bob, { from: 'alice' })

    expect(() => openRelayBlob({
      blobB64: blob,
      recipientBoxPriv: bob.privateKey,
      senderBoxPubB64: alice.publicKeyB64,
      from: 'carol',          // attacker re-attributes the blob
      to: 'bob', session: 'sess-1',
    })).toThrow()
  })

  it('AAD binds the session (cross-session replay fails)', () => {
    const alice = generateBoxKeyPair()
    const bob = generateBoxKeyPair()
    const blob = seal(alice, bob, { session: 'sess-1' })

    expect(() => openRelayBlob({
      blobB64: blob,
      recipientBoxPriv: bob.privateKey,
      senderBoxPubB64: alice.publicKeyB64,
      from: 'alice', to: 'bob',
      session: 'sess-2',      // different session
    })).toThrow()
  })

  it('detects ciphertext tampering (Poly1305 auth tag)', () => {
    const alice = generateBoxKeyPair()
    const bob = generateBoxKeyPair()
    const blob = seal(alice, bob)

    const raw = b64ToBytes(blob)
    raw[raw.length - 1] ^= 0xff   // flip a tag byte
    const tampered = bytesToB64(raw)

    expect(() => openRelayBlob({
      blobB64: tampered,
      recipientBoxPriv: bob.privateKey,
      senderBoxPubB64: alice.publicKeyB64,
      from: 'alice', to: 'bob', session: 'sess-1',
    })).toThrow()
  })

  it('rejects an unknown blob version', () => {
    const alice = generateBoxKeyPair()
    const bob = generateBoxKeyPair()
    const raw = b64ToBytes(seal(alice, bob))
    raw[0] = 0x02   // bump version
    expect(() => openRelayBlob({
      blobB64: bytesToB64(raw),
      recipientBoxPriv: bob.privateKey,
      senderBoxPubB64: alice.publicKeyB64,
      from: 'alice', to: 'bob', session: 'sess-1',
    })).toThrow(/version/)
  })
})

describe('relayBox — base64 helpers', () => {
  it('bytesToB64 / b64ToBytes round-trip arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255, 128, 64])
    expect(Array.from(b64ToBytes(bytesToB64(bytes)))).toEqual(Array.from(bytes))
  })
})
