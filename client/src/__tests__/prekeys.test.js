/**
 * prekeys.test.js — X3DH forward-secret content-key scheme (FS hardening).
 *
 * Asserts:
 *   • x3dhKDF reproduces the Go reference vector (prekeys.go:x3dhKDF) byte-for-byte.
 *   • initiate ↔ respond derive the SAME SK (JS↔JS agreement), with and without
 *     a one-time prekey.
 *   • salt is order-independent in the two ids (sorted), like the Go reference.
 *   • the signed-prekey ECDSA signature gates use (verify fails closed).
 *   • the v2 wire blob round-trips, and tamper / wrong-key / replay are rejected.
 *   • FORWARD SECRECY: once the one-time prekey is consumed (deleted), a CAPTURED
 *     v2 ciphertext can no longer be decrypted.
 *   • OPK-exhausted falls back to signed-prekey-only v2 (still no static-identity
 *     dependence for content secrecy).
 */

import { describe, it, expect } from 'vitest'
import {
  x3dhKDF, x3dhInitiate, x3dhRespond,
  generateSignedPreKey, verifySignedPreKey, PreKeyStore,
} from '../prekeys.js'
import {
  generateBoxKeyPair, sealRelayBlobV2, parseRelayBlobV2, openRelayBlobV2,
  relayBlobVersion, bytesToB64, b64ToBytes,
} from '../relayBox.js'

const hex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('')
const dec = (b) => new TextDecoder().decode(b)
const enc = (s) => new TextEncoder().encode(s)

function fill(n, b) { const u = new Uint8Array(n); u.fill(b); return u }
function cat(arrs) {
  let n = 0; for (const a of arrs) n += a.length
  const out = new Uint8Array(n); let o = 0
  for (const a of arrs) { out.set(a, o); o += a.length }
  return out
}

// ── ECDSA P-256 sign/verify closures (mirror FabricClient identity) ───────────
async function makeIdentity() {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
  )
  const signRaw = async (bytes) => {
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, bytes)
    return bytesToB64(new Uint8Array(sig))
  }
  const verifyRaw = async (bytes, sigB64) =>
    crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, b64ToBytes(sigB64), bytes)
  return { signRaw, verifyRaw }
}

describe('prekeys — Go KDF reference vector', () => {
  // Computed independently (Python RFC-5869 HKDF) AND confirmed by running the
  // real Go prekeys.go:x3dhKDF over the same inputs:
  //   ikm = 0xFF*32 || dh1||dh2||dh3[||dh4],  salt = sort(id)[":"],  info label.
  it('matches the Go x3dhKDF output (with one-time prekey)', () => {
    const concat = cat([fill(32, 1), fill(32, 2), fill(32, 3), fill(32, 4)])
    expect(hex(x3dhKDF(concat, 'alice', 'bob')))
      .toBe('b1e975484a474f7ae3b4310c2123e04603511703302b0120dac741a0fd5aa1e2')
  })

  it('matches the Go x3dhKDF output (signed-prekey only)', () => {
    const concat = cat([fill(32, 1), fill(32, 2), fill(32, 3)])
    expect(hex(x3dhKDF(concat, 'alice', 'bob')))
      .toBe('61fd32e241ed0314db38189560f1485c43fac046c221d00ba488389cf18015ae')
  })

  it('salt is order-independent in the two ids (sorted, like Go)', () => {
    const concat = cat([fill(32, 1), fill(32, 2), fill(32, 3)])
    expect(hex(x3dhKDF(concat, 'bob', 'alice')))
      .toBe(hex(x3dhKDF(concat, 'alice', 'bob')))
  })
})

describe('prekeys — X3DH initiate/respond agreement (JS↔JS)', () => {
  it('derive the same SK with a one-time prekey', () => {
    const sender = generateBoxKeyPair()
    const recip = generateBoxKeyPair()
    const spk = generateBoxKeyPair()
    const opk = generateBoxKeyPair()

    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey,
      recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: spk.publicKey,
      oneTimePreKeyPub: opk.publicKey,
      senderId: 'alice', recipientId: 'bob',
    })
    const sk2 = x3dhRespond({
      identityPriv: recip.privateKey,
      senderIdentityPub: sender.publicKey,
      signedPreKeyPriv: spk.privateKey,
      oneTimePreKeyPriv: opk.privateKey,
      ephemeralPub,
      senderId: 'alice', recipientId: 'bob',
    })
    expect(hex(sk2)).toBe(hex(sk))
  })

  it('derive the same SK without a one-time prekey (fallback)', () => {
    const sender = generateBoxKeyPair()
    const recip = generateBoxKeyPair()
    const spk = generateBoxKeyPair()

    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey,
      recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: spk.publicKey,
      oneTimePreKeyPub: null,
      senderId: 'alice', recipientId: 'bob',
    })
    const sk2 = x3dhRespond({
      identityPriv: recip.privateKey,
      senderIdentityPub: sender.publicKey,
      signedPreKeyPriv: spk.privateKey,
      oneTimePreKeyPriv: null,
      ephemeralPub,
      senderId: 'alice', recipientId: 'bob',
    })
    expect(hex(sk2)).toBe(hex(sk))
    // Content secrecy does NOT reduce to static identity ECDH: a fresh ephemeral
    // means a different SK every send even with the same identities + SPK.
    const again = x3dhInitiate({
      identityPriv: sender.privateKey,
      recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: spk.publicKey,
      oneTimePreKeyPub: null,
      senderId: 'alice', recipientId: 'bob',
    })
    expect(hex(again.sk)).not.toBe(hex(sk))
  })

  it('a wrong recipient identity yields a different SK', () => {
    const sender = generateBoxKeyPair()
    const recip = generateBoxKeyPair()
    const wrong = generateBoxKeyPair()
    const spk = generateBoxKeyPair()
    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey,
      recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: spk.publicKey,
      senderId: 'alice', recipientId: 'bob',
    })
    const skWrong = x3dhRespond({
      identityPriv: wrong.privateKey,           // attacker's identity
      senderIdentityPub: sender.publicKey,
      signedPreKeyPriv: spk.privateKey,
      ephemeralPub,
      senderId: 'alice', recipientId: 'bob',
    })
    expect(hex(skWrong)).not.toBe(hex(sk))
  })
})

describe('prekeys — signed prekey signature (ECDSA, fail closed)', () => {
  it('a valid signed prekey verifies; a forged pub is rejected', async () => {
    const { signRaw, verifyRaw } = await makeIdentity()
    const spk = await generateSignedPreKey(signRaw)
    expect(await verifySignedPreKey(verifyRaw, { pub: spk.pubB64, sig: spk.sigB64 })).toBe(true)

    // Swap the public key but keep the signature → must fail.
    const forged = generateBoxKeyPair()
    expect(await verifySignedPreKey(verifyRaw, { pub: forged.publicKeyB64, sig: spk.sigB64 })).toBe(false)

    // A signed prekey from a DIFFERENT identity does not verify under this one.
    const other = await makeIdentity()
    const spk2 = await generateSignedPreKey(other.signRaw)
    expect(await verifySignedPreKey(verifyRaw, { pub: spk2.pubB64, sig: spk2.sigB64 })).toBe(false)
  })
})

describe('prekeys — v2 wire blob round-trip + tamper/replay', () => {
  async function setup() {
    const { signRaw } = await makeIdentity()
    const sender = generateBoxKeyPair()
    const recip = generateBoxKeyPair()
    const store = await PreKeyStore.create(signRaw, 4)     // recipient prekey store
    const bundle = store.publicBundle('bob')
    const opkPub = bundle.one_time_prekeys[0]
    return { sender, recip, store, bundle, opkPub }
  }

  it('seals → opens for the legitimate recipient (with OPK)', async () => {
    const { sender, recip, store, bundle, opkPub } = await setup()
    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey,
      recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: b64ToBytes(bundle.signed_prekey.pub),
      oneTimePreKeyPub: b64ToBytes(opkPub.pub),
      senderId: 'alice', recipientId: 'bob',
    })
    const blob = sealRelayBlobV2({
      plaintext: enc(JSON.stringify({ session: 's1', data: 'fwd-secret' })),
      key: sk, ephemeralPub,
      signedPreKeyId: bundle.signed_prekey.id, oneTimePreKeyId: opkPub.id,
      from: 'alice', to: 'bob', session: 's1',
    })
    expect(relayBlobVersion(blob)).toBe(2)

    const parsed = parseRelayBlobV2(blob)
    expect(parsed.oneTimePreKeyId).toBe(opkPub.id)
    const sk2 = x3dhRespond({
      identityPriv: recip.privateKey,
      senderIdentityPub: sender.publicKey,
      signedPreKeyPriv: store.signedPreKeyPriv(parsed.signedPreKeyId),
      oneTimePreKeyPriv: store.oneTimePreKeyPriv(parsed.oneTimePreKeyId),
      ephemeralPub: parsed.ephemeralPub,
      senderId: 'alice', recipientId: 'bob',
    })
    const pt = openRelayBlobV2({ parsed, key: sk2, from: 'alice', to: 'bob', session: 's1' })
    expect(JSON.parse(dec(pt))).toEqual({ session: 's1', data: 'fwd-secret' })
  })

  it('the blob is ciphertext — no plaintext, header carries no secret', async () => {
    const { sender, recip, bundle, opkPub } = await setup()
    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey, recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: b64ToBytes(bundle.signed_prekey.pub),
      oneTimePreKeyPub: b64ToBytes(opkPub.pub), senderId: 'alice', recipientId: 'bob',
    })
    const blob = sealRelayBlobV2({
      plaintext: enc('TOP-SECRET-V2'), key: sk, ephemeralPub,
      signedPreKeyId: bundle.signed_prekey.id, oneTimePreKeyId: opkPub.id,
      from: 'alice', to: 'bob', session: 's1',
    })
    expect(dec(b64ToBytes(blob))).not.toContain('TOP-SECRET-V2')
  })

  it('tampering with the ephemeral key in the header fails decryption', async () => {
    const { sender, recip, store, bundle, opkPub } = await setup()
    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey, recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: b64ToBytes(bundle.signed_prekey.pub),
      oneTimePreKeyPub: b64ToBytes(opkPub.pub), senderId: 'alice', recipientId: 'bob',
    })
    const blob = sealRelayBlobV2({
      plaintext: enc('x'), key: sk, ephemeralPub,
      signedPreKeyId: bundle.signed_prekey.id, oneTimePreKeyId: opkPub.id,
      from: 'alice', to: 'bob', session: 's1',
    })
    // Flip a byte inside the header region (the ek) and re-encode.
    const raw = b64ToBytes(blob)
    raw[6] ^= 0xff   // somewhere inside headerJSON
    const tampered = bytesToB64(raw)
    expect(() => {
      const parsed = parseRelayBlobV2(tampered)
      const sk2 = x3dhRespond({
        identityPriv: recip.privateKey, senderIdentityPub: sender.publicKey,
        signedPreKeyPriv: store.signedPreKeyPriv(parsed.signedPreKeyId),
        oneTimePreKeyPriv: store.oneTimePreKeyPriv(parsed.oneTimePreKeyId),
        ephemeralPub: parsed.ephemeralPub, senderId: 'alice', recipientId: 'bob',
      })
      openRelayBlobV2({ parsed, key: sk2, from: 'alice', to: 'bob', session: 's1' })
    }).toThrow()
  })

  it('FORWARD SECRECY: a captured v2 blob is undecryptable after the OPK is consumed', async () => {
    const { sender, recip, store, bundle, opkPub } = await setup()
    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey, recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: b64ToBytes(bundle.signed_prekey.pub),
      oneTimePreKeyPub: b64ToBytes(opkPub.pub), senderId: 'alice', recipientId: 'bob',
    })
    const blob = sealRelayBlobV2({
      plaintext: enc('one-shot'), key: sk, ephemeralPub,
      signedPreKeyId: bundle.signed_prekey.id, oneTimePreKeyId: opkPub.id,
      from: 'alice', to: 'bob', session: 's1',
    })
    const parsed = parseRelayBlobV2(blob)

    // First open succeeds, then the recipient deletes the one-time prekey.
    const sk2 = x3dhRespond({
      identityPriv: recip.privateKey, senderIdentityPub: sender.publicKey,
      signedPreKeyPriv: store.signedPreKeyPriv(parsed.signedPreKeyId),
      oneTimePreKeyPriv: store.oneTimePreKeyPriv(parsed.oneTimePreKeyId),
      ephemeralPub: parsed.ephemeralPub, senderId: 'alice', recipientId: 'bob',
    })
    expect(dec(openRelayBlobV2({ parsed, key: sk2, from: 'alice', to: 'bob', session: 's1' }))).toBe('one-shot')
    expect(store.consumeOneTimePreKey(parsed.oneTimePreKeyId)).toBe(true)

    // An adversary who LATER compromises the signed-prekey + identity keys still
    // cannot reconstruct SK from the CAPTURED blob: the one-time prekey private
    // scalar is gone (replay also rejected — the OPK is unknown now).
    expect(store.oneTimePreKeyPriv(parsed.oneTimePreKeyId)).toBe(null)
    expect(store.consumeOneTimePreKey(parsed.oneTimePreKeyId)).toBe(false)  // replay rejected
  })

  it('OPK-exhausted: signed-prekey-only v2 still round-trips', async () => {
    const { signRaw } = await makeIdentity()
    const sender = generateBoxKeyPair()
    const recip = generateBoxKeyPair()
    const store = await PreKeyStore.create(signRaw, 0)   // empty OPK pool
    const bundle = store.publicBundle('bob')
    expect(bundle.one_time_prekeys).toEqual([])

    const { ephemeralPub, sk } = x3dhInitiate({
      identityPriv: sender.privateKey, recipientIdentityPub: recip.publicKey,
      signedPreKeyPub: b64ToBytes(bundle.signed_prekey.pub),
      oneTimePreKeyPub: null, senderId: 'alice', recipientId: 'bob',
    })
    const blob = sealRelayBlobV2({
      plaintext: enc('spk-only'), key: sk, ephemeralPub,
      signedPreKeyId: bundle.signed_prekey.id, oneTimePreKeyId: null,
      from: 'alice', to: 'bob', session: 's1',
    })
    const parsed = parseRelayBlobV2(blob)
    expect(parsed.oneTimePreKeyId).toBe(null)
    const sk2 = x3dhRespond({
      identityPriv: recip.privateKey, senderIdentityPub: sender.publicKey,
      signedPreKeyPriv: store.signedPreKeyPriv(parsed.signedPreKeyId),
      oneTimePreKeyPriv: null, ephemeralPub: parsed.ephemeralPub,
      senderId: 'alice', recipientId: 'bob',
    })
    expect(dec(openRelayBlobV2({ parsed, key: sk2, from: 'alice', to: 'bob', session: 's1' }))).toBe('spk-only')
  })
})
