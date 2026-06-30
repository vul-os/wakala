/**
 * _relayTestUtil.js — helpers for building E2E-encrypted relay blobs in tests.
 *
 * Since the relay-fallback path now seals payloads with XChaCha20-Poly1305 from
 * X25519-ECDH (see src/relayBox.js), test fixtures can no longer hand-roll a
 * plaintext `btoa(JSON.stringify({session, data}))` blob and expect the pickup
 * path to dispatch it.  These helpers build a blob the way a real depositing
 * peer would, sealed to the receiving FabricClient's announced box key.
 */

import { generateBoxKeyPair, sealRelayBlob } from '../relayBox.js'

/**
 * Build an encrypted relay blob addressed to `recipientBoxPubB64`.
 *
 * @returns {{ blob_b64: string, epk: string, senderKP: object }}
 */
export function makeRelayBlob({ recipientBoxPubB64, to, from, session, data, senderKP }) {
  const kp = senderKP || generateBoxKeyPair()
  const plaintext = new TextEncoder().encode(JSON.stringify({ session, data }))
  const blob_b64 = sealRelayBlob({
    plaintext,
    senderBoxPriv: kp.privateKey,
    recipientBoxPubB64,
    from,
    to,
    session,
  })
  return { blob_b64, epk: kp.publicKeyB64, senderKP: kp }
}
