// Mirrors broker-economics/src/visibility.rs's ContentVisibility logic client-side, so the
// UI can decide what to show *before* round-tripping to the admin API (and so the mock
// backend and any future real backend agree on the same honesty rules).

import type { AssuranceLevel, VisibilityClass, VisibilityDto } from './types';

export function isVerifiable(level: AssuranceLevel): boolean {
  return level === 'structural' || level === 'attested';
}

/** True iff presenting this claim as *verified* would be a §3.4 violation — a declared-level
 * blind/blind-routing claim only, never terminating (which is disclosed, not "verified blind"). */
export function mustNotPresentAsVerified(v: VisibilityDto): boolean {
  return v.class !== 'terminating' && !isVerifiable(v.level);
}

export function isVerifiablyBlind(v: VisibilityDto): boolean {
  return v.class !== 'terminating' && isVerifiable(v.level);
}

const CLASS_RANK: Record<VisibilityClass, number> = { blind: 0, 'blind-routing': 1, terminating: 2 };
const LEVEL_RANK: Record<AssuranceLevel, number> = { structural: 0, attested: 1, declared: 2 };

export function isDowngrade(from: VisibilityDto, to: VisibilityDto): boolean {
  return (
    CLASS_RANK[to.class] > CLASS_RANK[from.class] ||
    (to.class === from.class && LEVEL_RANK[to.level] > LEVEL_RANK[from.level])
  );
}

export const CLASS_LABEL: Record<VisibilityClass, string> = {
  blind: 'Blind',
  'blind-routing': 'Blind-routing',
  terminating: 'Terminating',
};

export const CLASS_DESCRIPTION: Record<VisibilityClass, string> = {
  blind: 'Forwards/holds ciphertext; holds no key that decrypts the payload; reads neither content nor routing beyond the wire.',
  'blind-routing': 'Cannot read the payload; sees routing metadata — envelope, SNI, addresses, size, timing.',
  terminating: 'Terminates encryption and sees plaintext — a deliberate, disclosed trust boundary.',
};

export const LEVEL_LABEL: Record<AssuranceLevel, string> = {
  structural: 'Structural',
  attested: 'Attested',
  declared: 'Declared',
};

export const LEVEL_DESCRIPTION: Record<AssuranceLevel, string> = {
  structural: 'The role has no key at all — E2E encryption makes reading impossible. Provable.',
  attested: 'The role runs in a TEE that proves the code only forwards and holds no key. Hardware-trust, disclosed not trustless.',
  declared: 'The operator promises it is blind; nothing structurally prevents cheating. Honest-trust only.',
};
