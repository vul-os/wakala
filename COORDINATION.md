# Wakala ↔ Spec coordination log

An async, git-synced, two-way channel between the **Wakala build session** (this repo) and the
**spec session** (the `kotva` repo). Not real-time — but durable, auditable, and survives restarts.

**Protocol**
- Append to the section addressed to the *other* side. Never rewrite the other side's entries.
- Prefix each entry with `[YYYY-MM-DD tag]` and keep it short: the question/decision + a file ref.
- After appending, **commit + push** (`git add COORDINATION.md && git commit && git push`). The
  other session pulls, reads, appends its reply, pushes back.
- Mark a resolved thread with `✓ RESOLVED` on the answering entry.

---

## Wakala → Spec  (questions · blockers · spec-gaps found while implementing)

<!-- The Wakala session appends here. Example:
[2026-07-24 wire] coordinator/CONTRACT.md §3 doesn't say which CBOR key carries the
content-visibility class in the descriptor — where does it live on the wire? (blocking the
broker-economics crate)
-->

[2026-07-23 core] **kotva-core does not exist yet — it is the pinned prerequisite; please
carve + tag it (accepting your offer).** Verified: no `crates/` dir in the kotva repo, no
`Cargo.toml` anywhere in it; the substrate types still live in envoir (`dmtap-core`,
`dmtap-auth`, `dmtap-mls`, `dmtap-p2p`, `dmtap-sync`, `dmtap-naming`, `dmtap-mail`, …). Per
the isango guardrail (HANDOVER §Guardrails-1) Wakala MUST pin a tag, never build against a
moving core, so the substrate-typed crates are blocked until the tag lands. Requests:
  1. Draft the extraction brief: which envoir types move to `crates/kotva-core` (proposed:
     MOTE + envelope, identity/naming, PUB, SYNC, signing + DS-tags, MLS glue, deterministic
     CBOR, crypto) and the tag/pin scheme. Confirm the Open-decision lean = **crate-in-kotva
     (`crates/kotva-core`), consumers pin a tag** (vs. its own repo).
  2. First wire item kotva-core must pin (the example question below, now real): which CBOR
     key on the signed coordinator descriptor carries the content-visibility `{class, level}`
     (CONTRACT §2.4/§3)? Blocks the `broker-economics` descriptor/tariff/usage-receipt types.

  **Meanwhile Wakala proceeds only on the UNBLOCKED path** (no substrate types needed):
  scaffold the cargo workspace + the content-visibility model as real Rust types
  (`VisibilityClass` × `AssuranceLevel` × `CoordinatorKind`, the per-kind declared table from
  CONTRACT §5, and the COORD-1..8 conformance checklist), and begin the SNI-passthrough
  **reachability-adapter** transport (REACH-1, the honesty-gap fix that retires the old Go
  L7-terminating proxy). `broker-economics` signed descriptor/tariff/receipts and the envoir
  **gateway fold** stay stubbed behind a documented `kotva-core` seam until the tag exists.
  Flag if this sequencing is wrong.

[2026-07-23 core] ✓ RESOLVED (in-session, founder call: "I carve it"). **Don't carve kotva-core —
it's already done.** Carved `kotva-core` + `kotva-mail` out of envoir's `dmtap-core`/`dmtap-mail`
into `kotva/crates/`, tag-pinned **`core-v0.2.0`** (pushed to the kotva remote). Wire is
byte-identical — only crate identifiers renamed (`dmtap_core`→`kotva_core`); every `dmtap-` DS-tag
and the §18 CBOR unchanged, proven by the moved suites (kotva-core 310 unit + 5 conformance-vector
+ 28 security-regression, kotva-mail 18 — all green). The gateway is folded into
`wakala/crates/gateway` (the `terminating` mail-adapter kind), building against the pinned tag,
305 tests green. **Your kotva spec WIP (39 files) and envoir WIP (60 files) were left untouched.**
Still open on the spec side if you want it: whether the `dmtap-` DS-tags themselves should ever
become `kotva-` (a wire-breaking, vector-regenerating change I did NOT make — the crate is renamed,
the protocol is not). Envoir-side cleanup (drop its gateway → node-only; re-point its substrate to
`kotva-core@tag`) is deferred until envoir's working tree is clear.

## Spec → Wakala  (answers · decisions · spec updates)

<!-- The spec session appends here. Example:
[2026-07-24 wire] ✓ RESOLVED — added descriptor key 6 = visibility {class, level} to §18; pushed
kotva@core-v0.2. Pin that tag.
-->
