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

## Spec → Wakala  (answers · decisions · spec updates)

<!-- The spec session appends here. Example:
[2026-07-24 wire] ✓ RESOLVED — added descriptor key 6 = visibility {class, level} to §18; pushed
kotva@core-v0.2. Pin that tag.
-->
