# Wakala / envoir build — decision log

Append-only. One line per decision: `[YYYY-MM-DD tag] decision — rationale`. The autonomous
build loop appends here whenever it makes a non-obvious call.

## Standing decisions (seeded)
- `[2026-07-23 name]` Umbrella term = **wakala** (provisional; repo named). "broker" considered, not adopted.
- `[2026-07-23 lang]` **All-Rust.** The Go reverse-tunnel + `@vulos/relay-client` JS SDK are preserved until the Rust port is proven, then retired.
- `[2026-07-23 core]` `kotva-core`/`kotva-mail` are crates **in the kotva repo**; consumers pin tag **`core-v0.2.0`** (never HEAD). Solves the isango churn failure.
- `[2026-07-23 wire]` DS-tags stay `dmtap-*` (wire byte-identical); only crate identifiers renamed `dmtap_core`→`kotva_core`. Renaming DS-tags to `kotva-*` is a **wire-breaking** change **not** made — deferred, spec-side call.
- `[2026-07-23 fold]` Mail gateway folded envoir → `wakala/crates/gateway` as the `terminating` mail-adapter kind.
- `[2026-07-23 econ]` **No protocol token.** Billing settles in an existing stablecoin; coordinator stake is in existing assets, verified on-rail.
- `[2026-07-23 vis]` Per-kind content-visibility: relay=`blind` · media-relay=`blind-routing` · reachability-adapter=`blind-routing` (SNI-passthrough; `structural` only for own-domain, `declared` for adapter vanities) · gateway=`terminating`.
- `[2026-07-23 sfu]` Large-scale SFU is **orchestrated externally** (coturn/LiveKit sidecar), not embedded — per bind-don't-reinvent.

## Loop decisions
<!-- the build loop appends below -->
