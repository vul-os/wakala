# Wakala build backlog

Autonomous program: complete **Wakala** (broker reference implementation of the KOTVA
coordinator contract) and **envoir** (node-only), as **clean OSS**. Worked in 15-minute sonnet
waves. Status marks: `[ ]` todo · `[~]` in-progress · `[x]` done+green · `[!]` blocked (see
COORDINATION.md).

## Guardrails (every wave)
- Every code change MUST `cargo build` + `cargo test` **green** before commit. **Never commit red.**
- Depend on `kotva-core`/`kotva-mail` via the **pinned tag `core-v0.2.0`**, never HEAD (isango rule).
- Content-visibility per CONTRACT §3 + profile fixes, and declarations MUST match runtime reality:
  relay=`blind`/structural · media-relay=`blind-routing` · reachability-adapter=`blind-routing`
  (SNI-passthrough; `structural` only for own-domain names, `declared` for adapter-zone vanities) ·
  gateway=`terminating`.
- **No protocol token.** Billing settles in an existing stablecoin; stake in existing assets.
- Clean OSS: dual MIT/Apache headers, rustdoc on public items, tests, no secrets, no dead code.
- **Read** the kotva spec (`coordinator/CONTRACT.md`, `DIRECTION.md`, `STYLE.md`, `THREAT-MODEL.md`,
  `profiles/*`) — never edit it. Never touch envoir/kotva uncommitted WIP. Spec gaps → COORDINATION.md.

## Phase 0 — repo hygiene
- [ ] W0.1 Rewrite wakala `README.md` → Wakala = broker reference impl (the kinds, no-token billing, self-host). Clean OSS.
- [ ] W0.2 Verify GH description + topics updated (set outside loop).
- [ ] W0.3 OSS hygiene: CONTRIBUTING/SECURITY present, dual-license confirmed, `.github/` CI wired (Phase 4).

## Phase 1 — broker-economics (the billing model) [CORE, mostly unblocked]
- [ ] E1.1 `CoordinatorDescriptor` (signed, discovery-only, **no stake field**) — carries content-visibility `{class, level}` (CONTRACT §2.1/§2.4).
- [ ] E1.2 `SignedTariff` — per-kind price shape (metered/flat/free) (§6).
- [ ] E1.3 `UsageReceipt` — signed, delivered direct to payer, one-directional audit (§6).
- [ ] E1.4 Authz — authenticated-sender + per-address/per-rail scope (GatewayAuthz shape, §7.11.2/§26).
- [ ] E1.5 Content-visibility declaration + a runtime assertion that declared `{class,level}` matches actual behavior.
- [ ] E1.6 Settlement seam — stablecoin adapter (alloy/solana-sdk); on-rail stake verification (§6). **No token.**
- [ ] E1.7 Tests + rustdoc for broker-economics.

## Phase 2 — kinds
- [ ] K2.1 reachability-adapter — SNI-passthrough (content-blind), TLS-ALPN-01, fail-closed on absent/ECH SNI (profiles/reachability.md). Retire the Go L7-terminating path.
- [ ] K2.2 relay (mesh) — rust-libp2p Circuit Relay v2, `blind`/structural.
- [ ] K2.3 media-relay — webrtc-rs/turn or coturn orchestration; `blind-routing` over SFrame (profiles/rtc.md).
- [ ] K2.4 gateway (mail adapter) — complete per §7 (already folded); wire to broker-economics.
- [ ] K2.5 provisional kind interfaces behind the contract: indexer · labeler · matcher · arbiter · oracle · compute (trait + conformance; full impl deferred, clearly stubbed).

## Phase 3 — admin
- [ ] A3.1 Operator admin surface — enable/disable kinds, set tariffs, view metering/receipts, key mgmt, publish descriptor. CLI first; optional minimal web. Clean OSS.
- [ ] A3.2 Self-host quickstart + docker-compose for an operator.

## Phase 4 — conformance + CI
- [ ] C4.1 broker-conformance — assert each kind meets COORD-1..8 and its visibility declaration matches reality.
- [ ] C4.2 CI (GitHub Actions) — fmt + clippy + test + conformance.

## Phase 5 — envoir node-only
- [ ] N5.1 Remove the gateway crate from envoir (it now lives in wakala).
- [ ] N5.2 Re-point envoir substrate crates to `kotva-core@core-v0.2.0` (retire envoir's own `dmtap-core`).
- [ ] N5.3 envoir builds node-only, tests green.
- [ ] N5.4 Update envoir README → node-only (loses gateway).

## Done criteria
Wakala: all kinds present (real or contract-stubbed), broker-economics billing model complete,
admin surface, conformance + CI green, clean OSS + README/docs. Envoir: node-only, on
`kotva-core@core-v0.2.0`, green.
