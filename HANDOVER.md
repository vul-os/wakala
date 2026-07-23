# Wakala — build handover

You are taking over the **Wakala** build. This file is your brief. Read it fully, then the
referenced KOTVA spec docs and the memories listed at the bottom, then begin at **Build order**.

## What Wakala is

Wakala is the **broker (coordinator) reference implementation** of the KOTVA standard — the
single project that implements `coordinator/CONTRACT.md`. It houses every broker *kind*: relay,
media-relay, reachability-adapter, mail gateway (adapter), and scaffolding for
indexer/labeler/matcher/arbiter/oracle/compute. (*wakala* = Swahili for agent/agency — a
swappable, fee-taking service point acting on a network's behalf. Provisional; the umbrella-term
name is not final — see Open decisions.)

## Current state (as of handover)

- Renamed from `vulos-relay` (folder + remote → `git@github.com:vul-os/wakala.git`). GitHub
  description/topics may still read "relay" — update them.
- Existing code is **Go** (a reverse-tunnel server, frp/ngrok replacement, wss + yamux,
  SSRF-guarded) + a **JS client SDK** (`@vulos/relay-client`, WebRTC peer-fabric). Clean tree,
  157 commits, all preserved.
- The relay is currently **content-visible at L7** — a known honesty gap. This MUST change to
  conform to spec (see guardrail 2).

## Target architecture (decided, do not re-litigate without the user)

- **All-Rust.** Rewrite the Go relay in Rust so the whole stack shares one core. envoir + soko
  are already Rust.
- **Depends on `kotva-core`** — a Rust crate in the kotva spec repo at `crates/kotva-core/`
  (substrate types: MOTE, envelope, identity/naming, PUB, SYNC, signing/DS-tags, MLS glue,
  CBOR, crypto). **Pin a tag, never track HEAD** (isango guardrail).
- **Implements the broker contract** (`coordinator/CONTRACT.md`): every kind is accountable /
  swappable / self-hostable / declares content-visibility (class × assurance level) /
  authorizes-never-classifies / signed tariff + usage receipts. **No token**; stake and settle
  in existing assets only.
- **Folds in the envoir mail gateway** (Rust) as the mail *adapter* kind — envoir then becomes
  node-only.

## Guardrails — do NOT skip

1. **isango lesson.** Extracting the gateway from envoir failed twice due to `dmtap-core` churn.
   So `kotva-core` MUST be a stable, versioned, **pinned** crate *before* the gateway is folded.
   Sequence: (a) carve `kotva-core` + tag it → (b) Wakala pins the tag → (c) fold the gateway.
   Do not port the gateway against an unstable core.
2. **Content-blindness is spec-mandated and per-kind** (`coordinator/CONTRACT.md` §3). Follow the
   spec, NOT the old relay's L7-visible behavior:
   - mesh **relay** = `blind` / structural (forwards ciphertext, holds no key)
   - **media-relay** = `blind-routing` (SFrame-sealed payload, routing metadata visible, RFC 9605)
   - **reachability-adapter** = `blind-routing` via SNI-passthrough (the box terminates TLS);
     `structural` only for own-domain names; `declared` for adapter-zone vanities (it *can* MITM
     those — disclose). See `profiles/reachability.md`.
3. **Preserve the Go code + history** until the Rust port is proven. Do not blind-delete working
   code. Keep the JS client SDK.
4. **Do not modify the kotva spec repo** — read it for the contract; the spec is owned by the
   spec session. If you find a spec gap or defect while implementing, log it in `COORDINATION.md`;
   do not edit the spec yourself.
5. **Do not modify envoir** until `kotva-core` is carved and agreed with the user.

## Build order

1. **Read the spec** (in the kotva repo, `~/code/vulos/kotva`): `coordinator/CONTRACT.md`,
   `DIRECTION.md`, `STYLE.md`, `THREAT-MODEL.md`, `bindings/README.md`, `profiles/reachability.md`,
   `profiles/rtc.md`, `profiles/media.md`.
2. **Scaffold** the Rust cargo workspace: one crate per kind + a shared `broker-economics` crate
   (authz / tariff / usage-receipts / content-visibility descriptor). Add a broker-contract
   conformance harness.
3. **Port the reverse-tunnel + reachability-adapter** to Rust (tokio, tokio-tungstenite, yamux),
   SNI-passthrough, content-blind per spec. Retire the L7-visible behavior.
4. **Media-relay** — `webrtc-rs`/`turn` crate, or orchestrate coturn/LiveKit as a sidecar for
   large SFU. `blind-routing` over SFrame.
5. **(Gated on `kotva-core`)** fold the envoir mail gateway in as the mail adapter.
6. **Conformance** — test each kind against the broker contract; assert content-visibility
   declarations match reality.

## Rust crate map (verified available)

libp2p → rust-libp2p · MLS → OpenMLS · SMTP → samotop/lettre · DKIM/SPF/DMARC → mail-auth (Stalwart) ·
tunnel → tokio-tungstenite + yamux · WebRTC/TURN → webrtc-rs + turn (or coturn sidecar) ·
HTTP → axum · CBOR → ciborium · crypto → ed25519-dalek/hpke-rs/blake3 · payments → alloy/solana-sdk ·
storage → iroh / Walrus SDK. (One caveat: large-scale SFU is orchestrated externally, not embedded.)

## Open decisions (confirm with the user via COORDINATION.md before large moves)

- Umbrella-term name: **wakala** (repo name) vs **broker** for the coordinator concept.
- `kotva-core` as a crate-in-kotva (`crates/kotva-core`, pinned tag — current lean) vs its own repo.
- Large-SFU: embed `webrtc-rs` vs orchestrate external LiveKit/coturn (lean: orchestrate).

## Memories to load first (in `~/.claude/projects/-Users-pc-code-vulos/memory/`)

- `kotva-substrate-rename-fold-2026-07-23.md` — **master**: the Wakala plan, kotva-core decision,
  isango reversal, primitive set, the 68-defect fix pass.
- `gateway-isango-in-place-decision-2026-07-23.md` — the isango history (**now reversed**: the
  gateway DOES leave envoir → wakala; the churn lesson still governs sequencing).
- `envoir-impl-status-2026-07-23.md` — envoir/gateway structure (what you're folding).
- `vulos-relay-sovereign-tunnel.md` — this relay's origin and design.
- `dmtap-vs-libp2p-reinvention-eval-2026-07-23.md` — libp2p is used off-the-shelf, not reinvented.
- `vulos-security-audit-2026-07-17.md` — the relay content-visible honesty gap you're closing.
- `vulos-infra-topology-2026-07.md` — relay deployment (Hetzner/Vultr).
- `envoir-dmtap-project.md` — project context; author imranparuk, **no co-author footer** on commits.

## Coordinating with the spec session

Append to `COORDINATION.md` in this repo. Commit + push so both sessions sync via git.
