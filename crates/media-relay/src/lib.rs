//! # media-relay — the `media-relay` coordinator kind (CONTRACT §5, `blind-routing`/`structural`)
//!
//! A **media-relay** forwards SFrame-sealed (RFC 9605) call/stream media so a host's own
//! bandwidth is not the size limit for a scaled call (DIRECTION §7). It is the `blind-routing`
//! row of `coordinator/CONTRACT.md` §3.1/§5 — distinct from both `relay` (`blind`/structural:
//! forwards opaque bytes with no visible structure at all) and `terminating` (a deliberate
//! plaintext trust boundary, e.g. the mail `gateway`). The media **payload** is sealed by
//! SFrame end-to-end between the call's own participants and this coordinator never holds the
//! key that would open it — but, unlike a pure `blind` relay, it MUST read **routing metadata**
//! (per-frame/packet size and timing, RTP routing, the participant graph) to do its forwarding
//! job at all. `blind-routing` names exactly that middle position, honestly, rather than
//! rounding it up to `blind` or down to `terminating`.
//!
//! ## Two halves, same split as the `relay` / `reachability-adapter` crates
//!
//! - [`sfu`] / [`external`] / [`mock`] — the **orchestration seam**: [`sfu::MediaSfu`] is the
//!   trait a real external SFU is coordinated through; [`external::ExternalSfu`] is the
//!   reference adapter for a real `coturn`/`livekit-server` sidecar; [`mock::MockSfu`] is an
//!   in-process fake for tests. **This is the actual content of this crate** — see those
//!   modules' docs for the honest-degrade contract and the generated sidecar configs.
//! - [`MediaRelayCoordinator`] (this module) — the `broker_conformance::Coordinator` posture:
//!   kind, declared visibility, and the CONTRACT §2/§4/§6 answers a media-relay operator gives.
//!   It composes a [`broker_economics::Descriptor`] signed by a real `kotva-core` `IdentityKey`;
//!   it does not itself forward a media byte (that is the orchestrated SFU's job, entirely
//!   outside this crate).
//!
//! ## Why the SFU is orchestrated, not embedded (DIRECTION §3, bind-don't-reinvent)
//!
//! Per the founder decision (wakala `DECISIONS.md`, `[2026-07-23 sfu]`) and DIRECTION §7, "the
//! large-scale SFU is orchestrated externally (coturn/LiveKit sidecar), not embedded." This
//! crate deliberately does **not**:
//!
//! - reimplement an SFU (packet forwarding, congestion control, simulcast/SVC selection) —
//!   that is [LiveKit](https://livekit.io) / Jitsi-Octo / mediasoup's job, adopted wholesale;
//! - reimplement SFrame (RFC 9605) or WebRTC — those are the client's job, riding the
//!   MLS → SFrame key schedule (DIRECTION §7, RTC.md §2.3/§27.5) entirely outside this crate;
//! - hold a media-decryption key of any kind, ever — there is structurally nothing key-shaped
//!   in [`sfu::SessionConfig`] or [`sfu::SfuHandle`], because the relay is not a party to the
//!   call's MLS group.
//!
//! What it *does* do is generate real sidecar configuration (a coturn `turnserver.conf`
//! fragment, a LiveKit-style config) and manage the sidecar as a **child process**, with an
//! honest degrade — see [`external::ExternalSfu`] — when the actual binary is not installed,
//! rather than a heavy embedded media/WebRTC dependency this crate pulls in and now owns the
//! bugs of.
//!
//! ## The `blind-routing` residual is disclosed, not hidden (CONTRACT §3.1, SEC-9)
//!
//! `blind-routing` is **not** `blind`. To forward a session's media at all, the SFU this crate
//! orchestrates reads: who is talking to whom, when, how much data, and the shape of the
//! participant graph (CONTRACT §3.1's own row for this kind; RTC.md §7 SEC-9/item 1: "An SFU
//! learns who is in the call, when it started and ended, how long it ran, who spoke when, who
//! shared a screen, and every participant's IP and rough location"). That metadata exposure is
//! the honest price of scaling a call past what direct mesh forwarding can carry — it is
//! disclosed here, in the descriptor's declared visibility, and to the calling client (RTC.md
//! R-RTC-3), never presented as though the coordinator saw nothing at all.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

pub mod external;
pub mod mock;
pub mod sfu;

pub use external::{CoturnConfig, ExternalSfu, ExternalSfuKind, LiveKitConfig};
pub use mock::MockSfu;
pub use sfu::{MediaSfu, SessionConfig, SfuError, SfuHandle, SfuStatus};

/// The declared content-visibility every conformant `media-relay` MUST publish (CONTRACT §5):
/// media payload sealed by SFrame (RFC 9605), routing metadata visible to forward it —
/// `blind-routing` at `structural` assurance, because the relay's lack of a media key is
/// architectural (the key never reaches it), not a promise. Not a default an operator can weaken
/// without it becoming a COORD-5 silent-downgrade violation the moment it diverges from the
/// descriptor.
pub const MEDIA_RELAY_VISIBILITY: ContentVisibility =
    ContentVisibility::new(VisibilityClass::BlindRouting, AssuranceLevel::Structural);

/// A `media-relay` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§6).
/// Pairs a signed [`Descriptor`] with the answers a media-relay operator gives to the four
/// conformance clauses. See the crate docs for the orchestration seam ([`sfu::MediaSfu`]) this
/// type is the discovery/posture half of.
pub struct MediaRelayCoordinator {
    descriptor: Descriptor,
    /// Whether this media-relay meters bandwidth and issues signed receipts (CONTRACT
    /// §6/COORD-7). Bandwidth metering via `broker-billing` is an optional seam — a media-relay
    /// pool run for free (the common case, per `SelfHost::Backstop`: anyone can run one) is
    /// `false`.
    metered: bool,
}

impl MediaRelayCoordinator {
    /// Wrap an already-built `MediaRelay`-kind, `blind-routing`/`structural` [`Descriptor`].
    /// Panics-free but does not itself validate `descriptor.kind`/`descriptor.visibility` — a
    /// caller that hands in the wrong kind/visibility gets exactly what
    /// `broker_conformance::check` is for: a COORD-1/COORD-4 finding, not a silent acceptance.
    /// Prefer [`MediaRelayCoordinator::signed`] for the common case of minting a fresh,
    /// correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `media-relay` descriptor from a real
    /// `kotva-core` identity — the [`Descriptor::sign`] path (CONTRACT §2.1: every coordinator
    /// MUST publish a signed descriptor under an attested identity, never a placeholder key).
    ///
    /// Returns both the [`MediaRelayCoordinator`] (for local posture/conformance use) and the
    /// [`SignedDescriptor`] (the wire form an operator actually publishes for discovery,
    /// independently verifiable via [`SignedDescriptor::verify`]).
    pub fn signed(
        ik: &IdentityKey,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::MediaRelay,
            visibility: MEDIA_RELAY_VISIBILITY,
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for MediaRelayCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::MediaRelay
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: switching media-relay pools (or the SFU behind one) is a config change
        // — re-point the call's signaling at a different pool/session. No user identity, keys,
        // MLS group state, or call history lives on a media-relay; the SFrame key root lives in
        // the call's own MLS epoch exporter (DIRECTION §7), entirely off this coordinator.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // NOT the scarce-reachability exception (CONTRACT §2.3's two disclosed members are
        // `gateway` and `reachability-adapter` only — see `CoordinatorKind::is_scarce_reachability`).
        // A media-relay pool is self-hostable by anyone who can run a coturn/LiveKit sidecar —
        // RTC.md §5's own "your own always-on box as SFU" middle rung. It needs bandwidth/CPU,
        // the same "run this on a cheap VPS" resource any self-hosted service needs, not an
        // ISP-allocated scarce one.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // A media-relay forwards SFrame-sealed media it cannot decrypt; it sits on no §4
        // delivery or canonical/authoritative *content* path to gate at all — admission control
        // is track/bitrate capacity (RTC.md R-RTC-4), never a content decision.
        Gate::NoDeliveryPath
    }

    fn metering(&self) -> Metering {
        // CONTRACT §6/COORD-7: if metered, signed usage receipts to the payer; else unmetered.
        // Wiring real receipts rides `broker-billing`'s `Meter`/`ReceiptLog` (optional; not
        // required for a conformant, free media-relay) — left to the operator composing this
        // crate, same seam shape as `relay`.
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // DIRECTION §5: no protocol token, ever. A metered media-relay settles bandwidth in an
        // existing stablecoin/fiat rail; `broker-billing::SettlementRail` is where that composes
        // in.
        Settlement::ExistingAssetsOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_conformance::check;

    fn ik(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    #[test]
    fn signed_media_relay_descriptor_verifies_and_declares_blind_routing_structural() {
        let (_coord, signed) = MediaRelayCoordinator::signed(&ik(1), Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "media-relay");
        assert!(
            signed.descriptor.visibility.is_verifiably_blind(),
            "media-relay MUST declare a verifiably-blind claim — blind-routing/structural"
        );
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::BlindRouting);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Structural);
    }

    #[test]
    fn blind_routing_is_distinct_from_blind_and_terminating() {
        // The specific footgun this kind exists to avoid getting wrong: rounding blind-routing
        // up to blind (overclaiming — the relay DOES see routing metadata) or down to
        // terminating (underclaiming — the payload genuinely is sealed).
        let v = MEDIA_RELAY_VISIBILITY;
        assert_eq!(v.class, VisibilityClass::BlindRouting);
        assert_ne!(v.class, VisibilityClass::Blind);
        assert_ne!(v.class, VisibilityClass::Terminating);
        // Still verifiably blind in the CONTRACT §3.4 sense (payload unreadable, provably).
        assert!(v.is_verifiably_blind());
        assert!(!v.must_not_present_as_verified());
    }

    #[test]
    fn a_free_media_relay_is_fully_conformant() {
        let (coord, _signed) = MediaRelayCoordinator::signed(&ik(2), Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_media_relay_is_also_conformant() {
        let (coord, _signed) = MediaRelayCoordinator::signed(&ik(3), Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    /// The specific footgun the crate docs' "not the scarce exception" note calls out: a
    /// media-relay MUST claim [`SelfHost::Backstop`], never
    /// [`SelfHost::ScarceReachabilityException`] (that exception's two members are `gateway` and
    /// `reachability-adapter` per `CoordinatorKind::is_scarce_reachability`). Assert both the
    /// posture *and* that the underlying kind is genuinely not in the scarce class.
    #[test]
    fn backstop_media_relay_is_not_the_scarce_exception() {
        let (coord, _signed) = MediaRelayCoordinator::signed(&ik(4), Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
        assert!(
            !CoordinatorKind::MediaRelay.is_scarce_reachability(),
            "media-relay must not be a member of the disclosed scarce-reachability exception class"
        );

        // A media-relay that mis-declared the scarce exception would still *pass* COORD-3 today
        // only if it really were a member of that class (`broker_conformance::check`'s COORD-3
        // arm checks membership) — demonstrate the violation directly.
        struct MisclaimedMediaRelay(Descriptor);
        impl Coordinator for MisclaimedMediaRelay {
            fn kind(&self) -> CoordinatorKind {
                CoordinatorKind::MediaRelay
            }
            fn descriptor(&self) -> &Descriptor {
                &self.0
            }
            fn lock_in(&self) -> LockIn {
                LockIn::None
            }
            fn self_host(&self) -> SelfHost {
                SelfHost::ScarceReachabilityException
            }
            fn delivery_path_gate(&self) -> Gate {
                Gate::NoDeliveryPath
            }
            fn metering(&self) -> Metering {
                Metering::NotMetered
            }
            fn settlement(&self) -> Settlement {
                Settlement::ExistingAssetsOnly
            }
        }
        let (_coord, signed) = MediaRelayCoordinator::signed(&ik(5), Cbor::empty(), None, false);
        let misclaimed = MisclaimedMediaRelay(signed.descriptor);
        let report = check(&misclaimed);
        assert!(
            !report.is_conformant(),
            "claiming the scarce-reachability exception for `media-relay` must be a COORD-3 violation"
        );
    }

    #[test]
    fn media_relay_has_no_delivery_path_to_gate() {
        let (coord, _signed) = MediaRelayCoordinator::signed(&ik(6), Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::NoDeliveryPath));
    }

    #[test]
    fn media_relay_mints_no_token() {
        let (coord, _signed) = MediaRelayCoordinator::signed(&ik(7), Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        // A media-relay coordinator built over a descriptor that claims a *different* kind (an
        // operator/config bug, not a spec-conformant media-relay) must fail the checklist rather
        // than be silently accepted — COORD-1 checks `descriptor.kind == coordinator.kind()`.
        let key = ik(8);
        let descriptor = Descriptor {
            identity: key.public(),
            kind: CoordinatorKind::Relay,
            visibility: MEDIA_RELAY_VISIBILITY,
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = MediaRelayCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
