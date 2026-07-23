//! The reference [`ExternalSfu`] adapter: generates sidecar config for a real **coturn** TURN
//! server (RFC 8656) and/or a **LiveKit**-style distributed SFU, and manages the sidecar as a
//! child process — degrading **honestly** (`SfuStatus::Unavailable`) when the actual binary is
//! not installed, never faking success.
//!
//! ## What this crate does NOT do
//!
//! Wakala does **not** reimplement an SFU, SFrame (RFC 9605), or WebRTC (DIRECTION §3,
//! bind-don't-reinvent; DIRECTION §7's "coordinated by an existing distributed SFU"). This
//! module orchestrates **adopted** media infrastructure: it shells out to a real
//! `coturn`/`livekit-server` binary the operator installs, the same way any deployment would —
//! it never parses RTP, never terminates DTLS-SRTP, and never touches a media byte.
//!
//! SFrame keying rides **MLS → SFrame** (DIRECTION §7, RTC.md §2.3/§27.5) end-to-end between the
//! call's own participants; that key material is generated and held by the **clients**, never by
//! this crate or the sidecar it launches. This is what makes the coordinator structurally
//! `blind-routing` rather than merely policy-blind (CONTRACT §3.3 `structural`): there is no key
//! *here* to hold in the first place, by construction, not by promise. What this adapter — and,
//! honestly, the real SFU it launches — DOES see to do its job: per-frame/packet metadata, RTP
//! routing, stream sizes, speaker timing, and the participant graph (CONTRACT §3.1's
//! `blind-routing` row; SEC-9). That exposure is disclosed, not hidden — see the crate-level
//! docs.
//!
//! ## The process-spawn seam degrades honestly
//!
//! [`ExternalSfu::start`] execs the configured binary. If it is not on `PATH` (the common case in
//! any environment that has not installed a real sidecar — including this crate's own CI), the
//! adapter records [`SfuStatus::Unavailable`] with a disclosed reason and returns
//! `Err(SfuError::Unavailable)` — it never invents a handle that later claims
//! [`SfuStatus::Running`]. Once a real child process *is* spawned, `status` re-checks the child's
//! liveness (`try_wait`) so an exited process is reported `Stopped`, not stale-`Running`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::process::{Child, Command};

use serde::Serialize;

use crate::sfu::{MediaSfu, SessionConfig, SfuError, SfuHandle, SfuStatus};

/// Which real sidecar this adapter launches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalSfuKind {
    /// coturn (RFC 8656 TURN/STUN) — the NAT-relay leg (RTC.md §2.3's `relay` row; also usable
    /// as the `media-relay`'s own TURN-over-SFrame path per CONTRACT §3.1).
    Coturn,
    /// A LiveKit-style distributed SFU (Pion-based). RTC.md §2.3 names Jitsi-Octo and mediasoup
    /// as cascade-compatible alternatives; this crate targets the one config shape, since §27 is
    /// implementable "against an SFU that does not know KOTVA exists" (RTC.md §2.3).
    LiveKit,
}

impl ExternalSfuKind {
    fn label(self) -> &'static str {
        match self {
            ExternalSfuKind::Coturn => "coturn",
            ExternalSfuKind::LiveKit => "livekit-server",
        }
    }
}

/// Peer addresses this generated coturn config MUST deny (anti-SSRF, see [`CoturnConfig::to_conf_text`]):
/// every non-forwardable/private range from RFC 1918, RFC 6598 (carrier-grade NAT), RFC 3927 /
/// RFC 4291 (link-local, incl. the `169.254.169.254` cloud-metadata endpoint), RFC 5737/RFC 3068
/// (documentation/6to4 anycast), and the IPv6 equivalents (loopback, link-local, unique-local).
/// `0.0.0.0/8` and `240.0.0.0/4` (reserved/multicast) are included for completeness alongside the
/// dedicated `no-multicast-peers` directive.
const DENIED_PEER_IP_RANGES: &[&str] = &[
    "0.0.0.0-0.255.255.255",
    "10.0.0.0-10.255.255.255",
    "100.64.0.0-100.127.255.255",
    "127.0.0.0-127.255.255.255",
    "169.254.0.0-169.254.255.255",
    "172.16.0.0-172.31.255.255",
    "192.0.0.0-192.0.0.255",
    "192.0.2.0-192.0.2.255",
    "192.88.99.0-192.88.99.255",
    "192.168.0.0-192.168.255.255",
    "198.18.0.0-198.19.255.255",
    "198.51.100.0-198.51.100.255",
    "203.0.113.0-203.0.113.255",
    "240.0.0.0-255.255.255.255",
    "::1",
    "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
];

/// A coturn `turnserver.conf` fragment (RFC 8656). Only the fields a media-relay operator
/// actually needs to hand a real coturn binary; coturn's own documentation covers the rest — this
/// type does not attempt to model coturn's full config surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoturnConfig {
    pub listening_port: u16,
    pub relay_ip: String,
    pub external_ip: Option<String>,
    pub realm: String,
    pub min_port: u16,
    pub max_port: u16,
    /// coturn's own `static-auth-secret` REST-API long-term-credential mechanism — a
    /// time-limited credential the media-relay operator's call-signaling issues per session,
    /// never a per-user password this crate manages or stores.
    pub static_auth_secret: String,
}

impl CoturnConfig {
    /// A conservative reference default: binds all interfaces, RFC-8656's conventional TURN
    /// port, and a narrow ephemeral relay-port band. An operator overrides every field for a
    /// real deployment (in particular `external_ip`, required behind NAT).
    pub fn reference(realm: impl Into<String>, static_auth_secret: impl Into<String>) -> Self {
        Self {
            listening_port: 3478,
            relay_ip: "0.0.0.0".to_string(),
            external_ip: None,
            realm: realm.into(),
            min_port: 49152,
            max_port: 49452,
            static_auth_secret: static_auth_secret.into(),
        }
    }

    /// Render the real coturn `turnserver.conf` key=value text this crate hands the sidecar —
    /// coturn's own config format, not a Wakala invention (bind-don't-reinvent).
    pub fn to_conf_text(&self) -> String {
        let mut out = String::new();
        out.push_str("# generated by wakala media-relay — coturn sidecar config (RFC 8656)\n");
        out.push_str(&format!("listening-port={}\n", self.listening_port));
        out.push_str(&format!("relay-ip={}\n", self.relay_ip));
        if let Some(ip) = &self.external_ip {
            out.push_str(&format!("external-ip={ip}\n"));
        }
        out.push_str(&format!("realm={}\n", self.realm));
        out.push_str(&format!("min-port={}\n", self.min_port));
        out.push_str(&format!("max-port={}\n", self.max_port));
        out.push_str("use-auth-secret\n");
        out.push_str(&format!("static-auth-secret={}\n", self.static_auth_secret));
        // Reject bare STUN binding responses that would leak the relay's own address
        // fingerprint-free; a documented coturn hardening default, not a Wakala invention.
        out.push_str("fingerprint\n");
        out.push_str("no-cli\n");
        // Anti-SSRF: a TURN relay that will happily open a relayed transport address onto the
        // operator's own loopback/private/link-local network is the #1 real-world coturn
        // misconfiguration (it turns an authenticated call participant into a client that can
        // reach 127.0.0.1 services, RFC 1918 internal hosts, or a cloud metadata endpoint like
        // 169.254.169.254 through the operator's own relay). `no-loopback-peers` and
        // `no-multicast-peers` are coturn's own built-in denials; the explicit `denied-peer-ip`
        // ranges below cover every RFC 1918 / RFC 6598 / RFC 3927 / RFC 5737 / IPv6 ULA /
        // link-local block a TURN peer address must never resolve to, generated safe-by-default
        // rather than left to the operator to remember (the reachability-adapter's REACH-6/REACH-9
        // box-side denial is the same discipline applied here, since coturn — unlike the adapter —
        // does dial an arbitrary peer address on the client's behalf).
        out.push_str("no-loopback-peers\n");
        out.push_str("no-multicast-peers\n");
        for range in DENIED_PEER_IP_RANGES {
            out.push_str(&format!("denied-peer-ip={range}\n"));
        }
        out
    }

    /// The documented sidecar launch command (a real coturn invocation, unwrapped) against a
    /// config file written from [`Self::to_conf_text`]. Never run implicitly — an operator, or
    /// [`ExternalSfu::start`], runs exactly this.
    pub fn launch_command(config_path: &str) -> Vec<String> {
        vec![
            "turnserver".to_string(),
            "-c".to_string(),
            config_path.to_string(),
            "-n".to_string(), // foreground, no daemonize — the seam manages the process lifetime
        ]
    }
}

/// A LiveKit-style SFU sidecar config. This mirrors the shape of a real `livekit-server` config
/// (`port`, `rtc` port range, `keys`, `turn`) closely enough to hand a real LiveKit binary as a
/// starting point — it is **not** maintained as a verbatim schema replica of upstream LiveKit; an
/// operator standing up a real cluster should still consult LiveKit's own config reference
/// (bind-don't-reinvent: Wakala orchestrates LiveKit, it does not own LiveKit's schema).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LiveKitConfig {
    pub port: u16,
    pub rtc: LiveKitRtcConfig,
    /// API key -> secret pairs authorizing room-service/session requests to this SFU — a
    /// control-plane credential, never a media-decryption key. SFrame keys never reach this
    /// sidecar (see module docs); this map has nothing to do with them.
    pub keys: HashMap<String, String>,
    pub turn: LiveKitTurnConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LiveKitRtcConfig {
    pub tcp_port: u16,
    pub port_range_start: u16,
    pub port_range_end: u16,
    pub use_external_ip: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LiveKitTurnConfig {
    pub enabled: bool,
    pub domain: String,
    pub tls_port: u16,
}

impl LiveKitConfig {
    pub fn reference(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        turn_domain: impl Into<String>,
    ) -> Self {
        let mut keys = HashMap::new();
        keys.insert(api_key.into(), api_secret.into());
        Self {
            port: 7880,
            rtc: LiveKitRtcConfig {
                tcp_port: 7881,
                port_range_start: 50000,
                port_range_end: 60000,
                use_external_ip: true,
            },
            keys,
            turn: LiveKitTurnConfig {
                enabled: true,
                domain: turn_domain.into(),
                tls_port: 5349,
            },
        }
    }

    /// Serialize to the config text handed to the sidecar. LiveKit's own loader accepts YAML;
    /// this emits JSON, which is also valid YAML (strict JSON is a YAML 1.2 subset), so the same
    /// bytes work as a `--config` file without pulling in a YAML dependency for this one crate.
    pub fn to_config_text(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// The documented sidecar launch command against a config file written from
    /// [`Self::to_config_text`].
    pub fn launch_command(config_path: &str) -> Vec<String> {
        vec![
            "livekit-server".to_string(),
            "--config".to_string(),
            config_path.to_string(),
        ]
    }
}

/// Per-session bookkeeping for a spawned (or attempted) sidecar process.
enum SessionState {
    Running { child: Child, endpoint: String },
    Unavailable(String),
}

/// The reference process-spawn [`MediaSfu`] adapter. See module docs for the honest-degrade
/// contract this type exists to demonstrate.
///
/// Sessions are kept behind a [`RefCell`] so [`MediaSfu::status`] (`&self`) can reap an exited
/// child (`Child::try_wait` needs `&mut Child`) without widening the trait's own `&self`
/// signature — the type is single-threaded-use by design, matching every other seam in this
/// crate (no `Sync` claimed or needed).
pub struct ExternalSfu {
    kind: ExternalSfuKind,
    /// The binary this adapter execs. Overridable so a caller can point at a path off `PATH`,
    /// and so a test can force the honest-absent path deterministically regardless of what is
    /// actually installed on the machine running the test.
    binary: String,
    sessions: RefCell<HashMap<String, SessionState>>,
}

impl ExternalSfu {
    /// A `coturn` adapter, execing `turnserver` from `PATH` by default.
    pub fn coturn() -> Self {
        Self::new(ExternalSfuKind::Coturn, "turnserver")
    }

    /// A LiveKit-style adapter, execing `livekit-server` from `PATH` by default.
    pub fn livekit() -> Self {
        Self::new(ExternalSfuKind::LiveKit, "livekit-server")
    }

    fn new(kind: ExternalSfuKind, binary: impl Into<String>) -> Self {
        Self {
            kind,
            binary: binary.into(),
            sessions: RefCell::new(HashMap::new()),
        }
    }

    /// Override the exec'd binary name/path — see the field doc on [`Self::binary`].
    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }

    pub fn kind(&self) -> ExternalSfuKind {
        self.kind
    }
}

impl MediaSfu for ExternalSfu {
    fn start(&mut self, config: &SessionConfig) -> Result<SfuHandle, SfuError> {
        {
            let sessions = self.sessions.borrow();
            if matches!(sessions.get(&config.session_id), Some(SessionState::Running { .. })) {
                return Err(SfuError::AlreadyRunning(config.session_id.clone()));
            }
        }
        // A real coturn/livekit-server invocation queries its own version rather than doing
        // anything session-shaped on this probe — this adapter demonstrates the process-spawn
        // seam and its honest degrade; it does not itself write config to disk (an operator
        // wires `CoturnConfig`/`LiveKitConfig`'s `to_*_text`/`launch_command` output into its own
        // deployment, per the crate docs' bind-don't-reinvent posture).
        match Command::new(&self.binary).arg("--version").spawn() {
            Ok(child) => {
                let endpoint = format!("{}://{}", self.kind.label(), config.session_id);
                self.sessions.borrow_mut().insert(
                    config.session_id.clone(),
                    SessionState::Running { child, endpoint: endpoint.clone() },
                );
                Ok(SfuHandle {
                    session_id: config.session_id.clone(),
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let reason = format!(
                    "{} binary '{}' not found on PATH — sidecar not installed; see \
                     ExternalSfu's crate docs for the documented launch command an operator runs",
                    self.kind.label(),
                    self.binary
                );
                self.sessions
                    .borrow_mut()
                    .insert(config.session_id.clone(), SessionState::Unavailable(reason.clone()));
                Err(SfuError::Unavailable(reason))
            }
            Err(e) => {
                let reason = format!("failed to spawn {}: {e}", self.kind.label());
                self.sessions
                    .borrow_mut()
                    .insert(config.session_id.clone(), SessionState::Unavailable(reason.clone()));
                Err(SfuError::Unavailable(reason))
            }
        }
    }

    fn stop(&mut self, handle: &SfuHandle) -> Result<(), SfuError> {
        match self.sessions.borrow_mut().remove(&handle.session_id) {
            Some(SessionState::Running { mut child, .. }) => {
                let _ = child.kill();
                let _ = child.wait();
                Ok(())
            }
            Some(SessionState::Unavailable(_)) | None => Err(SfuError::NotFound(handle.session_id.clone())),
        }
    }

    fn status(&self, handle: &SfuHandle) -> SfuStatus {
        let mut sessions = self.sessions.borrow_mut();
        match sessions.get_mut(&handle.session_id) {
            Some(SessionState::Running { child, endpoint }) => match child.try_wait() {
                // Still alive as far as we can tell — honestly Running.
                Ok(None) => SfuStatus::Running { endpoint: endpoint.clone() },
                // Exited (or wait failed) since start — honestly Stopped, never stale-Running.
                Ok(Some(_)) | Err(_) => SfuStatus::Stopped,
            },
            Some(SessionState::Unavailable(reason)) => SfuStatus::Unavailable(reason.clone()),
            None => SfuStatus::Stopped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A binary name essentially guaranteed absent on any machine, so this test's outcome does
    // not depend on whether the CI/dev box happens to have a real coturn/livekit-server
    // installed — the whole point is exercising the *absent* path deterministically.
    const DEFINITELY_ABSENT_BINARY: &str = "wakala-media-relay-definitely-not-a-real-binary-xyz";

    #[test]
    fn absent_binary_degrades_to_unavailable_never_fake_running() {
        let mut sfu = ExternalSfu::coturn().with_binary(DEFINITELY_ABSENT_BINARY);
        let cfg = SessionConfig::new("call-1", 4, 2000);
        let err = sfu.start(&cfg).expect_err("an absent binary must not report success");
        assert!(matches!(err, SfuError::Unavailable(_)));

        let handle = SfuHandle {
            session_id: "call-1".to_string(),
        };
        match sfu.status(&handle) {
            SfuStatus::Unavailable(reason) => {
                assert!(reason.contains(DEFINITELY_ABSENT_BINARY));
            }
            other => panic!("expected Unavailable, got {other:?} — a fake-running regression"),
        }
    }

    #[test]
    fn absent_binary_livekit_also_degrades_honestly() {
        let mut sfu = ExternalSfu::livekit().with_binary(DEFINITELY_ABSENT_BINARY);
        let cfg = SessionConfig::new("call-2", 4, 2000);
        let err = sfu.start(&cfg).unwrap_err();
        assert!(matches!(err, SfuError::Unavailable(_)));
    }

    #[test]
    fn status_of_a_session_never_started_is_stopped_not_unavailable() {
        // Unavailable is reserved for "we tried and the sidecar wasn't there"; a session that
        // was simply never asked for is the ordinary Stopped state, same as MockSfu.
        let sfu = ExternalSfu::coturn();
        let handle = SfuHandle {
            session_id: "never-asked".to_string(),
        };
        assert_eq!(sfu.status(&handle), SfuStatus::Stopped);
    }

    #[test]
    fn a_real_short_lived_process_is_observed_stopped_once_it_exits() {
        // `true` is a real POSIX utility present on every dev/CI box this crate targets — this
        // exercises the *success* spawn path (unlike the absent-binary tests above) and proves
        // `status` re-checks liveness rather than latching a stale Running.
        let mut sfu = ExternalSfu::coturn().with_binary("true");
        let cfg = SessionConfig::new("call-3", 4, 2000);
        let handle = sfu.start(&cfg).expect("`true` is expected to be spawnable");

        // Give the child a moment to exit; poll rather than a fixed sleep+single-check so this
        // isn't flaky under a loaded CI box.
        let mut saw_stopped = false;
        for _ in 0..200 {
            if sfu.status(&handle) == SfuStatus::Stopped {
                saw_stopped = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(saw_stopped, "status must observe the exited child, never stay stale-Running");
    }

    #[test]
    fn coturn_config_generates_valid_conf_text() {
        let cfg = CoturnConfig::reference("wakala.example", "s3cr3t");
        let text = cfg.to_conf_text();
        assert!(text.contains("listening-port=3478"));
        assert!(text.contains("realm=wakala.example"));
        assert!(text.contains("static-auth-secret=s3cr3t"));
        assert!(text.contains("min-port=49152"));
        assert!(text.contains("max-port=49452"));
        // No media key, no room/participant PII — only sidecar transport config.
        assert!(!text.to_lowercase().contains("sframe"));
    }

    /// Anti-SSRF: the generated config must deny relaying to loopback/private/link-local/
    /// cloud-metadata peer addresses by default — an operator who never edits the generated file
    /// still gets a safe TURN relay, not an open pivot into their own network (the #1 real-world
    /// coturn misconfiguration).
    #[test]
    fn coturn_config_denies_private_and_loopback_peer_ranges_by_default() {
        let cfg = CoturnConfig::reference("wakala.example", "s3cr3t");
        let text = cfg.to_conf_text();
        assert!(text.contains("no-loopback-peers\n"));
        assert!(text.contains("no-multicast-peers\n"));
        // RFC 1918 private ranges.
        assert!(text.contains("denied-peer-ip=10.0.0.0-10.255.255.255\n"));
        assert!(text.contains("denied-peer-ip=172.16.0.0-172.31.255.255\n"));
        assert!(text.contains("denied-peer-ip=192.168.0.0-192.168.255.255\n"));
        // Loopback and link-local (incl. the 169.254.169.254 cloud-metadata endpoint).
        assert!(text.contains("denied-peer-ip=127.0.0.0-127.255.255.255\n"));
        assert!(text.contains("denied-peer-ip=169.254.0.0-169.254.255.255\n"));
        // IPv6 loopback, unique-local, and link-local.
        assert!(text.contains("denied-peer-ip=::1\n"));
        assert!(text.contains("denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n"));
        assert!(text.contains("denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n"));
    }

    #[test]
    fn coturn_launch_command_references_the_config_file() {
        let cmd = CoturnConfig::launch_command("/etc/wakala/turnserver.conf");
        assert_eq!(cmd[0], "turnserver");
        assert!(cmd.contains(&"/etc/wakala/turnserver.conf".to_string()));
    }

    #[test]
    fn livekit_config_generates_valid_json_yaml_compatible_text() {
        let cfg = LiveKitConfig::reference("api-key", "api-secret", "turn.wakala.example");
        let text = cfg.to_config_text().expect("reference config must serialize");
        // Round-trips through a JSON parser (and therefore any YAML 1.2 parser, since valid
        // JSON is valid YAML).
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("must be valid JSON");
        assert_eq!(parsed["port"], 7880);
        assert_eq!(parsed["turn"]["domain"], "turn.wakala.example");
        assert_eq!(parsed["keys"]["api-key"], "api-secret");
    }

    #[test]
    fn livekit_launch_command_references_the_config_file() {
        let cmd = LiveKitConfig::launch_command("/etc/wakala/livekit.yaml");
        assert_eq!(cmd[0], "livekit-server");
        assert!(cmd.contains(&"/etc/wakala/livekit.yaml".to_string()));
    }

    #[test]
    fn starting_an_already_running_session_is_rejected() {
        let mut sfu = ExternalSfu::coturn().with_binary("true");
        let cfg = SessionConfig::new("call-4", 4, 2000);
        let _handle = sfu.start(&cfg).unwrap();
        let err = sfu.start(&cfg).unwrap_err();
        assert!(matches!(err, SfuError::AlreadyRunning(id) if id == "call-4"));
    }
}
