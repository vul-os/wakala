//! The orchestration seam: [`MediaSfu`] represents an **external** SFU this coordinator
//! schedules and coordinates, but never contains (DIRECTION §3, bind-don't-reinvent; DIRECTION
//! §7's "coordinated by an existing distributed SFU"). Two implementations live in this crate:
//!
//! - [`crate::external::ExternalSfu`] — the reference adapter for a real `coturn`/`livekit-server`
//!   sidecar, managed as a child process, degrading honestly when the binary is absent.
//! - [`crate::mock::MockSfu`] — an in-process fake for tests that need a `MediaSfu` without a
//!   real sidecar installed.
//!
//! Nothing in this module is media transport. `SessionConfig` carries only the orchestration
//! parameters an SFU needs to admit a session (RTC.md R-RTC-4: **tracks and bitrate, never
//! headcount**) — never a codec parameter, a media key, or a frame. The relay never holds a
//! media key: SFrame keying rides MLS → SFrame end-to-end between the call's own participants
//! (DIRECTION §7), so there is structurally nothing key-shaped for this seam to carry.

use std::error::Error;
use std::fmt;

/// Orchestration parameters for one session (a call/stream) the media-relay is asked to scale.
/// This is the **admission-control** request an SFU needs before it forwards a byte — never a
/// media parameter. Per RTC.md R-RTC-4, a conformant SFU publishes and re-checks its ceiling in
/// **tracks and bitrate**, not headcount, so those are exactly the two fields this type carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    /// A stable session/room identifier (e.g. the MLS group id the call is scoped to, RTC.md
    /// §2.1 — this crate never sees the group's key material, only its opaque id as a routing
    /// label).
    pub session_id: String,
    /// Track ceiling to admit for this session (RTC.md R-RTC-4).
    pub max_tracks: u32,
    /// Bitrate ceiling in kbps to admit for this session (RTC.md R-RTC-4).
    pub max_bitrate_kbps: u32,
}

impl SessionConfig {
    pub fn new(session_id: impl Into<String>, max_tracks: u32, max_bitrate_kbps: u32) -> Self {
        Self {
            session_id: session_id.into(),
            max_tracks,
            max_bitrate_kbps,
        }
    }
}

/// An opaque reference to a session started on an SFU — carries no media key and no participant
/// content, purely a handle for later `stop`/`status` calls (see module docs).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SfuHandle {
    pub session_id: String,
}

/// The SFU's reported state for a session. [`SfuStatus::Unavailable`] is a **first-class,
/// honestly-reported** state, not an error swallowed into a fake success — this is the whole
/// point of the honest-degrade contract every [`MediaSfu`] implementation MUST uphold: a caller
/// MUST NEVER see `Running` unless the adapter genuinely believes the sidecar is up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SfuStatus {
    /// The SFU process/service is up and (as far as this adapter can tell) forwarding for this
    /// session. `endpoint` is an adapter-defined descriptive label, not a media address a caller
    /// should parse.
    Running { endpoint: String },
    /// Not currently running for this session — never started, or cleanly stopped, or (for a
    /// process-backed adapter) observed to have exited.
    Stopped,
    /// The SFU could not be reached or started; `String` is the disclosed reason (e.g. "binary
    /// not found"). MUST NOT be coerced into `Running` or silently dropped.
    Unavailable(String),
}

/// Errors a [`MediaSfu`] implementation returns. Every variant is a hard "did not happen" —
/// callers MUST treat any `Err` as no session started, never partially trust it.
#[derive(Debug)]
pub enum SfuError {
    /// The sidecar could not be reached or started; the `String` is the disclosed reason. This
    /// is the honest-degrade case the absent-binary constraint requires — see
    /// [`crate::external::ExternalSfu`].
    Unavailable(String),
    /// `start` was called for a `session_id` already running.
    AlreadyRunning(String),
    /// `stop`/`status` was called for a `session_id` this adapter has no record of.
    NotFound(String),
}

impl fmt::Display for SfuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SfuError::Unavailable(reason) => write!(f, "SFU unavailable: {reason}"),
            SfuError::AlreadyRunning(id) => write!(f, "session '{id}' is already running"),
            SfuError::NotFound(id) => write!(f, "no session '{id}' on this adapter"),
        }
    }
}

impl Error for SfuError {}

/// An external SFU this coordinator orchestrates, never contains. Implementations own no media
/// bytes and no media key — they start/stop/observe a **process or service** that does the
/// actual RTP forwarding (DIRECTION §3, bind-don't-reinvent).
///
/// **Honest-degrade contract (normative for this crate):** `start` MUST return
/// [`SfuStatus::Unavailable`] (via `status`, and/or `Err(SfuError::Unavailable)` from `start`
/// itself) when the underlying sidecar cannot be reached — **never** a handle that later reports
/// [`SfuStatus::Running`] for a session that isn't. A fake "running" is worse than an honest
/// error: it would let a call proceed believing media is scaling when nothing is forwarding it.
pub trait MediaSfu {
    /// Start (or admit) a session on the SFU. On success, later `stop`/`status` calls take the
    /// returned handle.
    fn start(&mut self, config: &SessionConfig) -> Result<SfuHandle, SfuError>;

    /// Stop a session previously started on this adapter.
    fn stop(&mut self, handle: &SfuHandle) -> Result<(), SfuError>;

    /// Report the current state of a session. Never guessed — see the honest-degrade contract.
    fn status(&self, handle: &SfuHandle) -> SfuStatus;
}
