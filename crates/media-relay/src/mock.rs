//! [`MockSfu`] — an in-process, no-sidecar [`MediaSfu`] for tests and local development that
//! need a `MediaSfu` implementation without a real `coturn`/`livekit-server` installed. It
//! forwards nothing — there is no media plane here at all, only the same start/stop/status
//! bookkeeping shape a real adapter presents, so code written against [`MediaSfu`] can be
//! exercised without process-spawn or network dependencies.

use std::collections::HashMap;

use crate::sfu::{MediaSfu, SessionConfig, SfuError, SfuHandle, SfuStatus};

/// In-memory lifecycle state for [`MockSfu`]'s sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Running,
    Stopped,
}

/// The reference in-process fake [`MediaSfu`]. See module docs.
#[derive(Default)]
pub struct MockSfu {
    sessions: HashMap<String, State>,
}

impl MockSfu {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MediaSfu for MockSfu {
    fn start(&mut self, config: &SessionConfig) -> Result<SfuHandle, SfuError> {
        if self.sessions.get(&config.session_id) == Some(&State::Running) {
            return Err(SfuError::AlreadyRunning(config.session_id.clone()));
        }
        self.sessions.insert(config.session_id.clone(), State::Running);
        Ok(SfuHandle {
            session_id: config.session_id.clone(),
        })
    }

    fn stop(&mut self, handle: &SfuHandle) -> Result<(), SfuError> {
        match self.sessions.get(&handle.session_id) {
            Some(State::Running) => {
                self.sessions.insert(handle.session_id.clone(), State::Stopped);
                Ok(())
            }
            Some(State::Stopped) | None => Err(SfuError::NotFound(handle.session_id.clone())),
        }
    }

    fn status(&self, handle: &SfuHandle) -> SfuStatus {
        match self.sessions.get(&handle.session_id) {
            Some(State::Running) => SfuStatus::Running {
                endpoint: format!("mock://{}", handle.session_id),
            },
            Some(State::Stopped) | None => SfuStatus::Stopped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_then_status_reports_running() {
        let mut sfu = MockSfu::new();
        let cfg = SessionConfig::new("call-1", 4, 2000);
        let handle = sfu.start(&cfg).expect("mock start never fails for a fresh session");
        assert_eq!(
            sfu.status(&handle),
            SfuStatus::Running {
                endpoint: "mock://call-1".to_string()
            }
        );
    }

    #[test]
    fn stop_then_status_reports_stopped() {
        let mut sfu = MockSfu::new();
        let cfg = SessionConfig::new("call-2", 4, 2000);
        let handle = sfu.start(&cfg).unwrap();
        sfu.stop(&handle).expect("a running session stops cleanly");
        assert_eq!(sfu.status(&handle), SfuStatus::Stopped);
    }

    #[test]
    fn status_of_an_unknown_session_is_stopped_not_an_error() {
        let sfu = MockSfu::new();
        let handle = SfuHandle {
            session_id: "never-started".to_string(),
        };
        assert_eq!(sfu.status(&handle), SfuStatus::Stopped);
    }

    #[test]
    fn starting_an_already_running_session_is_rejected() {
        let mut sfu = MockSfu::new();
        let cfg = SessionConfig::new("call-3", 4, 2000);
        sfu.start(&cfg).unwrap();
        let err = sfu.start(&cfg).unwrap_err();
        assert!(matches!(err, SfuError::AlreadyRunning(id) if id == "call-3"));
    }

    #[test]
    fn stopping_a_session_that_was_never_started_is_not_found() {
        let mut sfu = MockSfu::new();
        let handle = SfuHandle {
            session_id: "ghost".to_string(),
        };
        let err = sfu.stop(&handle).unwrap_err();
        assert!(matches!(err, SfuError::NotFound(id) if id == "ghost"));
    }

    #[test]
    fn full_start_stop_start_lifecycle() {
        let mut sfu = MockSfu::new();
        let cfg = SessionConfig::new("call-4", 8, 4000);
        let h1 = sfu.start(&cfg).unwrap();
        sfu.stop(&h1).unwrap();
        // Restarting the same session id after a clean stop is allowed.
        let h2 = sfu.start(&cfg).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(
            sfu.status(&h2),
            SfuStatus::Running {
                endpoint: "mock://call-4".to_string()
            }
        );
    }
}
