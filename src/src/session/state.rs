use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Init,
    Handshake,
    Authenticated { since: Instant },
    Ready { since: Instant },
    Streaming { since: Instant },
    Failed(String),
    Closed,
}

impl SessionState {
    pub fn can_transition(&self, next: &SessionState) -> bool {
        use SessionState::*;
        match (self, next) {
            (Init, Handshake) => true,
            (Handshake, Authenticated { .. }) => true,
            (Authenticated { .. }, Ready { .. }) => true,
            (Ready { .. }, Streaming { .. }) => true,
            // terminal moves
            (_, Failed(_)) => true,
            (_, Closed) => true,
            _ => false,
        }
    }

    pub fn transition(self, next: SessionState) -> Result<SessionState, SessionStateError> {
        if self.can_transition(&next) {
            Ok(next)
        } else {
            Err(SessionStateError::InvalidTransition(format!(
                "cannot transition from {:?} to {:?}",
                self, next
            )))
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, SessionState::Failed(_))
    }

    pub fn is_closed(&self) -> bool {
        matches!(self, SessionState::Closed)
    }

    pub fn check_timeout(&self, timeout: Duration, now: Instant) -> bool {
        match self {
            SessionState::Authenticated { since }
            | SessionState::Ready { since }
            | SessionState::Streaming { since } => now.duration_since(*since) > timeout,
            _ => false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionStateError {
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),
}
