//! Recovery signals for Phase 3.2 deterministic resynchronization.
//!
//! This module determines when a session must emit a forced recovery keyframe
//! and exposes explicit `RecoveryStarted`/`RecoveryComplete` events. Recovery is
//! triggered only by sustained loss ratios or large burst gaps and never rewinds
//! the timeline.
use crate::stream::network::NetworkConditions;

const SUSTAINED_LOSS_THRESHOLD: f64 = 0.25;
const RECOVERY_CLEAR_LOSS_THRESHOLD: f64 = 0.05;
const BURST_LOSS_THRESHOLD: u64 = 3;
const RECOVERY_CLEAR_BURST_THRESHOLD: u64 = 1;

/// Represents why recovery was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    /// Sustained loss ratio across many frames.
    SustainedLoss,
    /// Burst loss gap (skipped sequences) exceeded the safe window.
    BurstLoss,
}

impl RecoveryReason {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            RecoveryReason::SustainedLoss => "sustained_loss",
            RecoveryReason::BurstLoss => "burst_loss",
        }
    }
}

/// Events emitted while evaluation recovery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEvent {
    /// Recovery just started for the given reason.
    RecoveryStarted(RecoveryReason),
    /// Recovery completed once metrics returned to safe bounds.
    RecoveryComplete(RecoveryReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryState {
    Idle,
    Recovering(RecoveryReason),
}

/// Monitor that enforces deterministic recovery transitions.
#[derive(Debug)]
pub struct RecoveryMonitor {
    state: RecoveryState,
}

impl RecoveryMonitor {
    /// Creates a fresh monitor in the idle state.
    pub fn new() -> Self {
        Self {
            state: RecoveryState::Idle,
        }
    }

    /// Feeds fresh metrics and returns a matching recovery event, if any.
    pub fn feed(&mut self, conditions: &NetworkConditions) -> Option<RecoveryEvent> {
        let metrics = conditions.metrics();
        let gap = conditions.max_loss_gap();
        match self.state {
            RecoveryState::Idle => {
                if gap >= BURST_LOSS_THRESHOLD {
                    self.state = RecoveryState::Recovering(RecoveryReason::BurstLoss);
                    return Some(RecoveryEvent::RecoveryStarted(RecoveryReason::BurstLoss));
                }
                if metrics.loss_ratio >= SUSTAINED_LOSS_THRESHOLD {
                    self.state = RecoveryState::Recovering(RecoveryReason::SustainedLoss);
                    return Some(RecoveryEvent::RecoveryStarted(
                        RecoveryReason::SustainedLoss,
                    ));
                }
            }
            RecoveryState::Recovering(reason) => {
                if metrics.loss_ratio <= RECOVERY_CLEAR_LOSS_THRESHOLD
                    && gap <= RECOVERY_CLEAR_BURST_THRESHOLD
                {
                    self.state = RecoveryState::Idle;
                    return Some(RecoveryEvent::RecoveryComplete(reason));
                }
            }
        }
        None
    }

    /// Returns `true` while recovery is active so callers can force keyframes.
    pub fn is_recovering(&self) -> bool {
        matches!(self.state, RecoveryState::Recovering(_))
    }

    /// Returns the active recovery reason, if present.
    pub fn active_reason(&self) -> Option<RecoveryReason> {
        match self.state {
            RecoveryState::Recovering(reason) => Some(reason),
            RecoveryState::Idle => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::network::NetworkConditions;

    fn low_loss_conditions() -> NetworkConditions {
        let mut cond = NetworkConditions::new();
        cond.record_frame(10, 0, 1_000);
        cond.record_frame(11, 1_000, 2_000);
        cond.record_frame(12, 2_000, 3_000);
        cond
    }

    #[test]
    fn starts_and_completes_on_loss_ratio() {
        let mut monitor = RecoveryMonitor::new();
        let mut cond = NetworkConditions::new();
        cond.record_frame(1, 0, 0);
        cond.record_frame(2, 1_000, 0);
        cond.record_frame(4, 2_000, 0);
        let event = monitor.feed(&cond);
        assert_eq!(
            event,
            Some(RecoveryEvent::RecoveryStarted(
                RecoveryReason::SustainedLoss
            ))
        );
        let complete = monitor.feed(&low_loss_conditions());
        assert_eq!(
            complete,
            Some(RecoveryEvent::RecoveryComplete(
                RecoveryReason::SustainedLoss
            ))
        );
    }

    #[test]
    fn burst_gap_triggers_recovery() {
        let mut monitor = RecoveryMonitor::new();
        let mut cond = NetworkConditions::new();
        cond.record_frame(1, 0, 0);
        cond.record_frame(5, 1_000, 0);
        let event = monitor.feed(&cond);
        assert_eq!(
            event,
            Some(RecoveryEvent::RecoveryStarted(RecoveryReason::BurstLoss))
        );
        let complete = monitor.feed(&low_loss_conditions());
        assert_eq!(
            complete,
            Some(RecoveryEvent::RecoveryComplete(RecoveryReason::BurstLoss))
        );
    }

    #[test]
    fn recovery_idempotent_until_cleared() {
        let mut monitor = RecoveryMonitor::new();
        let mut cond = NetworkConditions::new();
        cond.record_frame(1, 0, 0);
        cond.record_frame(4, 1_000, 0);
        assert!(matches!(
            monitor.feed(&cond),
            Some(RecoveryEvent::RecoveryStarted(_))
        ));
        assert_eq!(monitor.feed(&cond), None);
    }
}
