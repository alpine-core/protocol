//! Core adaptation state machine for Phase 3.3.
//!
//! This module defines the pure decision logic that takes deterministic network
//! metrics plus recovery signals and produces the next conservative adaptation
//! state. There are no side effects, no logging, and no streaming plumbing here.
use crate::profile::StreamIntent;
use crate::stream::network::NetworkConditions;
use crate::stream::recovery::RecoveryReason;

const DWELL_FRAMES: u32 = 8;

const LOSS_THRESHOLD_KEYFRAME: f64 = 0.30;
const LOSS_THRESHOLD_DISABLE: f64 = 0.50;
const LATE_THRESHOLD_DELTA: f64 = 0.20;
const JITTER_THRESHOLD_DELTA: f64 = 5.0;
const JITTER_TIGHTEN: f64 = 8.0;
const JITTER_RELAX: f64 = 3.0;
const BURST_THRESHOLD_KEYFRAME: u64 = 5;
const BURST_THRESHOLD_DISABLE: u64 = 8;
const BURST_THRESHOLD_DEGRADE: u64 = 10;
const LOSS_THRESHOLD_DEGRADE: f64 = 0.60;
const DEADLINE_STEP_MS: i16 = 10;

#[derive(Debug, Clone)]
pub struct AdaptationSnapshot {
    keyframe_interval: u8,
    delta_depth: u8,
    deadline_offset_ms: i16,
    frames_since_keyframe: u8,
}

impl AdaptationSnapshot {
    fn from_state(state: &AdaptationState) -> Self {
        Self {
            keyframe_interval: state.keyframe_interval,
            delta_depth: state.delta_depth,
            deadline_offset_ms: state.deadline_offset_ms,
            frames_since_keyframe: state.frames_since_keyframe,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProfileBounds {
    pub min_keyframe_interval: u8,
    pub base_keyframe_interval: u8,
    pub min_delta_depth: u8,
    pub base_delta_depth: u8,
    pub max_deadline_offset: i16,
    pub min_deadline_offset: i16,
}

impl ProfileBounds {
    fn for_intent(intent: StreamIntent) -> Self {
        match intent {
            StreamIntent::Auto => Self {
                min_keyframe_interval: 6,
                base_keyframe_interval: 10,
                min_delta_depth: 1,
                base_delta_depth: 3,
                max_deadline_offset: 15,
                min_deadline_offset: -15,
            },
            StreamIntent::Realtime => Self {
                min_keyframe_interval: 8,
                base_keyframe_interval: 12,
                min_delta_depth: 1,
                base_delta_depth: 2,
                max_deadline_offset: 0,
                min_deadline_offset: -20,
            },
            StreamIntent::Install => Self {
                min_keyframe_interval: 4,
                base_keyframe_interval: 8,
                min_delta_depth: 0,
                base_delta_depth: 3,
                max_deadline_offset: 25,
                min_deadline_offset: -10,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdaptationState {
    pub profile_intent: StreamIntent,
    pub keyframe_interval: u8,
    pub delta_depth: u8,
    pub deadline_offset_ms: i16,
    pub frames_in_state: u32,
    pub frames_since_keyframe: u8,
    pub degraded_safe: bool,
    pub last_safe_snapshot: Option<AdaptationSnapshot>,
    pub last_event: Option<AdaptationEvent>,
}

impl AdaptationState {
    pub fn baseline(intent: StreamIntent) -> Self {
        let bounds = ProfileBounds::for_intent(intent);
        Self {
            profile_intent: intent,
            keyframe_interval: bounds.base_keyframe_interval,
            delta_depth: bounds.base_delta_depth,
            deadline_offset_ms: 0,
            frames_in_state: DWELL_FRAMES,
            frames_since_keyframe: 0,
            degraded_safe: false,
            last_safe_snapshot: None,
            last_event: None,
        }
    }

    fn record_frame(&mut self) {
        self.frames_in_state = self.frames_in_state.saturating_add(1);
    }

    fn reset_frames(&mut self) {
        self.frames_in_state = 0;
    }

    fn reset_keyframe_counter(&mut self) {
        self.frames_since_keyframe = 0;
    }

    pub(crate) fn should_emit_keyframe(&mut self) -> bool {
        self.frames_since_keyframe = self.frames_since_keyframe.saturating_add(1);
        if self.frames_since_keyframe >= self.keyframe_interval {
            self.frames_since_keyframe = 0;
            true
        } else {
            false
        }
    }

    fn would_violate_bounds(
        &self,
        bounds: &ProfileBounds,
        next_interval: u8,
        next_delta: u8,
        next_deadline: i16,
    ) -> bool {
        next_interval < bounds.min_keyframe_interval
            || next_delta < bounds.min_delta_depth
            || next_deadline < bounds.min_deadline_offset
            || next_deadline > bounds.max_deadline_offset
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedReason {
    ExceededProfileBounds,
    UnrecoverableBurst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptationEvent {
    KeyframeCadenceIncreased,
    DeltaDepthReduced,
    DeltaDisabled,
    DeadlineAdjusted,
    EnteredDegradedSafe(DegradedReason),
    ExitedDegradedSafe,
}

impl AdaptationEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            AdaptationEvent::KeyframeCadenceIncreased => "keyframe_cadence_increased",
            AdaptationEvent::DeltaDepthReduced => "delta_depth_reduced",
            AdaptationEvent::DeltaDisabled => "delta_disabled",
            AdaptationEvent::DeadlineAdjusted => "deadline_adjusted",
            AdaptationEvent::EnteredDegradedSafe(_) => "entered_degraded_safe",
            AdaptationEvent::ExitedDegradedSafe => "exited_degraded_safe",
        }
    }
}

#[derive(Debug)]
pub struct AdaptationDecision {
    pub state: AdaptationState,
    pub event: Option<AdaptationEvent>,
}

impl AdaptationDecision {
    fn with_event(mut state: AdaptationState, event: Option<AdaptationEvent>) -> Self {
        state.last_event = event;
        Self { state, event }
    }
}

pub fn decide_next_state(
    current: &AdaptationState,
    network: &NetworkConditions,
    recovery: Option<RecoveryReason>,
    intent: StreamIntent,
) -> AdaptationDecision {
    let mut next = current.clone();
    next.record_frame();
    let bounds = ProfileBounds::for_intent(intent);
    let metrics = network.metrics();
    let gap = network.max_loss_gap();

    if current.degraded_safe {
        if metrics.loss_ratio <= LOSS_THRESHOLD_DISABLE
            && gap <= BURST_THRESHOLD_DISABLE
            && recovery.is_none()
        {
            if let Some(snapshot) = current.last_safe_snapshot.clone() {
                next.keyframe_interval = snapshot.keyframe_interval;
                next.delta_depth = snapshot.delta_depth;
                next.deadline_offset_ms = snapshot.deadline_offset_ms;
                next.frames_since_keyframe = snapshot.frames_since_keyframe;
            }
            next.degraded_safe = false;
            next.reset_frames();
            return AdaptationDecision::with_event(next, Some(AdaptationEvent::ExitedDegradedSafe));
        }
        return AdaptationDecision::with_event(next, None);
    }

    if metrics.loss_ratio >= LOSS_THRESHOLD_DEGRADE && gap >= BURST_THRESHOLD_DEGRADE {
        next.degraded_safe = true;
        next.last_safe_snapshot = Some(AdaptationSnapshot::from_state(current));
        next.reset_frames();
        next.reset_keyframe_counter();
        return AdaptationDecision::with_event(
            next,
            Some(AdaptationEvent::EnteredDegradedSafe(
                DegradedReason::UnrecoverableBurst,
            )),
        );
    }

    if next.frames_in_state < DWELL_FRAMES {
        return AdaptationDecision::with_event(next, None);
    }

    let jitter_ms = metrics.jitter_ms.unwrap_or(0.0);

    if gap >= BURST_THRESHOLD_DISABLE && recovery == Some(RecoveryReason::BurstLoss) {
        let next_delta = 0;
        if current.delta_depth != next_delta {
            next.delta_depth = next_delta;
            next.reset_frames();
            next.reset_keyframe_counter();
            return AdaptationDecision::with_event(next, Some(AdaptationEvent::DeltaDisabled));
        }
    }

    if metrics.loss_ratio >= LOSS_THRESHOLD_KEYFRAME || gap >= BURST_THRESHOLD_KEYFRAME {
        let next_interval = current.keyframe_interval.saturating_sub(1);
        if next_interval < bounds.min_keyframe_interval {
            next.degraded_safe = true;
            next.last_safe_snapshot = Some(AdaptationSnapshot::from_state(current));
            next.reset_frames();
            next.reset_keyframe_counter();
            return AdaptationDecision::with_event(
                next,
                Some(AdaptationEvent::EnteredDegradedSafe(
                    DegradedReason::ExceededProfileBounds,
                )),
            );
        }
        next.keyframe_interval = next_interval;
        next.reset_frames();
        next.reset_keyframe_counter();
        return AdaptationDecision::with_event(
            next,
            Some(AdaptationEvent::KeyframeCadenceIncreased),
        );
    }

    if metrics.late_frame_rate >= LATE_THRESHOLD_DELTA
        && jitter_ms > JITTER_THRESHOLD_DELTA
        && current.delta_depth > bounds.min_delta_depth
    {
        let next_delta = current.delta_depth.saturating_sub(1);
        if next_delta < bounds.min_delta_depth {
            next.degraded_safe = true;
            next.last_safe_snapshot = Some(AdaptationSnapshot::from_state(current));
            next.reset_frames();
            next.reset_keyframe_counter();
            return AdaptationDecision::with_event(
                next,
                Some(AdaptationEvent::EnteredDegradedSafe(
                    DegradedReason::ExceededProfileBounds,
                )),
            );
        }
        next.delta_depth = next_delta;
        next.reset_frames();
        next.reset_keyframe_counter();
        return AdaptationDecision::with_event(next, Some(AdaptationEvent::DeltaDepthReduced));
    }

    if jitter_ms > JITTER_TIGHTEN {
        let next_deadline = current.deadline_offset_ms - DEADLINE_STEP_MS;
        if next_deadline < bounds.min_deadline_offset {
            next.degraded_safe = true;
            next.last_safe_snapshot = Some(AdaptationSnapshot::from_state(current));
            next.reset_frames();
            next.reset_keyframe_counter();
            return AdaptationDecision::with_event(
                next,
                Some(AdaptationEvent::EnteredDegradedSafe(
                    DegradedReason::ExceededProfileBounds,
                )),
            );
        }
        next.deadline_offset_ms = next_deadline;
        next.reset_frames();
        return AdaptationDecision::with_event(next, Some(AdaptationEvent::DeadlineAdjusted));
    }

    if jitter_ms < JITTER_RELAX {
        let next_deadline = current.deadline_offset_ms + DEADLINE_STEP_MS;
        if next_deadline > bounds.max_deadline_offset {
            next.degraded_safe = true;
            next.last_safe_snapshot = Some(AdaptationSnapshot::from_state(current));
            next.reset_frames();
            next.reset_keyframe_counter();
            return AdaptationDecision::with_event(
                next,
                Some(AdaptationEvent::EnteredDegradedSafe(
                    DegradedReason::ExceededProfileBounds,
                )),
            );
        }
        next.deadline_offset_ms = next_deadline;
        next.reset_frames();
        return AdaptationDecision::with_event(next, Some(AdaptationEvent::DeadlineAdjusted));
    }

    AdaptationDecision::with_event(next, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::StreamProfile;
    use crate::stream::recovery::RecoveryReason;

    fn high_loss_conditions() -> NetworkConditions {
        let mut cond = NetworkConditions::new();
        cond.record_frame(1, 0, 0);
        cond.record_frame(2, 1_000, 0);
        cond.record_frame(10, 2_000, 0);
        cond
    }

    fn low_loss_conditions() -> NetworkConditions {
        let mut cond = NetworkConditions::new();
        cond.record_frame(1, 0, 0);
        cond.record_frame(2, 1_000, 0);
        cond.record_frame(3, 2_000, 0);
        cond.record_frame(4, 3_000, 0);
        cond
    }

    #[test]
    fn keyframe_cadence_increases_on_loss() {
        let profile = StreamProfile::auto();
        let state = AdaptationState::baseline(profile.intent());
        let network = high_loss_conditions();
        let decision = decide_next_state(&state, &network, None, profile.intent());
        assert_eq!(
            decision.event,
            Some(AdaptationEvent::KeyframeCadenceIncreased)
        );
        assert!(decision.state.keyframe_interval < state.keyframe_interval);
    }

    #[test]
    fn degraded_safe_when_bounds_block_keyframe() {
        let profile = StreamProfile::auto();
        let mut state = AdaptationState::baseline(profile.intent());
        state.keyframe_interval = ProfileBounds::for_intent(profile.intent()).min_keyframe_interval;
        state.frames_in_state = DWELL_FRAMES;

        let decision = decide_next_state(&state, &high_loss_conditions(), None, profile.intent());
        assert_eq!(
            decision.event,
            Some(AdaptationEvent::EnteredDegradedSafe(
                DegradedReason::ExceededProfileBounds
            ))
        );
        assert!(decision.state.degraded_safe);
    }

    #[test]
    fn degraded_safe_exits_when_metrics_clear() {
        let profile = StreamProfile::auto();
        let mut state = AdaptationState::baseline(profile.intent());
        state.degraded_safe = true;
        state.last_safe_snapshot = Some(AdaptationSnapshot::from_state(&state));
        state.frames_in_state = DWELL_FRAMES;

        let decision = decide_next_state(&state, &low_loss_conditions(), None, profile.intent());
        assert_eq!(decision.event, Some(AdaptationEvent::ExitedDegradedSafe));
        assert!(!decision.state.degraded_safe);
    }

    #[test]
    fn delta_disable_requires_burst_loss_recovery() {
        let profile = StreamProfile::auto();
        let state = AdaptationState::baseline(profile.intent());
        let network = {
            let mut cond = NetworkConditions::new();
            cond.record_frame(1, 0, 0);
            cond.record_frame(2, 1_000, 0);
            cond.record_frame(12, 2_000, 0);
            cond
        };
        let decision = decide_next_state(
            &state,
            &network,
            Some(RecoveryReason::BurstLoss),
            profile.intent(),
        );
        assert_eq!(decision.event, Some(AdaptationEvent::DeltaDisabled));
        assert_eq!(decision.state.delta_depth, 0);
    }

    #[test]
    fn no_oscillation_before_dwell() {
        let profile = StreamProfile::auto();
        let mut state = AdaptationState::baseline(profile.intent());
        state.frames_in_state = 1;
        let decision = decide_next_state(&state, &high_loss_conditions(), None, profile.intent());
        assert!(decision.event.is_none());
        assert_eq!(decision.state.frames_in_state, 2);
    }
}
