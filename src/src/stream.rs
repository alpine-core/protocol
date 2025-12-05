use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{info, warn};

use crate::messages::{ChannelFormat, FrameEnvelope, MessageType};
use crate::profile::CompiledStreamProfile;
use crate::session::{AlnpSession, JitterStrategy};
use crate::stream::adaptive::{decide_next_state, AdaptationState};

/// Minimal transport for sending serialized ALPINE frames (UDP/QUIC left to the caller).
pub trait FrameTransport: Send + Sync {
    /// Sends the provided serialized frame.
    fn send_frame(&self, bytes: &[u8]) -> Result<(), String>;
}

/// Stream state machine used by higher-level clients.
#[derive(Debug)]
pub struct AlnpStream<T: FrameTransport> {
    session: AlnpSession,
    transport: T,
    last_frame: parking_lot::Mutex<Option<FrameEnvelope>>,
    profile: CompiledStreamProfile,
    recovery: parking_lot::Mutex<RecoveryMonitor>,
    recovery_reason: parking_lot::Mutex<Option<RecoveryReason>>,
    adaptation: parking_lot::Mutex<AdaptationState>,
}

/// Errors emitted from the streaming helper.
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("sender not authenticated")]
    NotAuthenticated,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("streaming disabled")]
    StreamingDisabled,
    #[error("no session available")]
    MissingSession,
}

mod network;

pub use network::{NetworkConditions, NetworkMetrics};

mod recovery;

pub use recovery::{RecoveryEvent, RecoveryMonitor, RecoveryReason};

mod adaptive;

impl<T: FrameTransport> AlnpStream<T> {
    /// Builds a new streaming helper bound to a compiled profile.
    pub fn new(session: AlnpSession, transport: T, profile: CompiledStreamProfile) -> Self {
        let intent = profile.intent();
        Self {
            session,
            transport,
            last_frame: parking_lot::Mutex::new(None),
            profile,
            recovery: parking_lot::Mutex::new(RecoveryMonitor::new()),
            recovery_reason: parking_lot::Mutex::new(None),
            adaptation: parking_lot::Mutex::new(AdaptationState::baseline(intent)),
        }
    }

    /// Sends a streaming frame built from raw channel data.
    ///
    /// # Guarantees
    /// * Only sends when the session is already authenticated and streaming-enabled.
    /// * Applies jitter strategy derived from the compiled profile; no branching on
    ///   user-facing preferences happens at this layer.
    pub fn send(
        &self,
        channel_format: ChannelFormat,
        channels: Vec<u16>,
        priority: u8,
        groups: Option<HashMap<String, Vec<u16>>>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<(), StreamError> {
        let established = self
            .session
            .ensure_streaming_ready()
            .map_err(|_| StreamError::NotAuthenticated)?;
        if !self.session.streaming_enabled() {
            return Err(StreamError::StreamingDisabled);
        }

        let adjusted_channels = self.apply_jitter(&channels);
        let mut adaptation = self.adaptation.lock();
        let should_force_keyframe = adaptation.should_emit_keyframe();
        let adaptation_snapshot = adaptation.clone();
        drop(adaptation);
        let metadata =
            self.annotate_metadata(metadata, should_force_keyframe, &adaptation_snapshot);

        let envelope = FrameEnvelope {
            message_type: MessageType::AlpineFrame,
            session_id: established.session_id,
            timestamp_us: Self::now_us(),
            priority,
            channel_format,
            channels: adjusted_channels,
            groups,
            metadata,
        };

        let bytes = serde_cbor::to_vec(&envelope)
            .map_err(|e| StreamError::Transport(format!("encode: {}", e)))?;
        self.transport
            .send_frame(&bytes)
            .map_err(StreamError::Transport)?;
        *self.last_frame.lock() = Some(envelope);
        Ok(())
    }

    /// Updates recovery state based on observed network conditions.
    pub fn observe_network_conditions(&self, conditions: &NetworkConditions) {
        let mut monitor = self.recovery.lock();
        if let Some(event) = monitor.feed(conditions) {
            match event {
                RecoveryEvent::RecoveryStarted(reason) => warn!(
                    target: "alpine::recovery",
                    reason = reason.as_str(),
                    "recovery started due to {}",
                    reason.as_str()
                ),
                RecoveryEvent::RecoveryComplete(reason) => info!(
                    target: "alpine::recovery",
                    reason = reason.as_str(),
                    "recovery complete for {}",
                    reason.as_str()
                ),
            }
        }
        let reason = monitor.active_reason();
        {
            let mut guard = self.recovery_reason.lock();
            *guard = reason;
        }
        drop(monitor);

        let mut adaptation = self.adaptation.lock();
        let decision = decide_next_state(&adaptation, conditions, reason, self.profile.intent());
        *adaptation = decision.state;
    }

    fn annotate_metadata(
        &self,
        metadata: Option<HashMap<String, Value>>,
        force_keyframe: bool,
        adaptation_snapshot: &AdaptationState,
    ) -> Option<HashMap<String, Value>> {
        let mut map = metadata.unwrap_or_default();
        if let Some(reason) = *self.recovery_reason.lock() {
            map.insert(
                "alpine_recovery".to_string(),
                json!({
                    "phase": "recovery",
                    "reason": reason.as_str(),
                }),
            );
        }

        let event_name = adaptation_snapshot
            .last_event
            .map(|event| event.as_str())
            .unwrap_or("steady");
        map.insert(
            "alpine_adaptation".to_string(),
            json!({
                "keyframe_interval": adaptation_snapshot.keyframe_interval,
                "delta_depth": adaptation_snapshot.delta_depth,
                "deadline_offset_ms": adaptation_snapshot.deadline_offset_ms,
                "degraded_safe": adaptation_snapshot.degraded_safe,
                "frames_since_keyframe": adaptation_snapshot.frames_since_keyframe,
                "force_keyframe": force_keyframe,
                "event": event_name,
            }),
        );
        Some(map)
    }

    fn apply_jitter(&self, channels: &[u16]) -> Vec<u16> {
        match self.jitter_strategy_from_profile() {
            JitterStrategy::HoldLast => {
                if channels.is_empty() {
                    if let Some(last) = self.last_frame.lock().as_ref() {
                        return last.channels.clone();
                    }
                }
                channels.to_vec()
            }
            JitterStrategy::Drop => {
                if channels.is_empty() {
                    Vec::new()
                } else {
                    channels.to_vec()
                }
            }
            JitterStrategy::Lerp => {
                if let Some(last) = self.last_frame.lock().as_ref() {
                    let mut blended = Vec::with_capacity(channels.len());
                    for (idx, value) in channels.iter().enumerate() {
                        let prev = last.channels.get(idx).cloned().unwrap_or(0);
                        blended.push(((prev as u32 + *value as u32) / 2) as u16);
                    }
                    blended
                } else {
                    channels.to_vec()
                }
            }
        }
    }

    fn now_us() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }

    fn jitter_strategy_from_profile(&self) -> JitterStrategy {
        if self.profile.latency_weight() >= self.profile.resilience_weight() {
            JitterStrategy::HoldLast
        } else {
            JitterStrategy::Lerp
        }
    }
}
