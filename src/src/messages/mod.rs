use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub const ALPINE_VERSION: &str = "1.0";

/// Common envelope type identifiers used across CBOR payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    AlpineDiscover,
    AlpineDiscoverReply,
    SessionInit,
    SessionAck,
    SessionReady,
    SessionComplete,
    AlpineControl,
    AlpineControlAck,
    AlpineFrame,
    Keepalive,
}

/// Discovery request broadcast by controllers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveryRequest {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    #[serde(rename = "alpine_version")]
    pub alpine_version: String,
    #[serde(with = "serde_bytes")]
    pub client_nonce: Vec<u8>,
    pub requested: Vec<String>,
}

impl DiscoveryRequest {
    pub fn new(requested: Vec<String>, client_nonce: Vec<u8>) -> Self {
        Self {
            message_type: MessageType::AlpineDiscover,
            alpine_version: ALPINE_VERSION.to_string(),
            client_nonce,
            requested,
        }
    }
}

/// Discovery reply signed by the device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveryReply {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub alpine_version: String,
    pub device_id: String,
    pub manufacturer_id: String,
    pub model_id: String,
    pub hardware_rev: String,
    pub firmware_rev: String,
    pub mac: String,
    #[serde(with = "serde_bytes")]
    pub server_nonce: Vec<u8>,
    pub capabilities: CapabilitySet,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Optional Ed25519 identity public key (32 bytes) used to sign handshake challenges.
    #[serde(
        with = "serde_bytes",
        default,
        alias = "identity_pubkey",
        alias = "device_identity_key",
        alias = "identity_public_key",
        alias = "device_identity_public_key"
    )]
    pub device_identity_pubkey: Vec<u8>,
}

impl DiscoveryReply {
    pub fn new(
        identity: &DeviceIdentity,
        mac: String,
        server_nonce: Vec<u8>,
        capabilities: CapabilitySet,
        signature: Vec<u8>,
        device_identity_pubkey: Vec<u8>,
    ) -> Self {
        Self {
            message_type: MessageType::AlpineDiscoverReply,
            alpine_version: ALPINE_VERSION.to_string(),
            device_id: identity.device_id.clone(),
            manufacturer_id: identity.manufacturer_id.clone(),
            model_id: identity.model_id.clone(),
            hardware_rev: identity.hardware_rev.clone(),
            firmware_rev: identity.firmware_rev.clone(),
            mac,
            server_nonce,
            capabilities,
            signature,
            device_identity_pubkey,
        }
    }
}

/// Device identity tuple exchanged during discovery and handshake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub manufacturer_id: String,
    pub model_id: String,
    pub hardware_rev: String,
    pub firmware_rev: String,
}

/// Declared capabilities as defined by the spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilitySet {
    pub channel_formats: Vec<ChannelFormat>,
    pub max_channels: u32,
    pub grouping_supported: bool,
    pub streaming_supported: bool,
    pub encryption_supported: bool,
    pub vendor_extensions: Option<HashMap<String, serde_json::Value>>,
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self {
            channel_formats: vec![ChannelFormat::U8],
            max_channels: 512,
            grouping_supported: false,
            streaming_supported: true,
            encryption_supported: true,
            vendor_extensions: None,
        }
    }
}

/// Supported channel encodings for frames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChannelFormat {
    U8,
    U16,
}

/// Handshake session_init payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionInit {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    #[serde(with = "serde_bytes")]
    pub controller_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub controller_pubkey: Vec<u8>,
    pub requested: CapabilitySet,
    pub session_id: String,
}

/// Handshake session_ack payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionAck {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    #[serde(with = "serde_bytes")]
    pub device_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_pubkey: Vec<u8>,
    #[serde(
        with = "serde_bytes",
        default,
        alias = "identity_pubkey",
        alias = "device_identity_key",
        alias = "identity_public_key",
        alias = "device_identity_public_key"
    )]
    pub device_identity_pubkey: Vec<u8>,
    pub device_identity: DeviceIdentity,
    pub capabilities: CapabilitySet,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub session_id: String,
}

/// Controller readiness marker after keys are derived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionReady {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub session_id: String,
    #[serde(with = "serde_bytes")]
    pub mac: Vec<u8>,
}

/// Device completion acknowledgement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionComplete {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub session_id: String,
    pub ok: bool,
    pub error: Option<ErrorCode>,
}

/// Internal representation of an established session derived from the handshake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionEstablished {
    pub session_id: String,
    #[serde(with = "serde_bytes")]
    pub controller_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_nonce: Vec<u8>,
    pub capabilities: CapabilitySet,
    pub device_identity: DeviceIdentity,
}

/// Control-plane envelope with authenticated payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlEnvelope {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub session_id: String,
    pub seq: u64,
    pub op: ControlOp,
    pub payload: serde_json::Value,
    #[serde(with = "serde_bytes")]
    pub mac: Vec<u8>,
}

/// Ack for control-plane operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Acknowledge {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub session_id: String,
    pub seq: u64,
    pub ok: bool,
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub mac: Vec<u8>,
}

/// Control operations enumerated by the spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlOp {
    GetInfo,
    GetCaps,
    Identify,
    Restart,
    GetStatus,
    SetConfig,
    SetMode,
    TimeSync,
    Vendor,
}

/// Real-time frame envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrameEnvelope {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub session_id: String,
    pub timestamp_us: u64,
    pub priority: u8,
    pub channel_format: ChannelFormat,
    pub channels: Vec<u16>,
    pub groups: Option<HashMap<String, Vec<u16>>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Control-plane keepalive frame to detect dead sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Keepalive {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub session_id: String,
    pub tick_ms: u64,
}

/// Standard error codes from docs/errors.md.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    DiscoveryInvalidSignature,
    DiscoveryNonceMismatch,
    DiscoveryUnsupportedVersion,
    HandshakeSignatureInvalid,
    HandshakeKeyDerivationFailed,
    HandshakeTimeout,
    HandshakeReplay,
    SessionExpired,
    SessionInvalidToken,
    SessionMacMismatch,
    ControlUnknownOp,
    ControlPayloadInvalid,
    ControlUnauthorized,
    StreamBadFormat,
    StreamTooLarge,
    StreamUnsupportedChannelMode,
}
