//! Authenticated Lighting Network Protocol (ALPINE) reference implementation (v1.0).
//!
//! Implements discovery, handshake, control, and streaming layers as defined in the
//! specification documents. All messages are encoded using CBOR and cryptographically
//! authenticated with Ed25519 + X25519 + HKDF + ChaCha20-Poly1305.

pub mod attestation;
pub mod control;
pub mod crypto;
pub mod device;
pub mod discovery;
pub mod e2e_common;
pub mod handshake;
pub mod messages;
pub mod profile;
pub mod session;
pub mod stream;

pub use control::{ControlClient, ControlCrypto, ControlResponder};
pub use device::DeviceServer;
pub use messages::{
    Acknowledge, CapabilitySet, ChannelFormat, ControlEnvelope, ControlOp, DeviceIdentity,
    DiscoveryReply, DiscoveryRequest, FrameEnvelope, MessageType, SessionEstablished,
};
pub use profile::{CompiledStreamProfile, StreamProfile};
pub use session::{AlnpRole, AlnpSession, JitterStrategy};
pub use stream::{AlnpStream, FrameTransport};

mod c_api;
