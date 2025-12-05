use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

use crate::crypto::{KeyExchangeAlgorithm, SessionKeys};
use crate::messages::{
    Acknowledge, ControlEnvelope, Keepalive, SessionAck, SessionComplete, SessionEstablished,
    SessionInit, SessionReady,
};

pub mod client;
pub mod keepalive;
pub mod server;
pub mod transport;

/// Transport abstraction used during the ALNP handshake.
#[async_trait]
pub trait HandshakeTransport {
    async fn send(&mut self, msg: HandshakeMessage) -> Result<(), HandshakeError>;
    async fn recv(&mut self) -> Result<HandshakeMessage, HandshakeError>;
}

/// Minimal message envelope for the handshake pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HandshakeMessage {
    SessionInit(SessionInit),
    SessionAck(SessionAck),
    SessionReady(SessionReady),
    SessionComplete(SessionComplete),
    SessionEstablished(SessionEstablished),
    Keepalive(Keepalive),
    Control(ControlEnvelope),
    Ack(Acknowledge),
}

/// Context shared between handshake participants.
#[derive(Debug, Clone)]
pub struct HandshakeContext {
    pub key_algorithm: KeyExchangeAlgorithm,
    pub expected_controller: Option<String>,
    pub required_firmware_rev: Option<String>,
    pub client_nonce: Vec<u8>,
    pub device_identity_pubkey: Option<Vec<u8>>,
    pub recv_timeout: Duration,
    pub debug_cbor: bool,
}

impl HandshakeContext {
    pub fn with_client_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.client_nonce = nonce;
        self
    }

    pub fn with_device_identity_pubkey(mut self, pubkey: Vec<u8>) -> Self {
        self.device_identity_pubkey = Some(pubkey);
        self
    }

    pub fn with_recv_timeout(mut self, timeout: Duration) -> Self {
        self.recv_timeout = timeout;
        self
    }

    pub fn with_debug_cbor(mut self, enabled: bool) -> Self {
        self.debug_cbor = enabled;
        self
    }
}

impl Default for HandshakeContext {
    fn default() -> Self {
        Self {
            key_algorithm: KeyExchangeAlgorithm::X25519,
            expected_controller: None,
            required_firmware_rev: None,
            client_nonce: new_nonce().to_vec(),
            device_identity_pubkey: None,
            recv_timeout: Duration::from_millis(7000),
            debug_cbor: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("unsupported capability: {0}")]
    Capability(String),
}

/// Generates a cryptographic nonce for challenge/response.
pub fn new_nonce() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Shared behavior between controller and node handshake roles.
#[async_trait]
pub trait HandshakeParticipant {
    async fn run<T: HandshakeTransport + Send>(
        &self,
        transport: &mut T,
    ) -> Result<HandshakeOutcome, HandshakeError>;
}

/// Minimal authenticator stub for challenge validation.
pub trait ChallengeAuthenticator {
    fn sign_challenge(&self, nonce: &[u8]) -> Vec<u8>;
    fn verify_challenge(&self, nonce: &[u8], signature: &[u8]) -> bool;
    fn identity_verifying_key(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Output returned by handshake drivers.
#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    pub established: SessionEstablished,
    pub keys: SessionKeys,
}
