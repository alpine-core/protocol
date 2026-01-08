use std::net::SocketAddr;

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::messages::{CapabilitySet, DiscoveryReply, DiscoveryRequest, MessageType};

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("socket error: {0}")]
    Io(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("signature invalid")]
    InvalidSignature,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("unsupported version")]
    UnsupportedVersion,
}

/// Controller-side discovery helper.
pub struct DiscoveryClient;

impl DiscoveryClient {
    pub async fn broadcast(
        socket: &UdpSocket,
        broadcast: SocketAddr,
        requested: Vec<String>,
    ) -> Result<Vec<u8>, DiscoveryError> {
        let mut nonce = vec![0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let request = DiscoveryRequest::new(requested, nonce.clone());
        let bytes =
            serde_cbor::to_vec(&request).map_err(|e| DiscoveryError::Decode(e.to_string()))?;
        socket
            .send_to(&bytes, broadcast)
            .await
            .map_err(|e| DiscoveryError::Io(e.to_string()))?;
        Ok(nonce)
    }

    pub async fn recv_reply(
        socket: &UdpSocket,
        expected_nonce: &[u8],
        verifier: &VerifyingKey,
    ) -> Result<DiscoveryReply, DiscoveryError> {
        let mut buf = vec![0u8; 2048];
        let (len, _) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| DiscoveryError::Io(e.to_string()))?;
        let reply: DiscoveryReply = serde_cbor::from_slice(&buf[..len])
            .map_err(|e| DiscoveryError::Decode(e.to_string()))?;
        verify_reply(&reply, expected_nonce, verifier)?;
        Ok(reply)
    }
}

/// Device-side responder skeleton.
pub struct DiscoveryResponder {
    pub identity: crate::messages::DeviceIdentity,
    pub mac_address: String,
    pub capabilities: CapabilitySet,
    pub signer: ed25519_dalek::SigningKey,
}

impl DiscoveryResponder {
    pub fn reply(&self, server_nonce: Vec<u8>, client_nonce: &[u8]) -> DiscoveryReply {
        let mut data = server_nonce.clone();
        data.extend_from_slice(client_nonce);
        let signature = self.signer.sign(&data).to_vec();
        let pubkey = self.signer.verifying_key().to_bytes().to_vec();
        DiscoveryReply::new(
            &self.identity,
            self.mac_address.clone(),
            server_nonce,
            self.capabilities.clone(),
            signature,
            pubkey,
            Vec::new(),
            false,
        )
    }
}

fn verify_reply(
    reply: &DiscoveryReply,
    expected_client_nonce: &[u8],
    verifier: &VerifyingKey,
) -> Result<(), DiscoveryError> {
    if reply.message_type != MessageType::AlpineDiscoverReply {
        return Err(DiscoveryError::UnsupportedVersion);
    }
    if reply.alpine_version != crate::messages::ALPINE_VERSION {
        return Err(DiscoveryError::UnsupportedVersion);
    }

    // Signature is taken over server_nonce || client_nonce to bind request/response.
    let mut data = reply.server_nonce.clone();
    data.extend_from_slice(expected_client_nonce);
    let sig =
        Signature::from_slice(&reply.signature).map_err(|_| DiscoveryError::InvalidSignature)?;
    verifier
        .verify(&data, &sig)
        .map_err(|_| DiscoveryError::InvalidSignature)?;
    Ok(())
}
