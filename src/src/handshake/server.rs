use async_trait::async_trait;
use uuid::Uuid;

use super::{
    new_nonce, ChallengeAuthenticator, HandshakeContext, HandshakeError, HandshakeMessage,
    HandshakeOutcome, HandshakeParticipant, HandshakeTransport,
};
use crate::crypto::{compute_mac, KeyExchange};
use crate::messages::{
    CapabilitySet, DeviceIdentity, MessageType, SessionAck, SessionComplete, SessionEstablished,
};

/// Node-side handshake driver that validates the controller and proves identity.
pub struct ServerHandshake<A, K>
where
    A: ChallengeAuthenticator + Send + Sync,
    K: KeyExchange + Send + Sync,
{
    pub identity: DeviceIdentity,
    pub capabilities: CapabilitySet,
    pub authenticator: A,
    pub key_exchange: K,
    pub context: HandshakeContext,
}

#[async_trait]
impl<A, K> HandshakeParticipant for ServerHandshake<A, K>
where
    A: ChallengeAuthenticator + Send + Sync,
    K: KeyExchange + Send + Sync,
{
    async fn run<T: HandshakeTransport + Send>(
        &self,
        transport: &mut T,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        // 1) Controller -> device: session_init
        let init = match transport.recv().await? {
            HandshakeMessage::SessionInit(msg) => msg,
            other => {
                return Err(HandshakeError::Protocol(format!(
                    "expected SessionInit, got {:?}",
                    other
                )))
            }
        };

        let _session_uuid = Uuid::parse_str(&init.session_id)
            .map_err(|_| HandshakeError::Protocol("invalid session_id".into()))?;

        if let Some(expected) = &self.context.expected_controller {
            if expected != &init.session_id {
                return Err(HandshakeError::Authentication(
                    "controller identity not authorized".into(),
                ));
            }
        }

        // 2) Device -> controller: session_ack
        let device_nonce = new_nonce().to_vec();
        let signature = self.authenticator.sign_challenge(&init.controller_nonce);
        let identity_pubkey = self
            .authenticator
            .identity_verifying_key()
            .unwrap_or_default();
        let ack = SessionAck {
            message_type: MessageType::SessionAck,
            device_nonce: device_nonce.clone(),
            device_pubkey: self.key_exchange.public_key(),
            device_identity_pubkey: identity_pubkey,
            device_identity: self.identity.clone(),
            capabilities: self.capabilities.clone(),
            signature,
            session_id: init.session_id.clone(),
        };
        transport
            .send(HandshakeMessage::SessionAck(ack.clone()))
            .await?;

        // 3) Controller -> device: session_ready (validate MAC)
        let ready = match transport.recv().await? {
            HandshakeMessage::SessionReady(r) => r,
            other => {
                return Err(HandshakeError::Protocol(format!(
                    "expected SessionReady, got {:?}",
                    other
                )))
            }
        };

        if ready.session_id != init.session_id {
            return Err(HandshakeError::Protocol(
                "session_id mismatch between init and ready".into(),
            ));
        }

        let mut salt = init.controller_nonce.clone();
        salt.extend_from_slice(&device_nonce);
        let keys = self
            .key_exchange
            .derive_keys(&init.controller_pubkey, &salt)
            .map_err(|e| HandshakeError::Authentication(format!("{}", e)))?;
        let mac_valid = compute_mac(
            &keys,
            0,
            init.session_id.as_bytes(),
            device_nonce.as_slice(),
        )
        .map(|expected| expected == ready.mac)
        .unwrap_or(false);
        if !mac_valid {
            return Err(HandshakeError::Authentication(
                "session_ready MAC invalid".into(),
            ));
        }

        // 4) Device -> controller: session_complete
        let complete = SessionComplete {
            message_type: MessageType::SessionComplete,
            session_id: init.session_id.clone(),
            ok: true,
            error: None,
        };
        transport
            .send(HandshakeMessage::SessionComplete(complete))
            .await?;

        let established = SessionEstablished {
            session_id: init.session_id,
            controller_nonce: init.controller_nonce,
            device_nonce,
            capabilities: init.requested,
            device_identity: self.identity.clone(),
        };

        Ok(HandshakeOutcome { established, keys })
    }
}
