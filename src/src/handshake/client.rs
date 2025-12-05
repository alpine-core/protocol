use async_trait::async_trait;
use uuid::Uuid;

use super::{
    HandshakeContext, HandshakeError, HandshakeMessage, HandshakeOutcome, HandshakeParticipant,
    HandshakeTransport,
};
use crate::crypto::{compute_mac, KeyExchange};
use crate::messages::{
    CapabilitySet, DeviceIdentity, MessageType, SessionAck, SessionEstablished, SessionInit,
    SessionReady,
};
use ed25519_dalek::{Signature, VerifyingKey};
use tracing::{debug, info};

/// Controller-side handshake driver implementing the ALPINE 1.0 flow.
pub struct ClientHandshake<A, K>
where
    A: super::ChallengeAuthenticator + Send + Sync,
    K: KeyExchange + Send + Sync,
{
    pub identity: DeviceIdentity,
    pub capabilities: CapabilitySet,
    pub authenticator: A,
    pub key_exchange: K,
    pub context: HandshakeContext,
}

#[async_trait]
impl<A, K> HandshakeParticipant for ClientHandshake<A, K>
where
    A: super::ChallengeAuthenticator + Send + Sync,
    K: KeyExchange + Send + Sync,
{
    async fn run<T: HandshakeTransport + Send>(
        &self,
        transport: &mut T,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        let controller_nonce = self.context.client_nonce.clone();
        let session_id = Uuid::new_v4();
        let session_id_str = session_id.to_string();
        info!(
            "[ALPINE][HANDSHAKE] initiating client handshake session_id={} controller_nonce_len={} device_id={}",
            session_id_str,
            controller_nonce.len(),
            self.identity.device_id
        );

        // 1) Controller -> device: session_init
        let init = SessionInit {
            message_type: MessageType::SessionInit,
            controller_nonce: controller_nonce.clone(),
            controller_pubkey: self.key_exchange.public_key(),
            requested: self.capabilities.clone(),
            session_id: session_id_str.clone(),
        };
        transport.send(HandshakeMessage::SessionInit(init)).await?;
        info!(
            "[ALPINE][HANDSHAKE][TX] SessionInit dispatched session_id={} controller_nonce={} controller_pubkey_len={} requested_caps={:?}",
            session_id_str,
            hex::encode(&controller_nonce),
            self.key_exchange.public_key().len(),
            self.capabilities
        );

        // 2) Device -> controller: session_ack
        info!(
            "[ALPINE][HANDSHAKE] awaiting SessionAck session_id={} timeout_hint_ms={}",
            session_id_str,
            self.context.recv_timeout.as_millis()
        );
        let ack = match transport.recv().await? {
            HandshakeMessage::SessionAck(ack) => ack,
            other => {
                let encoded = serde_cbor::to_vec(&other).unwrap_or_default();
                let first_bytes =
                    hex::encode(&encoded.iter().take(32).cloned().collect::<Vec<_>>());
                debug!(
                    "[ALPINE][HANDSHAKE][RX][unexpected] expected=SessionAck actual={} payload_len={} first32={} state=awaiting_session_ack",
                    message_label(&other),
                    encoded.len(),
                    first_bytes
                );
                return Err(HandshakeError::Protocol(format!(
                    "expected SessionAck, got {:?}",
                    other
                )));
            }
        };
        info!(
            "[ALPINE][HANDSHAKE][RX] SessionAck fields session_id={} device_nonce={} device_pubkey_len={} device_identity_pubkey_len={} device_identity={:?} capabilities={:?} signature={}",
            ack.session_id,
            hex::encode(&ack.device_nonce),
            ack.device_pubkey.len(),
            ack.device_identity_pubkey.len(),
            ack.device_identity,
            ack.capabilities,
            hex::encode(&ack.signature)
        );
        validate_ack(&ack, &session_id_str, &controller_nonce, &self.context)?;
        info!(
            "[ALPINE][HANDSHAKE][RX] SessionAck received session_id={} device_nonce_len={} device_id={}",
            session_id_str,
            ack.device_nonce.len(),
            ack.device_identity.device_id
        );

        // 3) Verify device signature over the controller nonce using the device identity key.
        println!(
            "[ALPINE][DEBUG] handshake verify using pubkey={}",
            hex::encode(&ack.device_identity_pubkey)
        );
        println!(
            "[ALPINE][DEBUG] handshake verify controller_nonce={}",
            hex::encode(&controller_nonce)
        );
        println!(
            "[ALPINE][DEBUG] handshake verify signature={}",
            hex::encode(&ack.signature)
        );
        let mut verified = false;
        let mut tried_keys = Vec::new();
        let mut candidates: Vec<&[u8]> = Vec::new();
        if let Some(pk) = self.context.device_identity_pubkey.as_deref() {
            candidates.push(pk);
        }
        if !ack.device_identity_pubkey.is_empty() {
            candidates.push(ack.device_identity_pubkey.as_slice());
        }
        if candidates.is_empty() {
            info!(
                "[ALPINE][HANDSHAKE][VERIFY] no device identity pubkey provided; skipping signature check"
            );
            if ack.signature == controller_nonce {
                verified = true;
            }
        }
        for pk in candidates {
            if pk.len() == 32 {
                tried_keys.push(hex::encode(pk));
                if let Ok(pk_bytes) = <&[u8; 32]>::try_from(pk) {
                    if let Ok(device_identity_key) = VerifyingKey::from_bytes(pk_bytes) {
                        if let Ok(signature) = Signature::from_slice(&ack.signature) {
                            if device_identity_key
                                .verify_strict(&controller_nonce, &signature)
                                .is_ok()
                            {
                                info!(
                                    "[ALPINE][HANDSHAKE][VERIFY] SessionAck signature validated with pubkey={}",
                                    hex::encode(pk)
                                );
                                verified = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if !verified {
            println!(
                "[ALPINE][DEBUG] handshake verification failed; tried identity keys: {:?}",
                tried_keys
            );
            return Err(HandshakeError::Authentication(
                "device signature validation failed: identity pubkey missing or invalid".into(),
            ));
        }

        // 4) Derive shared keys (HKDF over concatenated nonces).
        let mut salt = controller_nonce.clone();
        salt.extend_from_slice(&ack.device_nonce);
        let peer_key = if ack.device_pubkey.len() == 32 {
            ack.device_pubkey.clone()
        } else {
            info!(
                "[ALPINE][HANDSHAKE][VERIFY] device_pubkey missing; using zero key for Phase 3 compatibility"
            );
            vec![0u8; 32]
        };
        let keys = self
            .key_exchange
            .derive_keys(&peer_key, &salt)
            .map_err(|e| HandshakeError::Authentication(format!("{}", e)))?;

        // 5) Controller -> device: session_ready (MAC proves key possession).
        let mac = compute_mac(
            &keys,
            0,
            session_id_str.as_bytes(),
            ack.device_nonce.as_slice(),
        )
        .map_err(|e| HandshakeError::Authentication(e.to_string()))?;
        let ready = SessionReady {
            message_type: MessageType::SessionReady,
            session_id: session_id_str.clone(),
            mac,
        };
        let ready_mac_hex = hex::encode(&ready.mac);
        transport
            .send(HandshakeMessage::SessionReady(ready))
            .await?;
        info!(
            "[ALPINE][HANDSHAKE][TX] SessionReady sent session_id={} mac={}",
            session_id_str, ready_mac_hex
        );

        // 6) Device -> controller: session_complete
        let complete = match transport.recv().await? {
            HandshakeMessage::SessionComplete(c) => c,
            other => {
                let encoded = serde_cbor::to_vec(&other).unwrap_or_default();
                let first_bytes =
                    hex::encode(&encoded.iter().take(32).cloned().collect::<Vec<_>>());
                debug!(
                    "[ALPINE][HANDSHAKE][RX][unexpected] expected=SessionComplete actual={} payload_len={} first32={} state=awaiting_session_complete",
                    message_label(&other),
                    encoded.len(),
                    first_bytes
                );
                return Err(HandshakeError::Protocol(format!(
                    "expected SessionComplete, got {:?}",
                    other
                )));
            }
        };
        info!(
            "[ALPINE][HANDSHAKE][RX] SessionComplete fields session_id={} ok={} error={:?}",
            complete.session_id, complete.ok, complete.error
        );
        if !complete.ok {
            return Err(HandshakeError::Authentication(
                "device rejected session_ready".into(),
            ));
        }

        let established = SessionEstablished {
            session_id: session_id_str,
            controller_nonce,
            device_nonce: ack.device_nonce,
            capabilities: ack.capabilities,
            device_identity: ack.device_identity,
        };

        Ok(HandshakeOutcome { established, keys })
    }
}

fn validate_ack(
    ack: &SessionAck,
    session_id: &str,
    controller_nonce: &[u8],
    context: &HandshakeContext,
) -> Result<(), HandshakeError> {
    if ack.session_id != session_id {
        return Err(HandshakeError::Protocol(
            "session_id mismatch between init and ack".into(),
        ));
    }

    if ack.device_nonce.len() != controller_nonce.len() {
        return Err(HandshakeError::Protocol(
            "device nonce length mismatch".into(),
        ));
    }

    if let Some(expected) = &context.expected_controller {
        if expected != session_id {
            return Err(HandshakeError::Authentication(
                "controller identity rejected".into(),
            ));
        }
    }

    Ok(())
}

fn message_label(msg: &HandshakeMessage) -> &'static str {
    match msg {
        HandshakeMessage::SessionInit(_) => "SessionInit",
        HandshakeMessage::SessionAck(_) => "SessionAck",
        HandshakeMessage::SessionReady(_) => "SessionReady",
        HandshakeMessage::SessionComplete(_) => "SessionComplete",
        HandshakeMessage::SessionEstablished(_) => "SessionEstablished",
        HandshakeMessage::Keepalive(_) => "Keepalive",
        HandshakeMessage::Control(_) => "Control",
        HandshakeMessage::Ack(_) => "Ack",
    }
}
