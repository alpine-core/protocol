use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{compute_mac, verify_mac, SessionKeys};
use crate::handshake::HandshakeError;
use crate::messages::{Acknowledge, ControlEnvelope, ControlOp, MessageType};
use crate::{handshake::transport::ReliableControlChannel, handshake::HandshakeTransport};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

/// Signs and verifies control envelopes using the derived session keys.
#[derive(Debug)]
pub struct ControlCrypto {
    keys: SessionKeys,
}

impl ControlCrypto {
    pub fn new(keys: SessionKeys) -> Self {
        Self { keys }
    }

    pub fn mac_for_payload(
        &self,
        seq: u64,
        session_id: &str,
        payload: &serde_json::Value,
    ) -> Result<Vec<u8>, HandshakeError> {
        let bytes = serde_cbor::to_vec(payload)
            .map_err(|e| HandshakeError::Protocol(format!("payload encode: {}", e)))?;
        compute_mac(&self.keys, seq, &bytes, session_id.as_bytes())
            .map_err(|e| HandshakeError::Authentication(e.to_string()))
    }

    pub fn verify_mac(
        &self,
        seq: u64,
        session_id: &str,
        payload: &serde_json::Value,
        mac: &[u8],
    ) -> Result<(), HandshakeError> {
        let bytes = serde_cbor::to_vec(payload)
            .map_err(|e| HandshakeError::Protocol(format!("payload encode: {}", e)))?;
        if verify_mac(&self.keys, seq, &bytes, session_id.as_bytes(), mac) {
            Ok(())
        } else {
            Err(HandshakeError::Authentication(
                "control MAC validation failed".into(),
            ))
        }
    }

    pub fn mac_for_ack(
        &self,
        seq: u64,
        session_id: &str,
        ok: bool,
        detail: Option<&str>,
        payload: Option<&[u8]>,
    ) -> Result<Vec<u8>, HandshakeError> {
        let record = AckMacRecord {
            ok,
            detail,
            payload,
        };
        let bytes = serde_cbor::to_vec(&record)
            .map_err(|e| HandshakeError::Protocol(format!("ack encode: {}", e)))?;
        compute_mac(&self.keys, seq, &bytes, session_id.as_bytes())
            .map_err(|e| HandshakeError::Authentication(e.to_string()))
    }

    pub fn decode_ack_payload<T>(payload: Option<&[u8]>) -> Result<Option<T>, HandshakeError>
    where
        T: DeserializeOwned,
    {
        if let Some(bytes) = payload {
            serde_cbor::from_slice(bytes)
                .map(Some)
                .map_err(|e| HandshakeError::Protocol(format!("ack payload decode: {}", e)))
        } else {
            Ok(None)
        }
    }
}

#[derive(Serialize)]
struct AckMacRecord<'a> {
    ok: bool,
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<&'a [u8]>,
}

/// Control-plane client helper to build authenticated envelopes and handle acks.
#[derive(Debug)]
pub struct ControlClient {
    pub device_id: Uuid,
    pub crypto: ControlCrypto,
    pub session_id: String,
}

impl ControlClient {
    pub fn new(device_id: Uuid, session_id: String, crypto: ControlCrypto) -> Self {
        Self {
            device_id,
            crypto,
            session_id,
        }
    }

    pub fn envelope(
        &self,
        seq: u64,
        op: ControlOp,
        payload: serde_json::Value,
    ) -> Result<ControlEnvelope, HandshakeError> {
        let mac = self
            .crypto
            .mac_for_payload(seq, self.session_id.as_str(), &payload)?;
        Ok(ControlEnvelope {
            message_type: MessageType::AlpineControl,
            session_id: self.session_id.clone(),
            seq,
            op,
            payload,
            mac,
        })
    }

    pub async fn send<T: HandshakeTransport + Send>(
        &self,
        channel: &mut ReliableControlChannel<T>,
        op: ControlOp,
        payload: serde_json::Value,
    ) -> Result<Acknowledge, HandshakeError> {
        let seq = channel.next_seq();
        let env = self.envelope(seq, op, payload)?;
        channel.send_reliable(env).await
    }

    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Control responder to validate envelopes and generate authenticated acks.
pub struct ControlResponder {
    pub crypto: ControlCrypto,
    pub session_id: String,
}

impl ControlResponder {
    pub fn new(session_id: String, crypto: ControlCrypto) -> Self {
        Self { crypto, session_id }
    }

    pub fn verify(&self, env: &ControlEnvelope) -> Result<(), HandshakeError> {
        if env.session_id != self.session_id {
            return Err(HandshakeError::Protocol(
                "session_id mismatch on control envelope".into(),
            ));
        }
        self.crypto
            .verify_mac(env.seq, env.session_id.as_str(), &env.payload, &env.mac)
    }

    pub fn ack(
        &self,
        seq: u64,
        ok: bool,
        detail: Option<String>,
        payload: Option<Vec<u8>>,
    ) -> Result<Acknowledge, HandshakeError> {
        let mac = self.crypto.mac_for_ack(
            seq,
            self.session_id.as_str(),
            ok,
            detail.as_deref(),
            payload.as_deref(),
        )?;
        Ok(Acknowledge {
            message_type: MessageType::AlpineControlAck,
            session_id: self.session_id.clone(),
            seq,
            ok,
            detail,
            payload,
            mac,
        })
    }
}
