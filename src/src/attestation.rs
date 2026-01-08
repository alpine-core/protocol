use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_cbor::Value;
use thiserror::Error;

use crate::messages::DiscoveryReply;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("device identity attestation missing")]
    Missing,
    #[error("attestation decode failed: {0}")]
    Decode(String),
    #[error("attestation missing field: {0}")]
    MissingField(&'static str),
    #[error("attestation invalid field: {0}")]
    InvalidField(&'static str),
    #[error("attestation unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("attestation signer not trusted: {0}")]
    UnknownSigner(String),
    #[error("attestation signature invalid")]
    InvalidSignature,
    #[error("attestation expired")]
    Expired,
    #[error("attestation identity mismatch: {0}")]
    IdentityMismatch(&'static str),
    #[error("device identity pubkey missing from discovery")]
    MissingDeviceIdentityPubkey,
}

#[derive(Debug, Clone, Default)]
pub struct AttesterRegistry {
    keys: HashMap<String, VerifyingKey>,
}

impl AttesterRegistry {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn insert(&mut self, kid: impl Into<String>, key: VerifyingKey) {
        self.keys.insert(kid.into(), key);
    }

    pub fn insert_key_bytes(
        &mut self,
        kid: impl Into<String>,
        key_bytes: &[u8],
    ) -> Result<(), AttestationError> {
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| AttestationError::InvalidField("signer_kid_pubkey"))?;
        let verifying = VerifyingKey::from_bytes(&key)
            .map_err(|_| AttestationError::InvalidField("signer_kid_pubkey"))?;
        self.insert(kid, verifying);
        Ok(())
    }

    pub fn get(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[derive(Debug)]
pub struct VerifiedDeviceIdentityAttestation {
    pub signer_kid: String,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Error)]
pub enum AttesterBundleError {
    #[error("attesters bundle decode failed: {0}")]
    Decode(String),
    #[error("attesters bundle missing field: {0}")]
    MissingField(&'static str),
    #[error("attesters bundle invalid field: {0}")]
    InvalidField(&'static str),
    #[error("attesters bundle unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("attesters bundle signature invalid")]
    InvalidSignature,
    #[error("attesters bundle expired")]
    Expired,
    #[error("root key invalid")]
    InvalidRootKey,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttesterRecord {
    pub kid: String,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    pub alg: String,
    pub status: String,
    #[serde(default)]
    pub revoked_at: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VerifiedAttesterBundle {
    pub issued_at: u64,
    pub expires_at: u64,
    pub signer_kid: Option<String>,
    pub attesters: Vec<AttesterRecord>,
    pub registry: AttesterRegistry,
}

#[derive(Debug, Deserialize)]
struct DeviceIdentityPayload {
    device_id: String,
    #[serde(rename = "mfg")]
    manufacturer_id: String,
    #[serde(rename = "model")]
    model_id: String,
    #[serde(rename = "hw_rev")]
    hardware_rev: String,
    #[serde(rename = "pub_ed25519", with = "serde_bytes")]
    pub_ed25519: Vec<u8>,
    #[serde(default)]
    expires_at: Option<u64>,
}

fn value_as_text(value: &Value) -> Option<String> {
    match value {
        Value::Text(text) => Some(text.clone()),
        Value::Bytes(bytes) => Some(hex::encode(bytes)),
        _ => None,
    }
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(int) if *int >= 0 => Some(*int as u64),
        Value::Float(float) if *float >= 0.0 => Some(*float as u64),
        _ => None,
    }
}

fn value_as_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

fn map_lookup<'a>(
    map: &'a std::collections::BTreeMap<Value, Value>,
    key: &str,
) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::Text(text) if text == key => Some(v),
        _ => None,
    })
}

pub fn verify_device_identity_attestation(
    reply: &DiscoveryReply,
    registry: &AttesterRegistry,
    now: SystemTime,
) -> Result<VerifiedDeviceIdentityAttestation, AttestationError> {
    if reply.device_identity_attestation.is_empty() {
        return Err(AttestationError::Missing);
    }
    if reply.device_identity_pubkey.is_empty() {
        return Err(AttestationError::MissingDeviceIdentityPubkey);
    }

    let envelope: Value = serde_cbor::from_slice(&reply.device_identity_attestation)
        .map_err(|err| AttestationError::Decode(err.to_string()))?;
    let map = match envelope {
        Value::Map(map) => map,
        _ => return Err(AttestationError::InvalidField("attestation_map")),
    };

    let payload_bytes = map_lookup(&map, "payload")
        .and_then(value_as_bytes)
        .ok_or(AttestationError::MissingField("payload"))?;
    let sig_bytes = map_lookup(&map, "sig")
        .and_then(value_as_bytes)
        .ok_or(AttestationError::MissingField("sig"))?;
    let alg = map_lookup(&map, "alg")
        .and_then(value_as_text)
        .ok_or(AttestationError::MissingField("alg"))?;
    let signer_kid = map_lookup(&map, "signer_kid")
        .and_then(value_as_text)
        .ok_or(AttestationError::MissingField("signer_kid"))?;
    let expires_at = map_lookup(&map, "expires_at").and_then(value_as_u64);

    let alg_lower = alg.to_ascii_lowercase();
    if alg_lower != "ed25519" && alg_lower != "eddsa" {
        return Err(AttestationError::UnsupportedAlgorithm(alg));
    }

    let attester_key = registry
        .get(&signer_kid)
        .ok_or_else(|| AttestationError::UnknownSigner(signer_kid.clone()))?;

    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| AttestationError::InvalidSignature)?;
    attester_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| AttestationError::InvalidSignature)?;

    let payload: DeviceIdentityPayload = serde_cbor::from_slice(&payload_bytes)
        .map_err(|err| AttestationError::Decode(err.to_string()))?;

    if payload.device_id != reply.device_id {
        return Err(AttestationError::IdentityMismatch("device_id"));
    }
    if payload.manufacturer_id != reply.manufacturer_id {
        return Err(AttestationError::IdentityMismatch("manufacturer_id"));
    }
    if payload.model_id != reply.model_id {
        return Err(AttestationError::IdentityMismatch("model_id"));
    }
    if payload.hardware_rev != reply.hardware_rev {
        return Err(AttestationError::IdentityMismatch("hardware_rev"));
    }
    if payload.pub_ed25519 != reply.device_identity_pubkey {
        return Err(AttestationError::IdentityMismatch("device_identity_pubkey"));
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let expires = expires_at.or(payload.expires_at);
    if let Some(expires_at) = expires {
        if expires_at <= now_secs {
            return Err(AttestationError::Expired);
        }
    }

    Ok(VerifiedDeviceIdentityAttestation {
        signer_kid,
        expires_at: expires,
    })
}

#[derive(Debug, Deserialize)]
struct AttesterBundleEnvelope {
    v: u8,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
    alg: String,
    #[serde(default)]
    signer_kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AttesterBundlePayload {
    v: u8,
    issued_at: u64,
    expires_at: u64,
    attesters: Vec<AttesterRecord>,
}

pub fn verify_attester_bundle(
    bundle_bytes: &[u8],
    root_pubkey: &[u8],
    now: SystemTime,
) -> Result<VerifiedAttesterBundle, AttesterBundleError> {
    let key_bytes: [u8; 32] = root_pubkey
        .try_into()
        .map_err(|_| AttesterBundleError::InvalidRootKey)?;
    let root_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| AttesterBundleError::InvalidRootKey)?;

    let envelope: AttesterBundleEnvelope = serde_cbor::from_slice(bundle_bytes)
        .map_err(|err| AttesterBundleError::Decode(err.to_string()))?;
    if envelope.v == 0 {
        return Err(AttesterBundleError::InvalidField("v"));
    }

    let alg_lower = envelope.alg.to_ascii_lowercase();
    if alg_lower != "ed25519" && alg_lower != "eddsa" {
        return Err(AttesterBundleError::UnsupportedAlgorithm(envelope.alg));
    }

    let signature =
        Signature::from_slice(&envelope.sig).map_err(|_| AttesterBundleError::InvalidSignature)?;
    root_key
        .verify(&envelope.payload, &signature)
        .map_err(|_| AttesterBundleError::InvalidSignature)?;

    let payload: AttesterBundlePayload = serde_cbor::from_slice(&envelope.payload)
        .map_err(|err| AttesterBundleError::Decode(err.to_string()))?;

    if payload.v == 0 {
        return Err(AttesterBundleError::InvalidField("payload.v"));
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    if payload.expires_at <= now_secs {
        return Err(AttesterBundleError::Expired);
    }

    let mut registry = AttesterRegistry::new();
    let mut active_attesters = Vec::new();

    for attester in payload.attesters.into_iter() {
        let status_lower = attester.status.to_ascii_lowercase();
        if status_lower != "active" {
            continue;
        }
        if let Some(revoked_at) = attester.revoked_at {
            if revoked_at <= now_secs {
                continue;
            }
        }
        if let Some(expires_at) = attester.expires_at {
            if expires_at <= now_secs {
                continue;
            }
        }
        let alg_lower = attester.alg.to_ascii_lowercase();
        if alg_lower != "ed25519" && alg_lower != "eddsa" {
            return Err(AttesterBundleError::UnsupportedAlgorithm(attester.alg));
        }
        registry
            .insert_key_bytes(attester.kid.clone(), &attester.pubkey)
            .map_err(|_| AttesterBundleError::InvalidField("attester.pubkey"))?;
        active_attesters.push(attester);
    }

    Ok(VerifiedAttesterBundle {
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        signer_kid: envelope.signer_kid,
        attesters: active_attesters,
        registry,
    })
}
