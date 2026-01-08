use std::convert::TryInto;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use serde_json::json;
use tokio::sync::mpsc;
use uuid::Uuid;

use alpine::attestation::{verify_attester_bundle, verify_device_identity_attestation, AttesterRegistry};
use alpine::control::{ControlClient, ControlCrypto, ControlResponder};
use alpine::crypto::{identity::NodeCredentials, X25519KeyExchange};
use alpine::discovery::DiscoveryResponder;
use alpine::handshake::{HandshakeContext, HandshakeError, HandshakeMessage, HandshakeTransport};
use alpine::messages::{
    CapabilitySet, ChannelFormat, ControlOp, DeviceIdentity, ErrorCode, FrameEnvelope, MessageType,
};
use alpine::profile::StreamProfile;
use alpine::session::{AlnpSession, Ed25519Authenticator, JitterStrategy, StaticKeyAuthenticator};
use alpine::stream::{AlnpStream, FrameTransport};

/// Simple transport bridge used to run two handshake participants in tests.
struct PipeTransport {
    sender: mpsc::Sender<HandshakeMessage>,
    receiver: mpsc::Receiver<HandshakeMessage>,
}

impl PipeTransport {
    fn pair() -> (PipeTransport, PipeTransport) {
        let (a_tx, a_rx) = mpsc::channel(16);
        let (b_tx, b_rx) = mpsc::channel(16);
        (
            PipeTransport {
                sender: a_tx,
                receiver: b_rx,
            },
            PipeTransport {
                sender: b_tx,
                receiver: a_rx,
            },
        )
    }
}

#[async_trait]
impl HandshakeTransport for PipeTransport {
    async fn send(&mut self, msg: HandshakeMessage) -> Result<(), HandshakeError> {
        self.sender
            .send(msg)
            .await
            .map_err(|e| HandshakeError::Transport(e.to_string()))
    }

    async fn recv(&mut self) -> Result<HandshakeMessage, HandshakeError> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| HandshakeError::Transport("transport closed".into()))
    }
}

fn make_identity(name: &str) -> DeviceIdentity {
    let uuid = Uuid::new_v4();
    DeviceIdentity {
        device_id: uuid.to_string(),
        manufacturer_id: format!("{name}-manu"),
        model_id: format!("{name}-model"),
        hardware_rev: "rev1".into(),
        firmware_rev: "1.0.11".into(),
    }
}

async fn create_sessions() -> (AlnpSession, AlnpSession) {
    let mut device_secret = [0u8; 32];
    OsRng.fill_bytes(&mut device_secret);
    let device_signing = SigningKey::from_bytes(&device_secret);
    let device_creds = NodeCredentials {
        signing: device_signing.clone(),
        verifying: device_signing.verifying_key(),
    };
    let device_pubkey = device_creds.verifying.to_bytes().to_vec();

    let (mut controller_transport, mut node_transport) = PipeTransport::pair();
    let controller_task = tokio::spawn(async move {
        AlnpSession::connect(
            make_identity("controller"),
            CapabilitySet::default(),
            StaticKeyAuthenticator::default(),
            X25519KeyExchange::new(),
            HandshakeContext::default().with_device_identity_pubkey(device_pubkey),
            &mut controller_transport,
        )
        .await
    });
    let node_task = tokio::spawn(async move {
        AlnpSession::accept(
            make_identity("node"),
            CapabilitySet::default(),
            Ed25519Authenticator::new(device_creds),
            X25519KeyExchange::new(),
            HandshakeContext::default(),
            &mut node_transport,
        )
        .await
    });
    let (ctrl_res, node_res) = tokio::join!(controller_task, node_task);
    (ctrl_res.unwrap().unwrap(), node_res.unwrap().unwrap())
}

#[derive(Clone)]
struct RecordingTransport {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingTransport {
    fn new() -> Self {
        Self {
            frames: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn snapshots(&self) -> Vec<Vec<u8>> {
        self.frames.lock().unwrap().clone()
    }
}

impl FrameTransport for RecordingTransport {
    fn send_frame(&self, bytes: &[u8]) -> Result<(), String> {
        self.frames.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

#[tokio::test]
async fn handshake_derives_session_keys_and_ids() {
    let (controller, node) = create_sessions().await;
    let controller_established = controller.established().unwrap();
    let node_established = node.established().unwrap();
    assert_eq!(
        controller_established.session_id,
        node_established.session_id
    );
    assert!(controller.keys().is_some());
    assert!(node.keys().is_some());
}

#[tokio::test]
async fn control_mac_roundtrip() {
    let (controller, node) = create_sessions().await;
    let controller_established = controller.established().unwrap();
    let node_established = node.established().unwrap();
    assert_eq!(
        controller_established.session_id,
        node_established.session_id
    );
    let session_id = controller_established.session_id.clone();
    let controller_keys = controller.keys().unwrap();
    let payload = json!({"status": "ping"});
    let client = ControlClient::new(
        Uuid::new_v4(),
        session_id.clone(),
        ControlCrypto::new(controller_keys.clone()),
    );
    let responder = ControlResponder::new(
        node_established.session_id.clone(),
        ControlCrypto::new(controller_keys.clone()),
    );
    let envelope = client
        .envelope(1, ControlOp::Identify, payload.clone())
        .unwrap();
    responder.verify(&envelope).unwrap();
    let ack = responder
        .ack(envelope.seq, true, Some("ok".into()), None)
        .unwrap();
    let expected_mac = responder
        .crypto
        .mac_for_ack(
            ack.seq,
            session_id.as_str(),
            ack.ok,
            ack.detail.as_deref(),
            ack.payload.as_deref(),
        )
        .unwrap();
    assert_eq!(expected_mac, ack.mac);
}

#[tokio::test]
async fn streaming_frames_hold_last_when_requested() {
    let (controller, _) = create_sessions().await;
    controller.set_jitter_strategy(JitterStrategy::HoldLast);
    let transport = RecordingTransport::new();
    let profile = StreamProfile::auto().compile().unwrap();
    let stream = AlnpStream::new(controller.clone(), transport.clone(), profile);
    stream
        .send(ChannelFormat::U8, vec![10, 20], 5, None, None)
        .unwrap();
    stream
        .send(ChannelFormat::U8, Vec::new(), 5, None, None)
        .unwrap();
    let snapshots = transport.snapshots();
    assert_eq!(snapshots.len(), 2);
    let first: FrameEnvelope = serde_cbor::from_slice(&snapshots[0]).unwrap();
    let second: FrameEnvelope = serde_cbor::from_slice(&snapshots[1]).unwrap();
    assert_eq!(first.channels, vec![10, 20]);
    assert_eq!(second.channels, first.channels);
    assert_eq!(first.message_type, MessageType::AlpineFrame);
}

#[test]
fn capability_defaults_cover_spec_requirements() {
    let caps = CapabilitySet::default();
    assert!(caps.streaming_supported);
    assert!(caps.encryption_supported);
    assert!(caps.channel_formats.contains(&ChannelFormat::U8));
    assert_eq!(caps.max_channels, 512);
}

#[test]
fn error_codes_serialize_as_expected() {
    let json = serde_json::to_string(&ErrorCode::HandshakeTimeout).unwrap();
    assert_eq!(json, "\"HANDSHAKE_TIMEOUT\"");
}

#[test]
fn discovery_reply_is_signed_and_verifiable() {
    let identity = make_identity("device");
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let signing = SigningKey::from_bytes(&secret_bytes);
    let verifier = signing.verifying_key();
    let responder = DiscoveryResponder {
        identity,
        mac_address: "AA:BB:CC:DD".into(),
        capabilities: CapabilitySet::default(),
        signer: signing.clone(),
    };
    let server_nonce = vec![0u8; 32];
    let client_nonce = vec![1u8; 32];
    let reply = responder.reply(server_nonce.clone(), &client_nonce);
    assert_eq!(reply.message_type, MessageType::AlpineDiscoverReply);
    let mut data = server_nonce;
    data.extend_from_slice(&client_nonce);
    let sig_bytes: [u8; 64] = reply
        .signature
        .clone()
        .try_into()
        .expect("signature must be 64 bytes");
    let sig = Signature::from_bytes(&sig_bytes);
    verifier.verify(&data, &sig).unwrap();
}

#[derive(Serialize)]
struct AttestationPayload {
    device_id: String,
    #[serde(rename = "mfg")]
    manufacturer_id: String,
    #[serde(rename = "model")]
    model_id: String,
    #[serde(rename = "hw_rev")]
    hardware_rev: String,
    #[serde(rename = "pub_ed25519", with = "serde_bytes")]
    pub_ed25519: Vec<u8>,
}

#[derive(Serialize)]
struct AttestationEnvelope<'a> {
    v: u8,
    #[serde(with = "serde_bytes")]
    payload: &'a [u8],
    #[serde(with = "serde_bytes")]
    sig: &'a [u8],
    alg: &'a str,
    signer_kid: &'a str,
}

#[derive(Serialize)]
struct AttesterBundleAttester {
    kid: String,
    #[serde(with = "serde_bytes")]
    pubkey: Vec<u8>,
    alg: String,
    status: String,
}

#[derive(Serialize)]
struct AttesterBundlePayload {
    v: u8,
    issued_at: u64,
    expires_at: u64,
    attesters: Vec<AttesterBundleAttester>,
}

#[derive(Serialize)]
struct AttesterBundleEnvelope<'a> {
    v: u8,
    #[serde(with = "serde_bytes")]
    payload: &'a [u8],
    #[serde(with = "serde_bytes")]
    sig: &'a [u8],
    alg: &'a str,
    signer_kid: &'a str,
}

#[test]
fn discovery_attestation_verifies() {
    let identity = make_identity("device");
    let mut device_secret = [0u8; 32];
    OsRng.fill_bytes(&mut device_secret);
    let device_signing = SigningKey::from_bytes(&device_secret);
    let device_pubkey = device_signing.verifying_key().to_bytes().to_vec();

    let mut attester_secret = [0u8; 32];
    OsRng.fill_bytes(&mut attester_secret);
    let attester_signing = SigningKey::from_bytes(&attester_secret);
    let attester_pub = attester_signing.verifying_key();

    let payload = AttestationPayload {
        device_id: identity.device_id.clone(),
        manufacturer_id: identity.manufacturer_id.clone(),
        model_id: identity.model_id.clone(),
        hardware_rev: identity.hardware_rev.clone(),
        pub_ed25519: device_pubkey.clone(),
    };
    let payload_bytes = serde_cbor::to_vec(&payload).unwrap();
    let sig = attester_signing.sign(&payload_bytes).to_vec();

    let envelope = AttestationEnvelope {
        v: 1,
        payload: &payload_bytes,
        sig: &sig,
        alg: "Ed25519",
        signer_kid: "alpine-test",
    };
    let attestation_bytes = serde_cbor::to_vec(&envelope).unwrap();

    let reply = alpine::messages::DiscoveryReply::new(
        &identity,
        "AA:BB:CC:DD".into(),
        vec![0u8; 32],
        CapabilitySet::default(),
        vec![0u8; 64],
        device_pubkey,
        attestation_bytes,
        false,
    );

    let mut registry = AttesterRegistry::new();
    registry.insert("alpine-test", attester_pub);

    verify_device_identity_attestation(&reply, &registry, std::time::SystemTime::now()).unwrap();
}

#[test]
fn attesters_bundle_verifies_and_builds_registry() {
    let mut root_secret = [0u8; 32];
    OsRng.fill_bytes(&mut root_secret);
    let root_signing = SigningKey::from_bytes(&root_secret);
    let root_pubkey = root_signing.verifying_key().to_bytes();

    let mut attester_secret = [0u8; 32];
    OsRng.fill_bytes(&mut attester_secret);
    let attester_signing = SigningKey::from_bytes(&attester_secret);

    let payload = AttesterBundlePayload {
        v: 1,
        issued_at: 1,
        expires_at: u64::MAX,
        attesters: vec![AttesterBundleAttester {
            kid: "alpine-attester".into(),
            pubkey: attester_signing.verifying_key().to_bytes().to_vec(),
            alg: "Ed25519".into(),
            status: "active".into(),
        }],
    };
    let payload_bytes = serde_cbor::to_vec(&payload).unwrap();
    let sig = root_signing.sign(&payload_bytes).to_vec();
    let envelope = AttesterBundleEnvelope {
        v: 1,
        payload: &payload_bytes,
        sig: &sig,
        alg: "Ed25519",
        signer_kid: "alpine-root",
    };
    let bundle_bytes = serde_cbor::to_vec(&envelope).unwrap();

    let verified = verify_attester_bundle(&bundle_bytes, &root_pubkey, std::time::SystemTime::now())
        .unwrap();
    assert!(verified.registry.get("alpine-attester").is_some());
}
