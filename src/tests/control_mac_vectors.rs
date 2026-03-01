use alpine::control::{ControlClient, ControlCrypto};
use alpine::crypto::SessionKeys;
use alpine::handshake::{HandshakeMessage, HandshakeTransport};
use alpine::handshake::transport::ReliableControlChannel;
use alpine::messages::ControlOp;
use alpine::messages::{Acknowledge, MessageType};
use serde_json::json;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const EXPECTED_CONTROL_MAC_HEX: &str = "39d30b91df2bd90de6dac3e7ae44fbd2";
const EXPECTED_ACK_MAC_HEX: &str = "14e11cf57f096117a1681f9aa334b94f";

fn test_keys() -> SessionKeys {
    let mut control_key = [0u8; 32];
    for (idx, byte) in control_key.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    SessionKeys {
        shared_secret: vec![],
        control_key,
        stream_key: [0u8; 32],
    }
}

fn test_session_id() -> String {
    "11111111-2222-3333-4444-555555555555".to_string()
}

fn test_payload() -> serde_json::Value {
    json!({})
}

fn control_mac_hex() -> String {
    let client = ControlClient::new(
        Uuid::nil(),
        test_session_id(),
        ControlCrypto::new(test_keys()),
    );
    let env = client
        .envelope(2, ControlOp::GetStatus, test_payload())
        .expect("control envelope");
    hex::encode(env.mac)
}

fn ack_mac_hex() -> String {
    let crypto = ControlCrypto::new(test_keys());
    let mac = crypto
        .mac_for_ack(2, &test_session_id(), true, Some("ok"), None)
        .expect("ack mac");
    hex::encode(mac)
}

#[derive(Clone, Default)]
struct FakeTransport {
    last_control: Arc<Mutex<Option<alpine::messages::ControlEnvelope>>>,
}

#[async_trait::async_trait]
impl HandshakeTransport for FakeTransport {
    async fn send(&mut self, msg: HandshakeMessage) -> Result<(), alpine::handshake::HandshakeError> {
        if let HandshakeMessage::Control(env) = msg {
            *self.last_control.lock().expect("lock") = Some(env);
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<HandshakeMessage, alpine::handshake::HandshakeError> {
        let seq = self
            .last_control
            .lock()
            .expect("lock")
            .as_ref()
            .map(|env| env.seq)
            .unwrap_or_default();
        Ok(HandshakeMessage::Ack(Acknowledge {
            message_type: MessageType::AlpineControlAck,
            session_id: test_session_id(),
            seq,
            ok: true,
            detail: None,
            payload: None,
            mac: vec![0u8; 16],
        }))
    }
}

#[test]
fn control_mac_matches_vector() {
    let computed = control_mac_hex();
    if std::env::var("ALPINE_PRINT_VECTORS").is_ok() {
        println!("control_mac_hex={}", computed);
    }
    assert_eq!(computed, EXPECTED_CONTROL_MAC_HEX);
}

#[test]
fn ack_mac_matches_vector() {
    let computed = ack_mac_hex();
    if std::env::var("ALPINE_PRINT_VECTORS").is_ok() {
        println!("ack_mac_hex={}", computed);
    }
    assert_eq!(computed, EXPECTED_ACK_MAC_HEX);
}

#[tokio::test]
async fn reliable_channel_preserves_seq() {
    let transport = FakeTransport::default();
    let last_control = transport.last_control.clone();
    let mut channel = ReliableControlChannel::new(transport);
    let env = ControlClient::new(
        Uuid::nil(),
        test_session_id(),
        ControlCrypto::new(test_keys()),
    )
    .envelope(7, ControlOp::GetStatus, test_payload())
    .expect("control envelope");
    channel.send_reliable(env.clone()).await.expect("send");
    let sent = last_control.lock().expect("lock").clone().expect("sent");
    assert_eq!(sent.seq, 7);
}
