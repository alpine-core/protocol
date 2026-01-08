use std::error::Error;

use serde_cbor;
use serde_json::json;
use tokio::net::UdpSocket;

use alpine::control::{ControlClient, ControlCrypto, ControlResponder};
use alpine::handshake::HandshakeError;
use alpine::messages::{Acknowledge, ControlEnvelope, ControlOp};
use uuid::Uuid;

use alpine::e2e_common::run_udp_handshake;

fn verify_ack(ack: &Acknowledge, crypto: &ControlCrypto) -> Result<(), HandshakeError> {
    let expected_mac = crypto.mac_for_ack(
        ack.seq,
        &ack.session_id,
        ack.ok,
        ack.detail.as_deref(),
        ack.payload.as_deref(),
    )?;
    if expected_mac == ack.mac {
        Ok(())
    } else {
        Err(HandshakeError::Authentication("ack mac mismatch".into()))
    }
}

#[tokio::test]
#[ignore = "UDP E2E test; run explicitly when environment is ready"]
async fn control_udp_e2e_phase2() -> Result<(), Box<dyn Error>> {
    let (controller_session, node_session) = run_udp_handshake().await?;
    let session_id = controller_session
        .established()
        .ok_or("controller missing established state")?
        .session_id
        .clone();

    let controller_keys = controller_session.keys().ok_or("controller missing keys")?;
    let node_keys = node_session.keys().ok_or("node missing keys")?;

    let controller_crypto_for_client = ControlCrypto::new(controller_keys.clone());
    let controller_crypto_for_ack = ControlCrypto::new(controller_keys.clone());
    let node_crypto = ControlCrypto::new(node_keys.clone());

    let controller_socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let node_socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let node_addr = node_socket.local_addr()?;

    let responder = ControlResponder::new(session_id.clone(), node_crypto);
    let controller_control = ControlClient::new(
        Uuid::new_v4(),
        session_id.clone(),
        controller_crypto_for_client,
    );

    let node_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (len, src) = node_socket.recv_from(&mut buf).await?;
        let envelope: ControlEnvelope = serde_cbor::from_slice(&buf[..len])?;
        responder.verify(&envelope)?;
        let ack = responder.ack(envelope.seq, true, Some("ok".into()), None)?;
        let ack_bytes = serde_cbor::to_vec(&ack)?;
        node_socket.send_to(&ack_bytes, src).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let controller_task = tokio::spawn(async move {
        let payload = json!({"action": "lock"});
        let envelope = controller_control.envelope(1, ControlOp::Identify, payload)?;
        let env_bytes = serde_cbor::to_vec(&envelope)?;
        controller_socket.send_to(&env_bytes, node_addr).await?;
        let mut buf = vec![0u8; 2048];
        let (len, _) = controller_socket.recv_from(&mut buf).await?;
        let ack: Acknowledge = serde_cbor::from_slice(&buf[..len])?;
        verify_ack(&ack, &controller_crypto_for_ack)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let (node_res, controller_res) = tokio::join!(node_task, controller_task);
    node_res?.map_err(|e| e as Box<dyn Error>)?;
    controller_res?.map_err(|e| e as Box<dyn Error>)?;
    Ok(())
}
