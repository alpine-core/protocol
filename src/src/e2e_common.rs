use std::error::Error;
use std::net::SocketAddr;

use async_trait::async_trait;
use serde_cbor;
use tokio::net::UdpSocket;

use crate::crypto::X25519KeyExchange;
use crate::handshake::{HandshakeContext, HandshakeError, HandshakeMessage, HandshakeTransport};
use crate::messages::{CapabilitySet, DeviceIdentity};
use crate::session::{AlnpSession, StaticKeyAuthenticator};
use uuid::Uuid;

struct UdpHandshakeTransport {
    socket: UdpSocket,
    peer: SocketAddr,
    buf_size: usize,
}

impl UdpHandshakeTransport {
    fn new(socket: UdpSocket, peer: SocketAddr, buf_size: usize) -> Self {
        Self {
            socket,
            peer,
            buf_size,
        }
    }
}

#[async_trait]
impl HandshakeTransport for UdpHandshakeTransport {
    async fn send(&mut self, msg: HandshakeMessage) -> Result<(), HandshakeError> {
        let bytes = serde_cbor::to_vec(&msg)
            .map_err(|e| HandshakeError::Protocol(format!("encode: {}", e)))?;
        self.socket
            .send_to(&bytes, self.peer)
            .await
            .map_err(|e| HandshakeError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<HandshakeMessage, HandshakeError> {
        let mut buf = vec![0u8; self.buf_size];
        let (len, _) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| HandshakeError::Transport(e.to_string()))?;
        serde_cbor::from_slice(&buf[..len])
            .map_err(|e| HandshakeError::Protocol(format!("decode: {}", e)))
    }
}

pub fn make_identity(prefix: &str) -> DeviceIdentity {
    DeviceIdentity {
        device_id: Uuid::new_v4().to_string(),
        manufacturer_id: format!("{prefix}-manu"),
        model_id: format!("{prefix}-model"),
        hardware_rev: "rev1".into(),
        firmware_rev: "1.0.11".into(),
    }
}

pub async fn run_udp_handshake() -> Result<(AlnpSession, AlnpSession), Box<dyn Error>> {
    let controller_socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let node_socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let controller_addr = controller_socket.local_addr()?;
    let node_addr = node_socket.local_addr()?;

    let controller_task = tokio::spawn(async move {
        let mut transport = UdpHandshakeTransport::new(controller_socket, node_addr, 4096);
        AlnpSession::connect(
            make_identity("controller"),
            CapabilitySet::default(),
            StaticKeyAuthenticator::default(),
            X25519KeyExchange::new(),
            HandshakeContext::default(),
            &mut transport,
        )
        .await
    });

    let node_task = tokio::spawn(async move {
        let mut transport = UdpHandshakeTransport::new(node_socket, controller_addr, 4096);
        AlnpSession::accept(
            make_identity("node"),
            CapabilitySet::default(),
            StaticKeyAuthenticator::default(),
            X25519KeyExchange::new(),
            HandshakeContext::default(),
            &mut transport,
        )
        .await
    });

    let (controller_res, node_res) = tokio::join!(controller_task, node_task);
    let controller_session = controller_res??;
    let node_session = node_res??;
    Ok((controller_session, node_session))
}
