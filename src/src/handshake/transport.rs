use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use hex;
use serde_cbor::value::Value as CborValue;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, info, trace};

use super::{HandshakeError, HandshakeMessage, HandshakeTransport};
use crate::messages::{Acknowledge, ControlEnvelope};

/// CBOR-over-UDP transport for handshake and control-plane exchange.
#[derive(Debug)]
pub struct CborUdpTransport {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    max_size: usize,
    debug_cbor: bool,
}

impl CborUdpTransport {
    pub async fn bind(
        local: SocketAddr,
        peer: SocketAddr,
        max_size: usize,
        debug_cbor: bool,
    ) -> Result<Self, HandshakeError> {
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|e| HandshakeError::Transport(e.to_string()))?;
        socket
            .connect(peer)
            .await
            .map_err(|e| HandshakeError::Transport(e.to_string()))?;
        let bound = socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        info!(
            "[ALPINE][HANDSHAKE][SOCKET] UDP transport bound local_addr={} peer={} max_size={}",
            bound, peer, max_size
        );
        Ok(Self {
            socket: Arc::new(socket),
            peer,
            max_size,
            debug_cbor,
        })
    }

    pub fn from_socket(
        socket: UdpSocket,
        peer: SocketAddr,
        max_size: usize,
        debug_cbor: bool,
    ) -> Result<Self, HandshakeError> {
        let bound = socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        info!(
            "[ALPINE][HANDSHAKE][SOCKET] UDP transport using provided socket local_addr={} peer={} max_size={}",
            bound, peer, max_size
        );
        Ok(Self {
            socket: Arc::new(socket),
            peer,
            max_size,
            debug_cbor,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

#[async_trait]
impl HandshakeTransport for CborUdpTransport {
    async fn send(&mut self, msg: HandshakeMessage) -> Result<(), HandshakeError> {
        let bytes = serde_cbor::to_vec(&msg)
            .map_err(|e| HandshakeError::Transport(format!("encode: {}", e)))?;
        let local_addr = self.local_addr();
        info!(
            "[ALPINE][TX] msg_type={} local_addr={} remote_addr={} bytes={}",
            message_label(&msg),
            local_addr,
            self.peer,
            bytes.len()
        );
        trace!(peer=%self.peer, len=%bytes.len(), message=?msg, "handshake send");
        self.socket
            .send_to(&bytes, self.peer)
            .await
            .map_err(|e| HandshakeError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<HandshakeMessage, HandshakeError> {
        let mut buf = vec![0u8; self.max_size];
        let (len, from) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| HandshakeError::Transport(e.to_string()))?;
        let local_addr = self.local_addr();
        let preview_len = len.min(32);
        let preview = hex::encode(&buf[..preview_len]);
        let tail_len = len.min(16);
        let tail = hex::encode(&buf[len.saturating_sub(tail_len)..len]);
        info!(
            "[ALPINE][RX] raw packet received local_addr={} from={} bytes={} buf_cap={} first32={} last16={}",
            local_addr,
            from,
            len,
            self.max_size,
            preview,
            tail
        );
        trace!(peer=%from, len=%len, "handshake raw recv");
        if self.debug_cbor {
            debug!(
                "[ALPINE][HANDSHAKE][DEBUG_CBOR] raw_hex={}",
                hex::encode(&buf[..len])
            );
            log_cbor_structure(&buf[..len]);
        }
        let mut msg = serde_cbor::from_slice(&buf[..len])
            .map_err(|e| HandshakeError::Transport(format!("decode: {}", e)));
        if let Err(_) = &msg {
            if !buf.is_empty() && (buf[0] & 0xE0) == 0xA0 {
                debug!(
                    "[ALPINE][HANDSHAKE][RX] attempting truncated CBOR map repair len={} cap={} first_byte=0x{:x}",
                    len,
                    self.max_size,
                    buf[0]
                );
                let mut repaired = buf[..len].to_vec();
                repaired[0] = 0xBF; // Indefinite-length map.
                repaired.push(0xFF); // Break.
                msg = serde_cbor::from_slice(&repaired)
                    .map_err(|e| HandshakeError::Transport(format!("decode(repaired): {}", e)));
            }
        }
        if let Ok(parsed) = &msg {
            info!(
                "[ALPINE][HANDSHAKE][RX][parsed] variant={} local_addr={} from={} fields={}",
                message_label(parsed),
                local_addr,
                from,
                describe_fields(parsed)
            );
        }
        trace!(peer=%from, result=?msg, "handshake parsed message");
        msg
    }
}

/// Wrapper that enforces per-message timeouts on recv.
#[derive(Debug)]
pub struct TimeoutTransport<T> {
    inner: T,
    recv_timeout: Duration,
}

impl<T> TimeoutTransport<T> {
    pub fn new(inner: T, recv_timeout: Duration) -> Self {
        Self {
            inner,
            recv_timeout,
        }
    }
}

#[async_trait]
impl<T> HandshakeTransport for TimeoutTransport<T>
where
    T: HandshakeTransport + Send,
{
    async fn send(&mut self, msg: HandshakeMessage) -> Result<(), HandshakeError> {
        self.inner.send(msg).await
    }

    async fn recv(&mut self) -> Result<HandshakeMessage, HandshakeError> {
        debug!(
            "[ALPINE][HANDSHAKE] recv with timeout_ms={}",
            self.recv_timeout.as_millis()
        );
        match time::timeout(self.recv_timeout, self.inner.recv()).await {
            Ok(res) => res,
            Err(_) => Err(HandshakeError::Transport("recv timeout".into())),
        }
    }
}

/// Minimal reliability layer for control envelopes with retransmissions and replay protection.
pub struct ReliableControlChannel<T> {
    transport: T,
    seq: u64,
    max_attempts: u8,
    base_timeout: Duration,
    drop_threshold: u8,
}

impl<T> ReliableControlChannel<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            seq: 0,
            max_attempts: 5,
            base_timeout: Duration::from_millis(200),
            drop_threshold: 5,
        }
    }
}

impl<T> ReliableControlChannel<T>
where
    T: HandshakeTransport + Send,
{
    pub async fn send_reliable(
        &mut self,
        mut envelope: ControlEnvelope,
    ) -> Result<Acknowledge, HandshakeError> {
        self.seq = self.seq.wrapping_add(1);
        envelope.seq = self.seq;

        let mut attempt: u8 = 0;
        loop {
            attempt += 1;
            self.transport
                .send(HandshakeMessage::Control(envelope.clone()))
                .await?;

            let timeout = self
                .base_timeout
                .checked_mul(2u32.saturating_pow((attempt - 1) as u32))
                .unwrap_or(self.base_timeout * 4);

            match time::timeout(timeout, self.transport.recv()).await {
                Ok(Ok(HandshakeMessage::Ack(ack))) => {
                    if ack.seq == envelope.seq && ack.ok {
                        return Ok(ack);
                    }
                }
                Ok(Ok(HandshakeMessage::Keepalive(_))) => {
                    // keepalive resets attempt counter
                    attempt = 0;
                }
                _ => {
                    if attempt >= self.max_attempts || attempt >= self.drop_threshold {
                        return Err(HandshakeError::Transport(
                            "control channel retransmit limit exceeded".into(),
                        ));
                    }
                }
            }
        }
    }

    pub fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }
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

fn log_cbor_structure(bytes: &[u8]) {
    if let Ok(value) = serde_cbor::from_slice::<CborValue>(bytes) {
        match value {
            CborValue::Map(map) => {
                debug!(
                    "[ALPINE][HANDSHAKE][DEBUG_CBOR] map_len={} entries={}",
                    map.len(),
                    map.len()
                );
                for (idx, (key, val)) in map.iter().enumerate() {
                    debug!(
                        "[ALPINE][HANDSHAKE][DEBUG_CBOR] entry={} key_type={} value_type={}",
                        idx,
                        describe_value(key),
                        describe_value(val)
                    );
                }
            }
            other => {
                debug!(
                    "[ALPINE][HANDSHAKE][DEBUG_CBOR] non-map top-level type={}",
                    describe_value(&other)
                );
            }
        }
    } else {
        debug!("[ALPINE][HANDSHAKE][DEBUG_CBOR] decode failed");
    }
}

fn describe_value(val: &CborValue) -> &'static str {
    match val {
        CborValue::Null => "null",
        CborValue::Bool(_) => "bool",
        CborValue::Integer(_) => "integer",
        CborValue::Bytes(_) => "bytes",
        CborValue::Text(_) => "text",
        CborValue::Array(_) => "array",
        CborValue::Map(_) => "map",
        CborValue::Tag(_, _) => "tag",
        CborValue::Float(_) => "float",
        _ => "other",
    }
}

fn describe_fields(msg: &HandshakeMessage) -> String {
    match msg {
        HandshakeMessage::SessionInit(init) => format!(
            "session_id={} controller_nonce_len={} controller_pubkey_len={} requested={:?}",
            init.session_id,
            init.controller_nonce.len(),
            init.controller_pubkey.len(),
            init.requested
        ),
        HandshakeMessage::SessionAck(ack) => format!(
            "session_id={} device_nonce_len={} device_pubkey_len={} device_identity_pubkey_len={} device_id={}",
            ack.session_id,
            ack.device_nonce.len(),
            ack.device_pubkey.len(),
            ack.device_identity_pubkey.len(),
            ack.device_identity.device_id
        ),
        HandshakeMessage::SessionReady(ready) => format!(
            "session_id={} mac_len={}",
            ready.session_id,
            ready.mac.len()
        ),
        HandshakeMessage::SessionComplete(comp) => format!(
            "session_id={} ok={} error={:?}",
            comp.session_id, comp.ok, comp.error
        ),
        HandshakeMessage::SessionEstablished(est) => format!(
            "session_id={} controller_nonce_len={} device_nonce_len={} device_id={}",
            est.session_id,
            est.controller_nonce.len(),
            est.device_nonce.len(),
            est.device_identity.device_id
        ),
        HandshakeMessage::Keepalive(k) => {
            format!("session_id={} tick_ms={}", k.session_id, k.tick_ms)
        }
        HandshakeMessage::Control(ctrl) => format!(
            "session_id={} seq={} op={:?} mac_len={}",
            ctrl.session_id,
            ctrl.seq,
            ctrl.op,
            ctrl.mac.len()
        ),
        HandshakeMessage::Ack(ack) => format!(
            "session_id={} seq={} ok={} detail_present={} payload_present={}",
            ack.session_id,
            ack.seq,
            ack.ok,
            ack.detail.is_some(),
            ack.payload.is_some()
        ),
    }
}
