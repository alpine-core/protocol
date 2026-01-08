use std::error::Error;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

use serde_cbor;
use tokio::net::UdpSocket;

use alpine::messages::{ChannelFormat, FrameEnvelope, MessageType};
use alpine::profile::StreamProfile;
use alpine::session::JitterStrategy;
use alpine::stream::{AlnpStream, FrameTransport};

use alpine::e2e_common::run_udp_handshake;

struct UdpFrameTransport {
    socket: StdUdpSocket,
    peer: SocketAddr,
}

impl UdpFrameTransport {
    fn new(socket: StdUdpSocket, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }
}

impl FrameTransport for UdpFrameTransport {
    fn send_frame(&self, bytes: &[u8]) -> Result<(), String> {
        self.socket
            .send_to(bytes, self.peer)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
#[ignore = "UDP E2E test; run explicitly when environment is ready"]
async fn streaming_udp_e2e_phase3() -> Result<(), Box<dyn Error>> {
    let (controller_session, _node_session) = run_udp_handshake().await?;
    controller_session.set_jitter_strategy(JitterStrategy::HoldLast);

    let stream_socket = StdUdpSocket::bind(("127.0.0.1", 0))?;
    let receiver_socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let receiver_addr = receiver_socket.local_addr()?;

    let transport = UdpFrameTransport::new(stream_socket, receiver_addr);
    let profile = StreamProfile::auto().compile().unwrap();
    let stream = AlnpStream::new(controller_session.clone(), transport, profile);

    let receiver_task = tokio::spawn(async move {
        let mut frames = Vec::with_capacity(2);
        for _ in 0..2 {
            let mut buf = vec![0u8; 4096];
            let (len, _) = receiver_socket.recv_from(&mut buf).await?;
            let frame: FrameEnvelope = serde_cbor::from_slice(&buf[..len])?;
            frames.push(frame);
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(frames)
    });

    stream
        .send(ChannelFormat::U8, vec![1, 2, 3], 5, None, None)
        .map_err(|e| Box::<dyn Error>::from(e))?;
    stream
        .send(ChannelFormat::U8, Vec::new(), 5, None, None)
        .map_err(|e| Box::<dyn Error>::from(e))?;

    let frames = receiver_task.await?.map_err(|e| e as Box<dyn Error>)?;
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].message_type, MessageType::AlpineFrame);
    assert_eq!(frames[0].channels, vec![1, 2, 3]);
    assert_eq!(frames[1].message_type, MessageType::AlpineFrame);
    assert_eq!(frames[1].channels, frames[0].channels);
    Ok(())
}
