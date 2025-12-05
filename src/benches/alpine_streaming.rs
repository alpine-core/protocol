use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_cbor;
use tokio::runtime::Runtime;

use alpine::e2e_common::run_udp_handshake;
use alpine::messages::{ChannelFormat, FrameEnvelope, MessageType};
use alpine::stream::{AlnpStream, FrameTransport};

#[path = "common/mod.rs"]
mod common;

use common::{
    config::{CHANNEL_COUNTS, FRAME_PRIORITY, UDP_BUFFER_SIZE},
    metrics::channel_payload,
    udp_loop::bind_socket,
};

struct UdpFrameTransport {
    socket: StdUdpSocket,
    peer: std::net::SocketAddr,
}

impl UdpFrameTransport {
    fn new(socket: StdUdpSocket, peer: std::net::SocketAddr) -> Self {
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

fn bench_alpine_streaming(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let (session, _node) = rt.block_on(run_udp_handshake()).expect("handshake failed");

    let mut group = c.benchmark_group("alpine_streaming_latency");
    for &channels in CHANNEL_COUNTS.iter() {
        let sender_socket = bind_socket().expect("failed to bind sender socket");
        let receiver_socket = bind_socket().expect("failed to bind receiver socket");
        receiver_socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let transport = UdpFrameTransport::new(sender_socket, receiver_addr);
        let stream = AlnpStream::new(session.clone(), transport);

        let payload = channel_payload(channels);
        let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

        group.bench_with_input(
            BenchmarkId::new("channels", channels),
            &payload,
            |b, payload| {
                b.iter(|| {
                    stream
                        .send(
                            ChannelFormat::U8,
                            payload.clone(),
                            FRAME_PRIORITY,
                            None,
                            None,
                        )
                        .expect("stream send failed");
                    let (len, _) = receiver_socket
                        .recv_from(&mut recv_buf)
                        .expect("recv failed");
                    let frame: FrameEnvelope =
                        serde_cbor::from_slice(&recv_buf[..len]).expect("decode failed");
                    assert_eq!(frame.message_type, MessageType::AlpineFrame);
                    assert_eq!(frame.channels.len(), payload.len());
                    black_box(frame);
                })
            },
        );
    }
    group.finish();
}

fn criterion_config() -> Criterion {
    Criterion::default()
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_alpine_streaming
}
criterion_main!(benches);
