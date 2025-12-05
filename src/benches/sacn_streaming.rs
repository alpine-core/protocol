use std::net::UdpSocket as StdUdpSocket;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

#[path = "common/mod.rs"]
mod common;

use common::{
    config::{CHANNEL_COUNTS, UDP_BUFFER_SIZE},
    metrics::channel_payload,
    udp_loop::bind_socket,
};

const SACN_IDENTIFIER: &[u8] = b"ASC-E1.17\0\0\0";

fn build_sacn_packet(channels: &[u16]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(32 + channels.len());
    packet.extend_from_slice(SACN_IDENTIFIER);
    let count = channels.len() as u16;
    packet.extend_from_slice(&count.to_be_bytes());
    packet.push(0x00);
    for &value in channels {
        packet.push((value % 256) as u8);
    }
    packet
}

fn parse_sacn_packet(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < SACN_IDENTIFIER.len() + 3 {
        return Err("truncated");
    }
    let (id, rest) = data.split_at(SACN_IDENTIFIER.len());
    if id != SACN_IDENTIFIER {
        return Err("invalid id");
    }
    let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + len + 1 {
        return Err("length mismatch");
    }
    Ok(rest[3..3 + len].to_vec())
}

struct UdpFrameTransport {
    socket: StdUdpSocket,
    peer: std::net::SocketAddr,
}

impl UdpFrameTransport {
    fn new(socket: StdUdpSocket, peer: std::net::SocketAddr) -> Self {
        Self { socket, peer }
    }

    fn send(&self, bytes: &[u8]) -> Result<(), String> {
        self.socket
            .send_to(bytes, self.peer)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn bench_sacn_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("sacn_streaming_latency");
    for &channels in CHANNEL_COUNTS.iter() {
        let sender_socket = bind_socket().expect("bind sender");
        let receiver_socket = bind_socket().expect("bind receiver");
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let transport = UdpFrameTransport::new(sender_socket, receiver_addr);
        let payload = channel_payload(channels);
        let packet = build_sacn_packet(&payload);
        let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

        group.bench_with_input(
            BenchmarkId::new("channels", channels),
            &(channels, packet.clone()),
            |b, (chan_count, pkt)| {
                b.iter(|| {
                    transport.send(black_box(pkt)).expect("send failed");
                    let (len, _) = receiver_socket
                        .recv_from(&mut recv_buf)
                        .expect("recv failed");
                    let frame = parse_sacn_packet(&recv_buf[..len]).expect("parse failed");
                    assert_eq!(frame.len(), *chan_count);
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
    targets = bench_sacn_streaming
}
criterion_main!(benches);
