use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

#[path = "common/mod.rs"]
mod common;

use common::{
    config::{CHANNEL_COUNTS, UDP_BUFFER_SIZE},
    metrics::channel_payload,
    udp_loop::bind_socket,
};

const ARTNET_ID: &[u8] = b"Art-Net\0";
const OPCODE_DMX: u16 = 0x5000;

fn build_artnet_packet(channels: &[u16]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + channels.len());
    packet.extend_from_slice(ARTNET_ID);
    packet.extend_from_slice(&OPCODE_DMX.to_le_bytes());
    packet.extend_from_slice(&[0x00, 0x14]);
    packet.push(0x00);
    packet.push(0x00);
    packet.extend_from_slice(&0x0000u16.to_le_bytes());
    let length = (channels.len() + 1) as u16;
    packet.extend_from_slice(&length.to_be_bytes());
    packet.push(0x00);
    for &value in channels {
        packet.push((value % 256) as u8);
    }
    packet
}

fn parse_artnet_packet(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < ARTNET_ID.len() + 10 {
        return Err("truncated");
    }
    if &data[..ARTNET_ID.len()] != ARTNET_ID {
        return Err("bad id");
    }
    let length =
        u16::from_be_bytes([data[ARTNET_ID.len() + 8], data[ARTNET_ID.len() + 9]]) as usize;
    if data.len() < ARTNET_ID.len() + 10 + length {
        return Err("length");
    }
    Ok(data[ARTNET_ID.len() + 10..ARTNET_ID.len() + 10 + length].to_vec())
}

fn bench_artnet_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("artnet_streaming_latency");
    for &channels in CHANNEL_COUNTS.iter() {
        let sender_socket = bind_socket().expect("bind sender");
        let receiver_socket = bind_socket().expect("bind receiver");
        receiver_socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let channel_data = channel_payload(channels);
        let packet = build_artnet_packet(&channel_data);
        let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

        group.bench_with_input(
            BenchmarkId::new("channels", channels),
            &(channels, packet.clone(), receiver_addr),
            |b, (chan_count, pkt, addr)| {
                b.iter(|| {
                    sender_socket
                        .send_to(black_box(pkt), *addr)
                        .expect("send failed");
                    let (len, _) = receiver_socket
                        .recv_from(&mut recv_buf)
                        .expect("recv failed");
                    let frame = parse_artnet_packet(&recv_buf[..len]).expect("parse failed");
                    assert_eq!(frame.len(), chan_count + 1);
                    black_box(frame);
                });
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
    targets = bench_artnet_streaming
}
criterion_main!(benches);
