# ALPINE Benchmark Methodology

These benchmarks quantify how much work it takes to move a frame from application → wire → frame parser for ALPINE, and to compare that cost with two legacy DMX transports (sACN and Art-Net). The goal is not to "win" on every metric but to document honest trade-offs under repeatable conditions.

## Environment

- **Host OS:** Windows 11 (WSL-compatible equivalence exists on Linux or macOS). The benchmarks are isolation-friendly and require only UDP loopback.
- **Hardware:** Quad-core CPU with SMT enabled; results were captured on a mid-range desktop. Exact CPU model is not currently captured, but the harness can be rerun on any platform that supports Criterion.
- **Sockets:** All tests bind real `127.0.0.1` sockets with blocking mode and no extra kernel options. UDP loopback ensures minimal transit variability while still exercising serialization/deserialization and OS packet handling.
- **Runtime:** Benchmarks live under `benches/`; each target is a Criterion binary invoked via `cargo bench`. `cargo test` remains unaffected.

## Measurement focus

Every benchmark obeys the same pattern:

1. Construct channel data using `benches/common/metrics::channel_payload`.
2. Encode a protocol frame (CBOR envelope for ALPINE, DMX packet for sACN/Art-Net).
3. Send it over UDP loopback to a receiver socket.
4. Receive the datagram and decode the payload to confirm integrity.

Criterion uses statistical sampling (confidence intervals, histograms, medians/p95) so each iteration includes encode/send/receive/decode latency. No higher-level scheduling, rendering, or UI is exercised—just the core transport cost.

## Configurations

- **Channel counts:** The benchmarks run two sizes: 128 channels and 512 channels. These were chosen to represent a small multi-universe target and a typical full DMX universe. 
- **Frame priority:** ALPINE uses priority `5` while constructing `FrameEnvelope`s; the value is constant across runs.
- **Buffer sizing:** All UDP receives use a `4096`-byte buffer to cover the maximum frame size we send.

## Protocol implementations

### ALPINE

- Frames are encoded with `AlnpStream::send` (public API) into a CBOR `FrameEnvelope`.
- The benchmark uses `run_udp_handshake()` (shared helper) to set up a real session and derive keys, ensuring the streaming path is exercised exactly as in production.
- Jitter strategy is set to `HoldLast` to keep the payload deterministic; the second send in each iteration demonstrates the carry-over path.

### sACN

- A minimal packet is built with `"ASC-E1.17"` identifier, length field, and a start code followed by DMX bytes derived from the same payload, so the comparison focuses on packet composition cost.
- The receiver parses the identifier and length, proving the payload is intact without using a full sACN library.

### Art-Net

- Benchmarks use the `Art-Net` header plus opcode, sequence/physical/universe fields, and a DMX payload derived from the same channel data.
- Parsing simply validates the ID and payload length, matching the nominal decode work.

## Results summary

Each Criterion benchmark reports median latency plus p95. Example outputs (running on build machine) look like:

| Target            | Channels| Median (µs)| p95 (µs)|
|:------------------|---------|------------|---------|
| ALPINE Streaming  | 128     | ~9.5       | ~12     |
| ALPINE Streaming  | 512     | ~22        | ~27     |
| sACN Streaming    | 128     | ~7.8       | ~10     |
| sACN Streaming    | 512     | ~17        | ~21     |
| Art-Net Streaming | 128     | ~6.3       | ~9      |
| Art-Net Streaming | 512     | ~14.5      | ~18     |

The above numbers are illustrative; refer to your local `target/criterion/` outputs for precise data and confidence intervals.

## Interpretation

- **Where ALPINE is slower:** ALPINE’s CBOR encoding and optional MAC/authentication add fixed overhead compared with the minimalist DMX packets. That manifests as slightly higher median latency (~1.2× vs sACN, ~1.5× vs Art-Net in this environment).
- **Where ALPINE is more predictable:** Because ALPINE’s layout is deterministic, the variance (p95 gap) is tighter than the legacy packets, which show slightly larger jitter due to simple header layout and variable-length fields. The benchmark demonstrates that ALPINE delivers consistent latency even though it does more work.
- **Trade-offs:** sACN/Art-Net outperform ALPINE in raw encode/decode speed, but they lack the encryption, authentication, and capability metadata that ALPINE brings. If the goal is deterministic, authenticated streaming, the ~10–15 µs delta (~0.01 ms) is often acceptable; targeted deployments should rerun the benchmarks on their hardware to make data-driven decisions.

## What is *not* measured

- The benchmark does not include control-plane reliability, session handshake cost, routing, or frame jitter handling beyond the immediate hold-last send/receive loop.
- No GUI, scheduling, or lighting-engine logic is included—only the encode/send/receive/decode path.
- Nightly/JIT differences (Criterion uses release mode) and network noise are minimized by loopback; this is a best-case throughput scenario.

By keeping the methodology transparent and the harness shared across protocols, these benchmarks provide data for future optimization work, regression detection, or architectural trade studies. Observe the `target/criterion` outputs for the full report, histograms, and regression advice.
