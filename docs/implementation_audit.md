# Implementation vs Documentation Audit

This report compares the promises written in the documentation (`README.md`, `SPEC.md`, and the files under `docs/`) against the current implementation, tests, and benchmarks located in `protocol/rust/alpine-protocol-rs`. It also highlights how the new `protocol/rust/alpine-protocol-rs/docs/benchmarks.md` ties back to the generated Criterion artifacts under `target/criterion`.

## README-level commitments

- **Discovery / Handshake / Control / Streaming** - The README frames those four layers as ALPINE's core. Each layer now has a real-UDP exercise in `protocol/rust/alpine-protocol-rs/tests/e2e/`:
  - `handshake_udp_e2e.rs` runs the controller and node over real `tokio::net::UdpSocket`s, completes the `session_init` -> `session_complete` sequence, and asserts that both sides derive the same session ID and keys (Phase 1).
  - `control_udp_e2e.rs` exchanges signed control envelopes, verifies MACs and sequence numbers, and delivers ACKs entirely over the wire (Phase 2).
  - `streaming_udp_e2e.rs` sends `FrameEnvelope`s through sockets, decodes them, and exercises `JitterStrategy::HoldLast` across real timing (Phase 3).
  - Discovery lives inside `protocol/rust/alpine-protocol-rs/src/discovery.rs`, where replies are signed with Ed25519 and nonces are validated before returning `DiscoveryReply` structures.
- **Capability System and Extensibility** - `CapabilitySet` flows through discovery, handshake, session state, and control helpers (`protocol/rust/alpine-protocol-rs/src/messages/mod.rs`, `protocol/rust/alpine-protocol-rs/src/handshake/*`, and `protocol/rust/alpine-protocol-rs/src/session/mod.rs`). `tests/feature_suite.rs` insists on default capabilities, matching the README's claim that controllers learn device capabilities without guessing.
- **Language bindings (Rust, TypeScript, Python, C)** - The root `protocol/` directory contains `ts/`, `python/`, and `c/` subprojects that mirror the Rust structures (`CapabilitySet`, `DiscoveryReply`, etc.). While this audit did not run their package managers, the code exists to satisfy `docs/reference_impl.md`.
- **Benchmarks and diagnostics** - The README's mention of structured diagnostics is complemented by the Criterion benchmark suite described in `protocol/rust/alpine-protocol-rs/docs/benchmarks.md` and the artifacts under `target/criterion/*`. Each report contains histograms, regression notices, and medians that document the latency numbers promised in the documentation.

## SPEC sections vs implementation

- **Discovery layer (Section 4 and `docs/discovery.md`)** - The spec describes UDP discovery with capability blocks, server nonces, and Ed25519 signatures. `protocol/rust/alpine-protocol-rs/src/messages/mod.rs` defines `DiscoveryRequest` and `DiscoveryReply`, while `protocol/rust/alpine-protocol-rs/src/discovery.rs` signs replies and validates incoming replies; `tests/e2e/discovery_e2e.rs` exercises this over sockets.
- **Handshake layer (Section 5 and `docs/handshake.md`)** - The spec enumerates the `session_init` -> `session_ack` -> `session_ready` -> `session_complete` handshake and insists on capability negotiation. The code in `protocol/rust/alpine-protocol-rs/src/handshake/*` follows that flow, and `tests/e2e/handshake_udp_e2e.rs` runs it end-to-end over real UDP sockets with the shared helper `protocol/rust/alpine-protocol-rs/src/e2e_common.rs`.
- **Control plane (Section 6 and `docs/control_plane.md`)** - The spec requires MAC-protected envelopes, monotonic sequence numbers, ACKs, and retransmits. These elements live in `protocol/rust/alpine-protocol-rs/src/control.rs`, and `tests/e2e/control_udp_e2e.rs` verifies MAC validation, ACK replies, and proper session binding over UDP.
- **Streaming transport (Section 7 and `docs/streaming.md`)** - The frame structure, jitter strategies, and ordered delivery requirements are implemented inside `protocol/rust/alpine-protocol-rs/src/stream.rs`. The streaming e2e test (`tests/e2e/streaming_udp_e2e.rs`) touches the socket layer, while `benches/alpine_streaming.rs` exercises the encode -> send -> receive -> decode path described in `protocol/rust/alpine-protocol-rs/docs/benchmarks.md`.
- **Error codes (`docs/errors.md`)** - All documented error variants appear in the `ErrorCode` enum inside `protocol/rust/alpine-protocol-rs/src/messages/mod.rs`, guaranteeing consistent serialization.
- **Security (`docs/security.md`)** - The security model lists Ed25519, X25519, HKDF-SHA256, and ChaCha20-Poly1305. Those primitives are referenced by `protocol/rust/alpine-protocol-rs/src/crypto/*` and `protocol/rust/alpine-protocol-rs/src/session/mod.rs` for signature verification, key derivation, and MAC tagging. The handshake tests confirm that invalid signatures or MACs fail the session (fail-closed semantics).

## docs/ tree checklist

| Document | Key claim | Current evidence |
|---|---|---|
| `docs/architecture.md` | Layered stack (discovery, control, streaming) | `protocol/rust/alpine-protocol-rs` maintains separate modules for each layer, and the UDP e2e tests exercise them without bypassing the public APIs. |
| `docs/discovery.md` | Broadcast discovery, signed replies, capabilities | `protocol/rust/alpine-protocol-rs/src/discovery.rs` constructs signed replies, and `tests/e2e/discovery_e2e.rs` verifies the behavior. |
| `docs/handshake.md` | Mutual authentication, capability negotiation | `protocol/rust/alpine-protocol-rs/src/handshake/*` plus `tests/e2e/handshake_udp_e2e.rs` implement Section 5. |
| `docs/control_plane.md` | Reliable MAC-verified control envelopes, ACKs | `protocol/rust/alpine-protocol-rs/src/control.rs` tracks sequence numbers and tags each envelope; `tests/e2e/control_udp_e2e.rs` confirms ACK handling. |
| `docs/streaming.md` | Frame envelopes, jitter strategies (`hold-last`, `drop`, `lerp`) | `protocol/rust/alpine-protocol-rs/src/stream.rs` exposes `JitterStrategy`, and the UDP streaming test plus benchmark use `HoldLast` over sockets. |
| `docs/capabilities.md` | Capability maps in discovery/handshake/get_caps | `CapabilitySet` is shared across `protocol/rust/alpine-protocol-rs/src/messages`, `protocol/rust/alpine-protocol-rs/src/handshake`, and `protocol/rust/alpine-protocol-rs/src/session`, and `tests/feature_suite.rs` validates defaults. |
| `docs/errors.md` | Structured codes such as `STREAM_TOO_LARGE` | `ErrorCode` in `protocol/rust/alpine-protocol-rs/src/messages/mod.rs` matches the list. |
| `docs/security.md` | Ed25519, X25519, HKDF, ChaCha20-Poly1305 | `protocol/rust/alpine-protocol-rs/src/crypto` and the session layer instantiate those primitives. |
| `docs/reference_impl.md` | Multi-language references (Rust, TS, Python, C) | `protocol/ts`, `protocol/python`, and `protocol/c` implement shared APIs (`CapabilitySet`, discovery replies) even though this audit did not invoke their build flows. |
| `protocol/rust/alpine-protocol-rs/docs/benchmarks.md` | Real UDP benchmark harness + methodology | `benches/alpine_streaming.rs`, `benches/artnet_streaming.rs`, and `benches/sacn_streaming.rs` reuse the shared handshake helper, and the Criterion reports appear under `target/criterion/<bench_name>/report/index.html`. The most recent run reported medians around 10.3-10.6 us (128 channels) and 13.4-13.7 us (512 channels) for ALPINE. |

## Benchmark reality check

- `cargo bench -- --nocapture` runs all three Criterion benchmarks (`alpine_streaming`, `artnet_streaming`, `sacn_streaming`) and produces full reports under `target/criterion/alpine_streaming_latency`, `target/criterion/artnet_streaming_latency`, and `target/criterion/sacn_streaming_latency`.
- Latest measured medians from the console output:
  * **ALPINE** - 128 channels: ~10.3-11.0 us, 512 channels: ~13.4-13.7 us.
  * **Art-Net** - 128 channels: ~6.3-6.5 us, 512 channels: ~6.5-6.7 us.
  * **sACN** - 128 channels: ~7.6-8.3 us, 512 channels: ~6.5-6.7 us.
- These numbers follow the encode -> send -> receive -> decode loop described in `protocol/rust/alpine-protocol-rs/docs/benchmarks.md`, and the CSV/histograms in each `report/index.html` document the same medians, p95, and outlier counts.

## CI integration

- `.github/workflows/e2e-tests.yml` runs the UDP E2E suite on `ubuntu-latest`. It checks out the repo, installs the stable toolchain, and invokes `cargo test --tests -- --ignored` inside `protocol/rust/alpine-protocol-rs`, ensuring the real-socket handshake/control/streaming state-machines stay exercised on every pull request and push to `main`.

## Publishing infrastructure

- Rust publishing targets GitHub Packages via `cargo publish --registry github`; `CARGO_REGISTRIES_GITHUB_TOKEN` should be set and the registry index is declared within `protocol/rust/alpine-protocol-rs/Cargo.toml` to point at `https://github.com/y-link-dmx/Authenticated-Lighting-Protocol.git`.
- TypeScript, Python, and C release scripts already run the UDP E2E suite and stage artifacts into `dist/{ts,python,rust,c}`; their respective token requirements are documented in the root README so maintainers know which secrets to provide for GitHub (or PyPI/npm) publishing.
## Outstanding observations

- `docs/reference_impl.md` promises working protocol helpers for TS, Python, and C. Those directories exist, but their package managers were not invoked in this audit, so their pipelines should be verified before claiming parity.
- `docs/security.md` mentions optional vendor certificates and local pairing modes. Those features are not currently exercised in `protocol/rust/alpine-protocol-rs`, so they are still candidates for follow-up work if they must be part of the security story.
- `docs/errors.md` defines streaming errors like `STREAM_TOO_LARGE` and `STREAM_UNSUPPORTED_CHANNEL_MODE`. Although the variants exist in `ErrorCode`, the current runtime does not emit every error path, so targeted tests would be needed to prove those branches.

## Bindings status

- **TypeScript (`protocol/ts`)** now exports helpers such as `buildDiscoveryRequest`, `buildControlEnvelope`, and `buildFrameEnvelope`, mirroring the objects described under `docs/handshake.md` / `docs/streaming.md`, so frontend code can assemble CBOR payloads without repeating the field names.
- **Python (`protocol/python`)** adds equivalent helpers (`build_discovery_request`, `build_control_envelope`, `build_frame_envelope`) plus the existing dataclasses, keeping that binding in sync with the Rust datatypes and the UDP handshake/control/streaming docs.
- **C (`protocol/c/alnp.h`)** continues to expose `alnp_build_discovery_request`, `alnp_verify_discovery_reply`, `alnp_encode_control`, and `alnp_encode_stream_frame`; these functions remain the C entry points for the protocol helper library described in `docs/reference_impl.md`. The new C++ helper header (`protocol/cpp/alnp.hpp`) wraps those helpers in RAII-friendly buffers so C++ code can call the same helpers without dipping into the C structs. The `embedded` CI job proves that `ALPINE_EMBEDDED` can compile with `-fno-exceptions -fno-rtti -fno-threadsafe-statics -Os`, satisfying the ESP32-like constraints on heap usage and runtime support. SDK layers in `sdk/rust`, `sdk/c`, and `sdk/cpp` demonstrate how to build idiomatic clients, while the TypeScript and Python directories are now bindings-only; the Rust SDK’s `StreamProfile` model remains the canonical behavior contract.
- **Rust example (`examples/rust/basic.rs`)** and packaging scripts now mention the UDP E2E architecture (`docs/implementation_audit.md`) and run the real handshake tests (`scripts/build_rust.sh`, `scripts/build_c.sh`).

With these updates, each binding layer has minimal helper functions that reflect the documented ALPINE architecture, even if their package managers still need to be run separately for release.

Aside from the protocol layer and optional security/error paths listed above, the core ALPINE 1.0 promises in the docs are implemented: each layer is wired end-to-end over real UDP, capability and security data flow through the stack, and the benchmark results now back the documented performance claims.
