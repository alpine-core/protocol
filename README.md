# ALPINE — Authenticated Lighting Network Protocol
![Rust](https://img.shields.io/badge/Rust-crates.io-000000?style=for-the-badge&logo=rust&logoColor=white) ![Python](https://img.shields.io/badge/Python-PyPI-3776AB?style=for-the-badge&logo=python&logoColor=white) ![C](https://img.shields.io/badge/C-GitHub%20Packages-181717?style=for-the-badge&logo=github&logoColor=white) ![License](https://img.shields.io/badge/License-Apache--2.0-blue?style=for-the-badge)

ALPINE is a **modern, secure, vendor-agnostic lighting control protocol** built for deterministic streaming, signed control envelopes, and constrained deployments. This directory is the protocol layer; SDKs, CLI, and the embedded runtime live beside it in the workspace.

| Layer | Purpose | Location |
| --- | --- | --- |
| **Protocol** | Low-level, stable CBOR helpers that map the wire format to Rust/TypeScript/C/Python/C++. Publish these independently so embedded or constrained builds can link without the SDK. | `protocol/` |
| **SDKs** | High-level, ergonomic clients that orchestrate discovery → connect → stream workflows and enforce stream profiles. These depend only on the published protocol public APIs. | `../sdk/` |
| **Embedded runtime** | Hook-based embedded runtime and adapters. | `../embedded-runtime/` |
| **CLI** | Operational tooling built on the SDK. | `../cli/` |

## What’s in this layer

- **Rust**: `rust/alpine-protocol-rs` is the protocol crate. It exports wire types, crypto helpers, stream profile validation, and stateless codecs. The crate is intentionally GUI, I/O, and runtime agnostic so futures and embedded platforms can reuse the primitives.
- **TypeScript**: `ts` compiles to `@alpine-core/protocol` and mirrors the Rust types (CBOR helpers, control envelopes, stream builders). Use it when you need the raw format on Node, Deno, or browser platforms that can’t run the SDK.
- **Python**: `python` exposes the same helpers via a minimal package (`alnp`). It stays free of sockets or async concerns so it can be imported inside constrained environments.
- **C/C++**: `c` and `cpp/alnp.hpp` provide the C API plus an embedded-friendly `ALPINE_EMBEDDED` guard. These headers/libraries are produced by `scripts/build_c.sh`.

## Discovery → Session workflow (recommended)

1. Create `sdk::DiscoveryClient`. It is **stateless, explicit, and observable**: you choose when to call `discover()`, you inspect every reply, and no sessions are created until you call `AlpineClient::connect`.
2. Call `DiscoveryClient::discover()` and inspect the returned `DiscoveredDevice` entries for identity, capability set, socket address, and whether replies were signed.
3. Choose a `StreamProfile` (Auto / Realtime / Install) and call `sdk::AlpineClient::connect`.
4. Once connected, call `start_stream(profile)` and send frames; the client enforces profile guarantees and keeps a single steady stream once it starts.

## Release & publishing

We treat this workspace as two independent release axes:

1. **Protocol release (`vX.Y.Z`)** — covers `protocol/*`, including the Rust crate, TypeScript protocol helpers, Python helpers, and C/C++ artifacts.
2. **SDK release (`sdk-vA.B.C`)** — publishes `sdk/rust` (and other SDKs in the future) on its own version schedule.

To keep releases boring:

- The **`protocol-publish`** workflow runs on every `v*` tag, builds the protocol layer, runs the tests, packages the artifacts, and publishes to crates.io/npm/PyPI/GitHub Packages. (It also validates the embedded C++ build via `scripts/build_embedded_cpp.sh`.)
- The **`sdk-publish`** workflow runs after `protocol-publish` succeeds. It builds the SDK crate, ensures it compiles against the freshly published protocol artifacts, and publishes the SDK with its own version.

Before tagging:

1. Run `cargo test --manifest-path rust/alpine-protocol-rs/Cargo.toml`.
2. Run `../scripts/build_c.sh`.
3. Run `../scripts/build_embedded_cpp.sh`.
4. Run `../scripts/build_ts.sh` and `../scripts/build_python.sh` for the new `protocol/` packages.
5. Run `cargo test --manifest-path ../sdk/rust/Cargo.toml`.

## Documentation & references

- [`roadmap.md`](roadmap.md)
- [`docs/release_process.md`](docs/release_process.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/documentation_policy.md`](docs/documentation_policy.md)
- [`docs/discovery.md`](docs/discovery.md)
- [`SPEC.md`](SPEC.md)
- [`docs/status.md`](docs/status.md)

## Continuous Integration

- `UDP E2E Tests` (`../.github/workflows/e2e-tests.yml`) validates the protocol’s UDP control/streaming paths.
- `embedded` (`../.github/workflows/embedded.yml`) validates the embedded C++ flags via `../scripts/build_embedded_cpp.sh`.
- `protocol-publish` and `sdk-publish` ensure release artifacts are reproducible.

## License

Apache-2.0
