# Changelog

All notable changes to ALPINE will be documented in this file.

-## [Unreleased] - Phase 0 (Modular architecture split & release)
- Move `alpine-protocol-rs` under `protocol/rust/` and keep the crate focused on wire helpers, crypto primitives, and stream profiles. `AlpineClient` now lives entirely in `sdk/rust/alpine-protocol-sdk`.
- Introduce `protocol-publish.yml` and `sdk-publish.yml`, version the protocol artifacts for each release, and let every SDK release follow its own semantic version set (the Rust SDK is `0.1.7` for this cycle).
- Document the split in the README, roadmap, and release process so contributors understand the release boundaries (protocol layer for stability, SDKs for ergonomics).
- Align the tooling so the protocol layer publishes first and SDKs run afterwards against the freshly published artifacts while keeping Phase 2 guarantees frozen.

## [Unreleased] - Phase 3.1-3.2 (Detection + Recovery)
- Introduce deterministic `NetworkConditions` metrics (loss ratio, late frame rate, jitter) so every session can observe per-stream network health without adaptive behavior.
- Add regression tests proving those metrics stay deterministic when sequences miss, deadlines slip, or intervals vary.
- Ship a deterministic `RecoveryMonitor` that starts/completes recovery on sustained or burst loss, annotates retransmitted frames, and never rewinds or reorders the timeline.
- Introduce Phase 3.3.1's pure adaptation core (deterministic state + decision engine) scoped to keyframe cadence, delta depth, and deadlines without integrating yet.
- Begin Phase 3.3.2 by wiring the adaptation state into the streaming path: network + recovery update `AdaptationState`, and every frame carries `alpine_adaptation` metadata plus a keyframe flag.
- Add `alpine-embedded-core` (portable C99 FSM + CBOR classifier) so embedded firmware can copy the reference implementation instead of re-rolling transports.
- Publish embedded-focused docs: `docs/embedded-fsm.md`, `docs/embedded-wire.md`, and updated `SPEC.md` language that forbids routing by port and discovery/handshake mixing.
- Ship scaffolds for POSIX, ESP32, and STM32 showing how to wire the embedded core without parsing CBOR manually.
- Introduce `alpine conformance` CLI command that drives discovery, handshake, malformed payloads, and discovery-during-handshake tests with pass/fail output.

- ## [2.0.21] - 2025-12-03
- Finalize the Rust-only runtime: publish `alpine-protocol-rs 2.0.21` and `alpine-protocol-sdk 0.1.10`, making the control helpers (`ping`, `status`, `health`, `identity`, `metadata`) and `ack.payload` semantics available only in Rust.
- Bindings-only artifacts (`protocol/ts`, `protocol/python`) follow as supporting packages; archived TS/Python SDK runtimes remain for reference.
## [2.0.19] - 2025-12-01
- Extend `Acknowledge` with an optional CBOR `payload` that stays protected by the MAC and provide helpers for decoding typed replies.
- Add typed control helpers (`ping`, `status`, `health`, `identity`, `metadata`) to `AlpineClient` so Rust consumers can access structured responses without touching UDP/JSON.
- Ship the Rust SDK package (`sdk/rust` @ 0.1.8) and the protocol helpers (`2.0.19`) so every artifact depends on the freshly tagged control payload semantics.
- Archived the TypeScript and Python SDK runtimes (`sdk/ts`, `sdk/python`) so Rust is the only fully supported runtime; the other languages now only provide bindings/data shapes.

## [2.0.18] - 2025-11-30
- Bump the protocol artifacts (`alpine-protocol-rs`, `@alpine-core/protocol`, `alnp`) to `2.0.18` and document the SDK release workflow so they can be published reliably.
- Publish the SDK packages (`sdk/rust`, `sdk/ts`, `sdk/python`) at `0.1.7`, ensuring they depend on the freshly tagged protocol release and that the release docs reference the new tag-and-dependency versions.

## [1.2.4] - 2025-11-29
- Bump Rust, TypeScript, and Python package versions to `1.2.4` so the SDK release tags align with publishable artifacts.

## [1.2.3] - 2025-11-29
- Add `sdk::DiscoveryClient` so discovery is stateless, explicit, and surfaces identity/address/capabilities along with a signed flag.
- Clarify the README workflow (DiscoveryClient → AlpineClient::connect → start_stream → send_frame) and highlight the new pre-session guarantee.
- Improve `ClientError` diagnostics so discovery/handshake failures preserve their concrete causes.

## [1.2.2] - 2025-11-28
- Added regression tests covering profile validation failures, deterministic `config_id`, and the immutability guarantee once streaming begins.
- Hardened the embedded build script so it runs `build_c.sh` first and links against `libalpine-<version>.a`, enabling the `embedded` workflow to pass.

## [1.2.1] - 2025-11-28
- Introduce language-specific SDK layers (`sdk/rust`, `sdk/ts`, `sdk/python`, `sdk/cpp`) with ergonomic APIs (`connect`, `send_frame`, `control`, keepalive) that now select stream profiles.
- Add Stream Profiles (Auto/Realtime/Install) that compile into deterministic `config_id`s, validate weights, and cannot be changed once streaming starts; `start_stream` binds the profile.
- Added tests covering profile validation failures, config_id determinism, and immutability once streaming commences.
- Update docs/README to position those SDKs as the recommended application entry points while keeping the auto-generated protocol helpers stable for embedded use.
- Keep the existing release artifacts, embedded CI job, and documentation policy so every platform continues to ship consistent behavior guarantees.

## [1.0.10] - 2025-11-27
- Publish the Rust crate as `alpine-protocol-rs` so we can continue releasing from the `alpine-core` repo even though the old crate name was owned elsewhere.
- Update release scripts to copy the new `alpine-protocol-rs-*.crate` so the artifact matches the crates.io name while clients still include `alpine` in their namespaces.
- Keep shipping docs, the GHCR C package, and the embedded-friendly CI job so every release bundles docs + binaries with the constrained build checks.

## [1.0.9] - 2025-11-27
- Add the `embedded` build profile (`#define ALPINE_EMBEDDED`) so the C++ helper compiles with no exceptions, RTTI, or heap allocations.
- Validate that mode via `.github/workflows/embedded.yml` and `scripts/build_embedded_cpp.sh`, which runs with the ESP32-safe flag set for every push/PR.
- Document the embedded path in the README/docs so constrained targets get the same great API as desktop builds.

## [1.0.8] - 2025-11-27
- Provide the C++ helper header (`protocol/cpp/alnp.hpp`) so C++ projects can include ALPINE without touching the raw C structs.
- Deliver the new header along with `README.md`, `SPEC.md`, and `docs/` in each release asset so documentation and libs travel together.
- Keep the GHCR C package, TypeScript, Python, and Rust releases aligned under the `v1.0.8` tag.

## [1.0.7] - 2025-11-27
- Keep the crate name `alpine-core` for crates.io while exposing the library as `alpine` so existing tests and consumers can still import `alpine::...`.
- Restore `libalpine.a` as the C artifact while keeping the GHCR image packaging and docs bundle unchanged.
- Continue shipping docs + artifacts together so every release always includes README/SPEC/docs and the tarball on GHCR.

## [1.0.6] - 2025-11-27
- Rename the Rust crate to `alpine-core` and ship it as `alpine-core-1.0.6` so future updates belong to the alpine-core organization.
- Update the static library export to `libalpine-core-*.a` so the C protocol helpers still match the crate name.
- Keep docs, GHCR C package, and release notes flowing with the new tag.

## [1.0.5] - 2025-11-27
- Publish the C tarball as both a release asset and a GHCR package so it is easy to download and use.
- Bundle `README.md`, `SPEC.md`, and `docs/` into each release asset so the documentation always travels with every package.
- Keep TS, Python, and Rust manifests in sync with the `v1.0.5` tag so CI redeploys everything cleanly.

## [1.0.4] - 2025-11-27
- Target `crates-io` explicitly when publishing Rust so Cargo knows which registry to use.
- Refresh every binding manifest/tag to `1.0.4` so the next release has new artifacts.
- Confirm C/TS/Python jobs still upload via GitHub Packages with the new permissions.

## [1.0.2] - 2025-11-27
- Align TS/GitHub package workflows with the `@alpine-core` scope and add npmjs/public flags.
- Fix release artifacts to copy the actual crate/static lib names and expose Python wheels.
- Tag the repo `v1.0.2` so CI can publish all protocol artifacts again.

## [1.0.0] - 2025-11-23
- First public release of ALPINE v1.
- Deterministic session state machine and authenticated control plane over UDP.
- X25519 + Ed25519 security model with signed control envelopes.
- Reliable control channel (retransmit/backoff/replay protection).
- ALNP-Stream gating with jitter handling (hold-last, drop, lerp).
- TypeScript and C protocol scaffolds; Python package stub for clients.

[1.0.11]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.11
[1.0.10]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.10
[1.0.9]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.9
[1.0.8]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.8
[1.0.7]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.7
[1.0.6]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.6
[1.0.5]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.5
[1.0.4]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.4
[1.0.3]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.3
[1.0.2]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.2
[1.0.0]: https://github.com/alpine-core/Authenticated-Lighting-Protocol/releases/tag/v1.0.0
