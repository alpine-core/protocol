# ALPINE Roadmap

Authenticated Lighting Protocol (for Intelligent Networks and Environments)

This roadmap tracks the protocol, bindings, and SDKs with a strict split
between protocol truth and developer experience.

---

## Phase 1: Core Protocol Foundations (v1.0, completed)

Status: Complete

Goal: Deliver a vendor-agnostic protocol baseline that works on Ethernet and
Wi-Fi without special configuration.

- Finalized v1 wire formats for discovery, handshake, control, and streaming.
- Defined deterministic session state machines and failure semantics.
- Documented packet loss, jitter handling, late-frame behavior, and recovery.
- Established cryptographic identity, signing, and verification primitives.

Outcome:
ALPINE v1 is stable, predictable, and suitable for real deployments.

---

## Phase 2: Stream Profiles and Selectable Behavior (v1.2, completed)

Status: Complete (v1.2.x, frozen)

Goal: Allow operators to select runtime behavior without unsafe tuning.

- Introduced stream profiles (Auto, Realtime, etc.) as immutable objects.
- Bound profile identity to sessions to prevent runtime mutation.
- Defined deterministic fallback rules when constraints conflict.
- Locked Phase 2 behavior with tests, documentation, and regressions.

Outcome:
Users can choose latency vs resilience trade-offs safely.

---

## Phase 3: Adaptive Streaming and Network Resilience (v1.3 or v2.x, in progress)

Status: In progress (no public release yet)

Goal: Keep visuals stable under real-world network conditions.

- Detect packet loss, jitter, late frames, and gaps in real time.
- Adjust keyframe cadence, deltas, and deadlines deterministically.
- Trigger forced recovery frames when required.
- Expose observability and metrics explaining why behavior changed.

Notes:
- Phase 3 started before the v2 architectural split.
- Final features may land as v1.3 or v2.x depending on SDK coupling.

Outcome (when released):
ALPINE degrades visual quality when needed, never temporal correctness.

---

## Phase 4: Architecture Split - Bindings vs SDK (v2.0, completed)

Status: Complete

Goal: Keep protocol truth and developer ergonomics separated long term.

Bindings (protocol surface):
- Rust (alpine-protocol-rs)
- TypeScript bindings
- Python bindings

Bindings contain only:
- Wire and message types
- Crypto primitives and codecs
- Stream profile validation helpers

SDKs (developer experience layer):
- sdk/rust is the only maintained SDK runtime.
- sdk/ts-archived and sdk/python-archived are reference only.
- Other SDK bindings are thin wrappers for their platforms.

Outcome:
Protocol stability and the Rust SDK evolve together while TS/Python remain
bindings-only.

---

## Phase 5: Tooling and CLI (v2.x)

Status: Planned

Goal: Provide authoritative tooling for developers and operators.

- Official ALPINE CLI (discover, inspect, handshake, validate, diagnostics).
- CLI built on SDKs with optional raw protocol access.
- Used for debugging, conformance testing, and field diagnostics.

Outcome:
ALPINE becomes inspectable and trustworthy, not a black box.

---

## Phase 6: Custom Profiles and Intent-Level Configuration (v2.x)

Status: Planned

Goal: Express preferences without low-level flags.

- Intent-level profile goals (latency, smoothness, resilience).
- Compile to validated stream profiles.
- Reject unsafe configurations before they hit the wire.
- Portable, shareable profiles across teams and venues.

Outcome:
Power users gain expressiveness without compromising determinism.

---

## Phase 7: Security and Trust Hardening (v2.x+)

Status: Planned

Goal: Strengthen trust without unnecessary complexity.

- Certificate-backed device identities.
- Replay protection across restarts.
- Optional encrypted payloads for high-security environments.
- Conservative defaults with explicit guarantees.

Outcome:
Security is native, understandable, and auditable.

---

## Phase 8: Ecosystem Growth and Compatibility (future)

Status: Planned

Goal: Enable safe, long-term ecosystem growth.

- Capability negotiation and vendor extension ranges.
- Strict backward compatibility guarantees.
- Clean upgrade paths for hardware and software.
- Optional bridges to legacy ecosystems (sACN/Art-Net).

Outcome:
ALPINE becomes a stable foundation others can build on.

---

## Near-term protocol additions (v2.x candidates)

- Standard stream metrics control op (queue, drops, latency).
- Stream kind registry with payload contracts and supported kinds.
- Explicit rate guard semantics (max Hz per stream).
- Delta encoding with anchor frames as a standard stream mode.
- Vendor extension registry to avoid magic op strings.

---

## Design commitment

Under packet loss, jitter, or delay, ALPINE degrades visual quality, never
temporal correctness. This governs the protocol, bindings, SDKs, and tooling.
