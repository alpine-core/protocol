# ALPINE Roadmap

*Authenticated Lighting Protocol (for Intelligent Networks and Environments)*

This roadmap describes the evolution of the **ALPINE protocol**, its **bindings**, and its **official SDKs & tooling**, with a strict separation between protocol truth and developer experience layers.

---

## Phase 1 – Core Protocol Foundations (v1.0, completed)

**Status:** ✅ Complete

**Goal:** Deliver a rock-solid, vendor-agnostic protocol baseline that works on Ethernet and Wi-Fi without special configuration.

* Finalized v1 wire formats for discovery, handshake, control, and real-time streaming.
* Defined deterministic session state machines and failure semantics.
* Documented packet loss, jitter handling, late-frame behavior, and recovery guarantees.
* Established cryptographic identity, signing, and verification primitives.

**Outcome:**
ALPINE v1 is stable, predictable, and suitable for real deployments.

---

## Phase 2 – Stream Profiles & Selectable Behavior (v1.2, completed)

**Status:** ✅ Complete (v1.2.x, frozen)

**Goal:** Allow operators to select predictable runtime behavior without unsafe tuning.

* Introduced stream profiles (`Auto`, `Realtime`, etc.) as validated, immutable objects.
* Bound profile identity to sessions to prevent runtime mutation.
* Defined deterministic fallback rules when conflicting constraints are detected.
* Locked Phase 2 behavior with tests, documentation, and regression guarantees.

**Outcome:**
Users can choose latency vs resilience trade-offs safely. Phase 2 behavior is frozen.

---

## Phase 3 – Adaptive Streaming & Network Resilience (v1.3 / v2.x, in progress – not released)

**Status:** 🚧 In progress (no public release yet)

**Goal:** Keep ALPINE visually stable under real-world network conditions.

* Detect packet loss, jitter, late frames, and gaps in real time.
* Adjust keyframe cadence, deltas, and deadlines deterministically.
* Trigger forced recovery frames when required.
* Expose observability and metrics explaining *why* behavior changed.

**Notes:**

* Phase 3 development started before the v2 architectural split.
* No Phase 3 behavior is released or guaranteed yet.
* Final Phase 3 features may land either as v1.3 (bindings-only) or v2.x, depending on coupling with SDK ergonomics.

**Outcome (when released):**
ALPINE degrades visual quality when needed — **never temporal correctness**.

---

## Phase 4 – Architectural Split: Bindings vs SDK (v2.0, completed)

**Status:** ✅ Complete

**Goal:** Enforce a clean, long-term separation between protocol truth and developer ergonomics.

### Bindings (Protocol Surface)

Canonical, low-level protocol implementations:

* Rust (`alpine-protocol-rs`)
* TypeScript bindings
* Python bindings

Bindings contain **only**:

* wire and message types
* cryptographic primitives and codecs
* stream profile validation helpers

Bindings are fully usable **without** any SDK and are the only supported artifacts in TypeScript and Python at the moment.

### SDKs (Developer Experience Layer)

`sdk/` now hosts:

* `sdk/rust` — the **only** maintained SDK runtime that orchestrates discovery, session lifecycle, control, and streaming.
* `sdk/ts-archived` and `sdk/python-archived` remain only for reference; no active SDK releases exist for those languages in this phase.
* Other SDK bindings (C/C++) continue as thin wrappers for their respective platforms.

The `alpine-protocol-sdk` depends **only** on the public APIs of the bindings.

**Outcome:**

Protocol stability and the Rust SDK evolve together while TypeScript and Python remain bindings-only until we are ready to reintroduce full runtimes.

---

## Phase 5 – Tooling & CLI (v2.x)

**Status:** Planned

**Goal:** Provide authoritative tooling for developers, operators, and vendors.

* Introduce an official **ALPINE CLI**:

    * `alpine discover`
    * `alpine inspect`
    * `alpine handshake`
    * `alpine capabilities`
    * `alpine validate`
    * optional raw / diagnostic modes
* CLI built on top of SDKs (with optional raw protocol access).
* Used for:

    * debugging
    * protocol validation
    * conformance testing
    * internal dogfooding

**Outcome:**
ALPINE becomes inspectable, debuggable, and trustworthy — not a black box.

---

## Phase 6 – Custom Profiles & Intent-Level Configuration (v2.x)

**Status:** Planned

**Goal:** Let advanced users express preferences without touching low-level flags.

* Define intent-level profile goals (latency, smoothness, resilience).
* Compile validated preferences into concrete stream profiles.
* Reject unsafe or contradictory configurations *before* they hit the wire.
* Enable portable, shareable profiles across teams and venues.

**Outcome:**
Power users gain expressiveness without compromising determinism.

---

## Phase 7 – Security & Trust Hardening (v2.x+)

**Status:** Planned

**Goal:** Strengthen trust without gimmicks or unnecessary complexity.

* Certificate-backed device identities.
* Replay protection across restarts.
* Optional encrypted payloads for high-security environments.
* Conservative defaults with explicit guarantees.

**Outcome:**
Security is native, understandable, and auditable.

---

## Phase 8 – Ecosystem Growth & Compatibility (future)

**Status:** Planned

**Goal:** Enable safe, long-term ecosystem growth.

* Capability negotiation and vendor extension ranges.
* Strict backward compatibility guarantees.
* Clean upgrade paths for hardware and software.
* Optional bridges to legacy ecosystems (e.g. sACN / Art-Net).

**Outcome:**
ALPINE becomes a stable foundation others can confidently build on.

---

## Design Commitment

> **Under packet loss, jitter, or delay, ALPINE degrades visual quality — never temporal correctness.**

This principle governs the protocol, the bindings, the SDKs, and all tooling.
