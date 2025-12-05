# ALPINE Reference Implementation Guide

This document describes how we expose ALPINE 1.0 implementations:

- **Rust (canonical implementation)** — the only full protocol + SDK runtime.
- **TypeScript / Python** — bindings-only packages that expose message types, enums, and serialization helpers without running sessions or control channels.
- **C (static library)** and **C++ helper header** with `ALPINE_EMBEDDED`.
- **Stream Profiles in Rust** (profiles are the canonical behavior knobs).
- **Language-specific SDK helpers** currently exist only for Rust (`sdk/rust`). Other SDK directories are archived and not maintained.

A correct implementation MUST:

1. Implement CBOR encoding/decoding
2. Support UDP broadcast discovery
3. Implement handshake state machine
4. Maintain session state with expiry
5. Support control envelopes
6. Support streaming envelopes
7. Validate signatures and MAC tags
8. Handle capability negotiation
9. Follow error semantics exactly

Reference code structure is included for each language; C++ users can toggle
`ALPINE_EMBEDDED` to compile the same header without heap allocations or RTTI.
