# TypeScript Protocol Bindings

This package (`@alpine-core/protocol`) ships the **ALPINE protocol bindings** for TypeScript and JavaScript runtimes. It exposes:

- Message enums and structures (discovery, handshake, control, streaming)
- CBOR payload builders/parsers that match the Rust wire format
- Type-safe helpers for `StreamProfile`, `ControlOp`, and `CapabilitySet`

It does **not** run sockets, building state machines, or maintain a control channel. Rust remains the canonical protocol runtime with full session management and control helpers. Use these bindings only when you need the raw message types or to encode/decode CBOR from other environments.
