# Python Protocol Bindings

`alnp` provides the Python bindings for ALPINE’s protocol layer. It mirrors the Rust types (`ControlEnvelope`, `FrameEnvelope`, `StreamProfile`, etc.) and exposes helpers to build/encode CBOR payloads so other tooling can speak ALPINE without running a full session.

This package is **bindings only**: it does not implement discovery, handshake, streaming, or the control channel. Rust is currently the only fully supported runtime for those experiences. Use `alnp` when you need the message shapes, serialization helpers, or for embedding ALPINE data into your own tooling.
