# Current Runtime Status

As of this release cycle, the ALPINE repository exposes:

| Layer | Runtime | Status |
| --- | --- | --- |
| Protocol | Rust (`alpine-protocol-rs`) | Canonical implementation; publishes to crates.io. |
| SDK | Rust (`alpine-protocol-sdk`) | Only maintained SDK runtime; covers discovery, handshake, control, streaming. |
| Bindings | TypeScript (`protocol/ts`) | Bindings-only package (`@alpine-core/protocol`); no runtime logic. |
| Bindings | Python (`protocol/python`) | Bindings-only package (`alnp`); no runtime logic. |
| SDK | TypeScript (`sdk/ts-archived`) | Archived runtime, kept for reference only. |
| SDK | Python (`sdk/python-archived`) | Archived runtime, kept for reference only. |

Control helpers (`ping`, `status`, `health`, `identity`, `metadata`) are implemented only in the Rust SDK. All other languages currently offer type-level or serialization helpers; they do not manage sockets, sessions, or the signed control envelope workflow.
