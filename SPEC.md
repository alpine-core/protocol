# ALPINE 1.0 Specification

This document defines the **wire protocol**, **message formats**, **cryptographic primitives**, **transport behavior**, and **state machines** for the Authenticated Lighting Protocol (ALPINE) v1.0.

ALPINE consists of four major subsystems:

1. **Discovery Layer**
2. **Handshake Layer**
3. **Control Plane**
4. **Streaming Transport**

All behaviour defined here is canonical. Language bindings and reference implementations must follow this spec exactly.

---

# 1. Terminology

- **Controller:** Any software generating control or streaming output.
- **Endpoint:** Any device speaking ALPINE (fixture, node, processor).
- **Session:** A mutually authenticated bidirectional channel between a controller and endpoint.
- **Envelope:** A structured CBOR message containing type, metadata, and payload.

---

# 2. Cryptographic Foundations

ALPINE uses:

- **Ed25519** signatures
- **X25519** for key exchange
- **ChaCha20-Poly1305** for encrypted control envelopes
- **HKDF-SHA256** for key derivation

Every device MUST embed:

- A long-term Ed25519 public key
- A stable device identifier
- Manufacturer + model identifiers

---

# 3. Message Encoding

All messages MUST be encoded using **CBOR (RFC 8949)**.

CBOR maps MUST use:
- deterministic key ordering
- shortest-encoding integer keys where possible
- UTF-8 strings

---

# 4. Discovery Layer

Defines two messages:

### 4.1 `alpine_discover`
Sent via UDP broadcast.

```json
{
"type": "alpine_discover",
"version": "1.0",
"client_nonce": <32 bytes>,
"requested": ["identity", "capabilities", "network"]
}
```


### 4.2 `alpine_discover_reply`
Signed by device.

```json
{
"type": "alpine_discover_reply",
"alpine_version": "1.0",

"device_id": <string>,
"manufacturer_id": <string>,
"model_id": <string>,
"hardware_rev": <string>,
"firmware_rev": <string>,
"mac": AA:BB:CC...
```

Controllers MUST verify:
- Ed25519 signature
- Nonce integrity
- Identity fields

---

# 5. Handshake Layer

States:
- `Init`
- `Handshake`
- `Authenticated`
- `Ready`
- `Streaming`

Flow:
1. Controller → device: `session_init`
2. Device → controller: `session_ack`
3. Verify signature
4. Derive session keys (HKDF)
5. Controller → device: `session_ready`
6. Device → controller: `session_complete`

Sessions MUST fail-closed on:
- nonce mismatch
- signature failure
- timeout
- replay violation

---

# 6. Control Plane

Envelopes:

```json

{
"type": "alpine_control",
"session_id": <uuid>,
"seq": <uint64>,
"op": "<operation>",
"payload": { ... },
"mac": <auth_tag>
}
```


Control operations include:
- get_info
- get_caps
- identify
- restart
- get_status
- set_config
- set_mode
- time_sync

Control envelopes MUST support:
- retransmit
- ack messages
- exponential backoff
- optional signatures

---

# 7. Streaming Transport (ALNP-Stream)

A modern frame transport replacing DMX limitations.

Frame envelope:

```json
{
"type": "alpine_frame",
"session_id": <uuid>,
"timestamp_us": <uint64>,
"priority": <0-255>,
"channel_format": "u8" | "u16",
"channels": [ ... ],
"groups": { ... },
"metadata": { ... }
}
```


Requirements:
- No fixed universe or 512-slot constraints
- Ordering MUST be preserved per-session
- No retransmission for frames
- Device may apply jitter strategies:
    - hold-last
    - drop
    - interpolate

---

# 8. Error Codes

Defined in `docs/errors.md`.

---

# 9. Security

See `docs/security.md`.

---

# 10. Interoperability

All fields must be stable and vendor-agnostic.  
Capabilities MUST describe optional or extended functionality.  

---

# 11. Embedded Protocol Guardrails

Embedded implementations MUST observe the following SHALL/MUST rules:

1. **Routing by CBOR only.** Every UDP datagram MUST be decoded until the top-level `"type"` text key is read. Branching on source port, socket, or inferred phase is **invalid**.
2. **SessionInit invariants.** `session_init` includes `controller_nonce`, `controller_pubkey`, `requested`, and `session_id`. It MUST NOT include `client_nonce`. Rejecting a SessionInit due to a missing `client_nonce` is non-compliant.
3. **Discovery suppression.** Once a node transitions into handshake, subsequent discovery packets MUST be ignored or dropped. They MUST NOT abort handshake or alter the finite-state machine.
4. **Byte-string fidelity.** Nonces, public keys, MACs, and signatures are CBOR byte strings. They MUST NOT be interpreted as integer arrays or UTF-8 sequences.
5. **Finite-state enforcement.** Firmware MUST embed the FSM defined in `docs/embedded-fsm.md`. Only the FSM may transition states, and impossible transitions (e.g., control before SessionInit) MUST be rejected centrally.
6. **Error visibility.** Any violation above MUST surface as a protocol error/event and MUST require an explicit reset before traffic is accepted again.
