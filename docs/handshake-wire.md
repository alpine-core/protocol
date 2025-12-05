# ALPINE Handshake Wire Specification (Controller → Y1)

Audience: Y1 firmware developers implementing ALPINE packet classification and SessionInit → SessionAck handling.

## Transport contract
- Transport: UDP
- Framing: none; one CBOR item per UDP packet
- No preamble or magic bytes
- Payload is raw CBOR; the **first byte of the UDP payload is always a CBOR major-type byte**
- No length prefix; the UDP datagram boundary is the message boundary

## Top-level CBOR shape (SessionInit)
The controller sends a single CBOR **map** with **string keys** for SessionInit. All fields are required.

```
{
  "type": "session_init",
  "controller_nonce": <byte string, 32 bytes>,
  "controller_pubkey": <byte string, 32 bytes>,
  "requested": { ...CapabilitySet... },
  "session_id": "<UUID string, hyphenated, 36 chars>"
}
```

Notes:
- Keys are text strings (no integer keys).
- Values use CBOR major types as specified below.
- There is **no `client_nonce` field** inside SessionInit.
- No protocol version field is carried in SessionInit.

## Field-by-field specification (SessionInit)

| Field name           | CBOR type    | Length/format                | Description                                                                    |
|----------------------|--------------|------------------------------|--------------------------------------------------------------------------------|
| `type`               | text string  | exact value `"session_init"` | Message classifier; required for routing.                                      |
| `controller_nonce`   | byte string  | 32 bytes                     | Random controller nonce; opaque to Y1; **CBOR byte string**, not an int array. |
| `controller_pubkey`  | byte string  | 32 bytes                     | Controller X25519 public key for key agreement; **CBOR byte string**.          |
| `requested`          | map          | see CapabilitySet below      | Requested capabilities; same shape as discovery replies.                       |
| `session_id`         | text string  | 36-character hyphenated UUID | Session identifier; must be echoed verbatim in SessionAck.                     |

### CapabilitySet shape (value of `requested`)
```
{
  "channel_formats": [ "u8" | "u16", ... ],
  "max_channels": <unsigned int>,
  "grouping_supported": <bool>,
  "streaming_supported": <bool>,
  "encryption_supported": <bool>,
  "vendor_extensions": <map or null>
}
```
- `channel_formats` elements are text strings `"u8"` or `"u16"`.
- `vendor_extensions` may be omitted or `null`; if present, it is a CBOR map.

## Classification rules (all ALPINE UDP packets)
- Decode CBOR first; do **not** classify by port, socket, or discovery state.
- The presence and value of the top-level `"type"` text field determines the message kind.
- Unknown or missing `"type"` ⇒ treat as `unknown`.

Classifier outline:
```
msg = cbor_decode(packet)
if not is_map(msg): return UNKNOWN
if "type" not in msg: return UNKNOWN
switch (msg["type"]):
  case "alpine_discover":       -> DiscoveryRequest
  case "alpine_discover_reply": -> DiscoveryReply
  case "session_init":          -> SessionInit
  case "session_ack":           -> SessionAck
  case "session_ready":         -> SessionReady
  case "session_complete":      -> SessionComplete
  case "keepalive":             -> Keepalive
  case "alpine_control":        -> Control envelope
  case "alpine_control_ack":    -> Control ack
  default:                      -> UNKNOWN
```

## Discovery vs Handshake separation
- Discovery (`type = "alpine_discover"`) includes `client_nonce` (byte string, 32 bytes) and is stateless.
- Handshake start (`type = "session_init"`) **does not** include `client_nonce`.
- Once a SessionInit is accepted, discovery packets may be ignored or dropped; they must not abort an in-progress handshake.

## Controller expectations after SessionInit
When Y1 receives a valid SessionInit:
- Respond with `SessionAck` on the **same UDP socket/tuple** (same remote address/port).
- SessionAck must include:
  - `type`: `"session_ack"` (text string)
  - `device_nonce`: byte string, 32 bytes
  - `device_pubkey`: byte string, 32 bytes (X25519 public key)
  - `device_identity`: map with `device_id`, `manufacturer_id`, `model_id`, `hardware_rev`, `firmware_rev` (all text strings)
  - `capabilities`: CapabilitySet map (same shape as above)
  - `signature`: byte string (signature over controller nonce, per ALPINE spec)
  - `session_id`: text string, same value received in SessionInit
- No encryption is applied yet; both SessionInit and SessionAck are plaintext CBOR over UDP.

## Annotated real-world SessionInit (decoded)
Example (values illustrative but structure exact):
```
type:              "session_init"
controller_nonce:  h'652EA031F9A8434EE49D9F10A22C5CBC9BE2B7088FB35EC239A2933024C82B28'  ; 32-byte bstr
controller_pubkey: h'8E4A0F4F6C5A9D0C3E1F...'(32 bytes)                                 ; 32-byte bstr (X25519)
requested:
  channel_formats: [ "u8" ]
  max_channels: 512
  grouping_supported: false
  streaming_supported: true
  encryption_supported: true
  vendor_extensions: null
session_id:        "d81775fb-374c-4ba7-8b7c-dd1df0304336"                                ; text string UUID
```

Why misclassification happens:
- If the decoder expects `client_nonce` in SessionInit, classification will fail; that field exists **only in discovery**.
- If the decoder expects integer map keys, it will fail; all keys are text strings.
- If the decoder assumes a binary UUID, it must instead accept a text UUID string exactly as sent.
