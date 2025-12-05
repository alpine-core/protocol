# ALPINE Control Plane

The Control Plane provides reliable, secure, structured operations.

Operations are encoded as:

```json
{
type: "alpine_control",
session_id,
seq,
op,
payload,
mac
}
```


## Reliability

- Sequence numbers increment monotonically
- Retransmission permitted for control envelopes
- Ack messages must be sent when requested
- Exponential backoff is REQUIRED
- Control envelopes MUST be cryptographically authenticated

> Only the Rust SDK currently runs the complete control channel. TypeScript/Python packages only provide bindings/data shapes; they do not execute the control lifecycle or verify MACs.

## Acknowledge payloads

- Acknowledgements now optionally carry a CBOR `payload` field that contains structured reply data. Senders must MAC-cover `ok`, `detail`, and `payload`, and receivers should verify the MAC before parsing.
 - The SDK layer exposes typed helpers (`ping`, `status`, `health`, `identity`, `metadata`) that read from this payload to avoid JSON/UDP plumbing.

## Standard Operations

- get_info
- get_caps
- get_status
- identify
- set_config
- restart
- time_sync
- vendor namespace operations
