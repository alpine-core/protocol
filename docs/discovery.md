# ALPINE Discovery Layer

Discovery allows controllers to find endpoints on a LAN without:
- knowing the device IP
- relying on mDNS
- relying on multicast
- scanning the subnet

Discovery uses:
- UDP IPv4 broadcast (mandatory for requests)
- Optional multicast (never required)

## 1. Request Message

`alpine_discover` is sent as a CBOR map with:

- version
- client_nonce (32 bytes)
- requested info categories

## 2. Reply Message

Devices respond with:

- identity block
- network block (IPv4, MAC)
- capabilities block
- server_nonce
- Ed25519 signature
- device identity attestation (optional CBOR blob)
- device identity trusted flag (bool; false if attestation missing/unverified)

## 3. Controller Requirements

Controller MUST:
- send discovery via broadcast to the well-known port
- verify signature
- verify nonce
- verify device identity attestation before marking identities trusted
- extract and trust IPv4
- attach device to NIC that received the reply

## 4. Device Requirements

Device MUST:
- generate or load permanent Ed25519 keypair
- sign discovery reply
- respond **unicast** to sender IP/port

Invariant:
- Discovery packets MUST arrive as raw UDP on port 19455. If raw UDP is not observed, discovery is broken at the transport/interface layer.

## 5. Device identity attestation (CBOR shape)

The optional `device_identity_attestation` field is a CBOR-encoded map with **string keys**.
It is encoded as a **byte string** inside the discovery reply.

Envelope:
```
{
  "v": 1,
  "payload": <bytes>,   // CBOR of the payload map below
  "sig": <bytes>,       // Ed25519 signature over payload bytes
  "alg": "Ed25519",
  "signer_kid": "<string>",   // must match an attester kid in the bundle
  "expires_at": <uint> // optional
}
```

Payload:
```
{
  "device_id": "<string>",
  "mfg": "<string>",
  "model": "<string>",
  "hw_rev": "<string>",
  "pub_ed25519": <bytes>,  // device identity pubkey, must match discovery field
  "issued_at": <uint>,
  "expires_at": <uint>     // optional
}
```

Notes:
- `device_id` must match the discovery reply `device_id` **exactly** (same encoding).
- `signer_kid` must be a **string**, not bytes.
