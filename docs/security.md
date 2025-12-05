# ALPINE Security Model

ALPINE relies on:

- Ed25519 long-term device identity keys
- X25519 ephemeral key exchange
- HKDF-SHA256 key derivation
- ChaCha20-Poly1305 envelope encryption
- Nonce-checked discovery replies
- Session-based replay windows
- Cryptographically authenticated control envelopes

Optional features:
- vendor-issued certificates
- local pairing modes
- encrypted frame streaming
