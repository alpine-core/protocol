# ALPINE Handshake

The ALPINE handshake establishes:
- mutual authentication
- shared session keys
- session identifiers
- capability negotiation

## Flow

1) Controller → device: `session_init`
    - X25519 ephemeral pubkey
    - controller nonce

2) Device → controller: `session_ack`
    - device X25519 pubkey
    - device identity block
    - Ed25519 signature
    - server nonce

3) Controller verifies signature and identity

4) Both derive shared secret using X25519

5) Controller → device: `session_ready`
    - encrypted readiness message

6) Device → controller: `session_complete`

Session is now active.
