# ALPINE Discovery Layer

Discovery allows controllers to find endpoints on a LAN without:
- knowing the device IP
- relying on mDNS
- relying on multicast
- scanning the subnet

Discovery uses:
- UDP broadcast (mandatory)
- UDP multicast (optional)

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

## 3. Controller Requirements

Controller MUST:
- verify signature
- verify nonce
- extract and trust IPv4
- attach device to NIC that received the reply

## 4. Device Requirements

Device MUST:
- generate or load permanent Ed25519 keypair
- sign discovery reply
- respond unicast to sender IP/port
