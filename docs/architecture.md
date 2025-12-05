# ALPINE Architecture Overview

ALPINE is built around four clean layers:
```
+-------------------------------+
| Application (Controllers) |
+-------------------------------+
| Control Plane (reliable) |
+-------------------------------+
| Streaming Layer (realtime) |
+-------------------------------+
| Handshake / Discovery |
+-------------------------------+
| Transport (UDP/QUIC) |
+-------------------------------+
```

The architecture separates:
- cryptographic identity
- control operations
- real-time streaming
- discovery  
  so that devices and controllers remain interoperable and highly portable.

This document details how the layers interact and the constraints between them.
