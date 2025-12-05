# ALPINE Device Capabilities

Each device declares a capability map during:

- discovery
- handshake
- get_caps

Capabilities define:

- supported channel formats (u8/u16)
- maximum channel count
- grouping support
- streaming support
- encryption support
- vendor extensions

Capabilities allow controllers to adapt without guessing device behavior.
