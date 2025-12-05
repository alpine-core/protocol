# ALPINE Streaming (ALP-Stream)

ALNP-Stream replaces DMX/sACN universes with modern frame envelopes.

## Frame Structure

```json
{
type: "alpine_frame",
session_id,
timestamp_us,
priority,
channel_format, // "u8" or "u16"
channels, // array of values
groups, // optional grouping
metadata // optional per-frame metadata
}
```


## Guarantees

- Frames are not retransmitted
- Delivery order is preserved per-session
- Supported jitter strategies:
    - hold-last
    - drop
    - lerp (interpolate)
- Encryption optional but supported

## Advantages

- No fixed universe limits
- Unlimited channels
- Engineered for AI-driven or dynamic lighting
- Frame metadata extensible
