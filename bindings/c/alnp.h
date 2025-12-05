#ifndef ALNP_H
#define ALNP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ALPINE 1.0 CBOR envelope helpers for C consumers.

typedef struct {
  const uint8_t* data;
  uint32_t len;
} alnp_bytes_t;

typedef struct {
  alnp_bytes_t client_nonce; // 32 bytes
  const char** requested;    // array of strings
  uint32_t requested_len;
} alnp_discovery_request_t;

typedef struct {
  alnp_bytes_t payload;
  alnp_bytes_t signature;
} alnp_signed_reply_t;

typedef enum {
  ALNP_CHANNEL_U8 = 0,
  ALNP_CHANNEL_U16 = 1
} alnp_channel_format_t;

typedef struct {
  const uint16_t* channels;
  uint32_t channels_len;
  alnp_channel_format_t format;
  uint8_t priority;
} alnp_frame_t;

// Build a CBOR-encoded discovery request buffer into the provided output.
int alnp_build_discovery_request(const alnp_discovery_request_t* req, alnp_bytes_t* out_buf);

// Verify a signed discovery reply; returns 0 on success.
int alnp_verify_discovery_reply(const alnp_signed_reply_t* reply, const uint8_t* expected_nonce, uint32_t nonce_len, const uint8_t* verifying_key, uint32_t key_len);

// Encode and send a control envelope (caller provides transport).
int alnp_encode_control(const uint8_t* session_id, const uint8_t* payload, uint32_t payload_len, uint64_t seq, alnp_bytes_t* out_buf);

// Encode a streaming frame for transmission.
int alnp_encode_stream_frame(const uint8_t* session_id, const alnp_frame_t* frame, alnp_bytes_t* out_buf);

#ifdef __cplusplus
}
#endif

#endif // ALNP_H
