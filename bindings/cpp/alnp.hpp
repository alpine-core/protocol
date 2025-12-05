#ifndef ALNP_CPP_HPP
#define ALNP_CPP_HPP

#include <cstddef>
#include <cstdint>

#ifndef ALPINE_EMBEDDED
#include <vector>
#endif

#include "alnp.h"

namespace alnp {

/// Simple span-like view into a byte buffer.
struct ByteSpan {
  const uint8_t* data = nullptr;
  std::size_t size = 0;
};

/// EncodedBuffer wraps either a caller-owned buffer (embedded) or a heap-backed
/// `std::vector` (desktop) while exposing the same descriptor.
#if defined(ALPINE_EMBEDDED)
class EncodedBuffer {
 public:
  EncodedBuffer(uint8_t* buffer, std::size_t capacity)
      : data_(buffer), capacity_(capacity), written_(0) {}

  uint8_t* data() { return data_; }
  std::size_t capacity() const { return capacity_; }
  uint32_t size() const { return written_; }

  alnp_bytes_t descriptor() const {
    return alnp_bytes_t{data_, static_cast<uint32_t>(capacity_)};
  }

  void setSize(uint32_t len) {
    if (len <= capacity_) {
      written_ = len;
    }
  }

 private:
  uint8_t* data_;
  std::size_t capacity_;
  uint32_t written_;
};
#else
class EncodedBuffer {
 public:
  explicit EncodedBuffer(std::size_t capacity = 2048)
      : buffer_(capacity), written_(0) {}

  uint8_t* data() { return buffer_.data(); }
  std::size_t capacity() const { return buffer_.size(); }
  uint32_t size() const { return written_; }

  alnp_bytes_t descriptor() const {
    return alnp_bytes_t{buffer_.data(),
                        static_cast<uint32_t>(buffer_.size())};
  }

  void setSize(uint32_t len) {
    if (len > buffer_.size()) {
      buffer_.resize(len);
    }
    written_ = len;
  }

 private:
  std::vector<uint8_t> buffer_;
  uint32_t written_;
};
#endif

/// DiscoveryRequest mirrors the C helper struct but keeps ownership with the
/// caller in embedded scenarios.
struct DiscoveryRequest {
  const uint8_t* client_nonce = nullptr;
  uint32_t client_nonce_len = 0;
  const char* const* requested = nullptr;
  uint32_t requested_len = 0;
};

/// SignedReply carries the CBOR message + signature produced by the library.
struct SignedReply {
  const uint8_t* payload = nullptr;
  uint32_t payload_len = 0;
  const uint8_t* signature = nullptr;
  uint32_t signature_len = 0;
};

#if !defined(ALPINE_EMBEDDED)
inline ByteSpan make_span(const alnp_bytes_t& bytes) {
  return ByteSpan{bytes.data, bytes.len};
}
#endif

inline int buildDiscoveryRequest(const DiscoveryRequest& request,
                                 EncodedBuffer& out) {
  alnp_discovery_request_t c_req;
  c_req.client_nonce.data = request.client_nonce;
  c_req.client_nonce.len = request.client_nonce_len;
  c_req.requested =
      request.requested && request.requested_len > 0
          ? const_cast<const char**>(request.requested)
          : nullptr;
  c_req.requested_len = request.requested_len;

  auto descriptor = out.descriptor();
  const int rc = alnp_build_discovery_request(&c_req, &descriptor);
  if (rc == 0) {
    out.setSize(descriptor.len);
  }
  return rc;
}

inline int verifyDiscoveryReply(const SignedReply& reply,
                                const ByteSpan& expected_nonce,
                                const ByteSpan& verifying_key) {
  alnp_signed_reply_t c_reply;
  c_reply.payload.data = reply.payload;
  c_reply.payload.len = reply.payload_len;
  c_reply.signature.data = reply.signature;
  c_reply.signature.len = reply.signature_len;

  return alnp_verify_discovery_reply(
      &c_reply, expected_nonce.data,
      static_cast<uint32_t>(expected_nonce.size), verifying_key.data,
      static_cast<uint32_t>(verifying_key.size));
}

inline int encodeControl(const ByteSpan& session_id, const ByteSpan& payload,
                         uint64_t seq, EncodedBuffer& out) {
  auto buf = out.descriptor();
  const int rc = alnp_encode_control(session_id.data, payload.data,
                                      static_cast<uint32_t>(payload.size), seq,
                                      &buf);
  if (rc == 0) {
    out.setSize(buf.len);
  }
  return rc;
}

inline int encodeStreamFrame(const ByteSpan& session_id,
                             const alnp_frame_t& frame, EncodedBuffer& out) {
  auto buf = out.descriptor();
  const int rc =
      alnp_encode_stream_frame(session_id.data, &frame, &buf);
  if (rc == 0) {
    out.setSize(buf.len);
  }
  return rc;
}

}  // namespace alnp

#endif  // ALNP_CPP_HPP
