#ifndef ALPINE_SDK_HPP
#define ALPINE_SDK_HPP

#include <array>
#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "../alnp.hpp"

namespace alnp {
namespace sdk {

/// Intents used by stream profiles; marshaled into config IDs.
enum class StreamIntent : uint8_t { Auto = 0, Realtime = 1, Install = 2 };

/// Deterministic representation of a validated stream profile.
struct CompiledStreamProfile {
  StreamIntent intent;
  uint8_t latency_weight;
  uint8_t resilience_weight;
  std::string config_id;
};

/// Declarative intent for stream behavior selection.
class StreamProfile {
 public:
  static StreamProfile Auto() { return {StreamIntent::Auto, 50, 50}; }
  static StreamProfile Realtime() { return {StreamIntent::Realtime, 80, 20}; }
  static StreamProfile Install() { return {StreamIntent::Install, 25, 75}; }

  StreamProfile& with_weights(uint8_t latency, uint8_t resilience) & {
    latency_weight = latency;
    resilience_weight = resilience;
    return *this;
  }

  CompiledStreamProfile compile() const {
    if (latency_weight > 100) {
      throw std::invalid_argument("latency weight must be <= 100");
    }
    if (resilience_weight > 100) {
      throw std::invalid_argument("resilience weight must be <= 100");
    }
    if (latency_weight == 0 && resilience_weight == 0) {
      throw std::invalid_argument("latency and resilience weights cannot both be zero");
    }
    std::string config_id = std::to_string(latency_weight) + ":" +
                            std::to_string(resilience_weight) + ":" +
                            std::to_string(static_cast<int>(intent));
    return CompiledStreamProfile{intent, latency_weight, resilience_weight,
                                 std::move(config_id)};
  }

 private:
  StreamIntent intent;
  uint8_t latency_weight;
  uint8_t resilience_weight;
};

/// Abstract transport used by the high-level SDK helpers.
class AlpineTransport {
 public:
  virtual ~AlpineTransport() = default;
  virtual void send(const std::vector<uint8_t>& payload) = 0;
  virtual std::vector<uint8_t> receive(std::size_t max_size) = 0;
};

/// Simple frame descriptor so clients can build streaming data.
struct FrameRequest {
  ChannelFormat format = ChannelFormat::U8;
  std::vector<uint16_t> channels;
  uint8_t priority = 0;
  std::vector<std::string> groups;
};

/// SDK layer that wraps the low-level protocol helpers with more ergonomic helpers.
class AlpineClient {
 public:
  explicit AlpineClient(AlpineTransport& transport);

  bool sendDiscovery(
      const std::vector<std::string>& requested,
      const std::array<uint8_t, 32>& nonce);

  std::vector<uint8_t> receiveDiscovery(std::size_t max_size = 2048);

  std::vector<uint8_t> buildFrame(const FrameRequest& request);

  std::vector<uint8_t> buildControl(
      const std::string& session_id,
      uint64_t seq,
      ControlOp op,
      const std::vector<uint8_t>& payload,
      const std::vector<uint8_t>& mac);

  void keepalive(const std::array<uint8_t, 16>& session_id, uint64_t tick_ms);

  /// Starts streaming using the selected profile; returns the runtime config ID.
  ///
  /// Streaming cannot be restarted with a different profile afterward.
  std::string start_stream(const StreamProfile& profile);

 private:
  AlpineTransport& transport_;
  bool streaming_active_ = false;
  std::string config_id_;

  template <typename EncodeFn>
  std::vector<uint8_t> encode(EncodeFn encode);
};

inline AlpineClient::AlpineClient(AlpineTransport& transport)
    : transport_(transport) {}

inline bool AlpineClient::sendDiscovery(
    const std::vector<std::string>& requested,
    const std::array<uint8_t, 32>& nonce) {
  EncodedBuffer buffer(1024);
  alnp_discovery_request_t req;
  req.client_nonce.data = nonce.data();
  req.client_nonce.len = static_cast<uint32_t>(nonce.size());
  std::vector<const char*> requested_ptrs;
  requested_ptrs.reserve(requested.size());
  for (const auto& entry : requested) {
    requested_ptrs.push_back(entry.c_str());
  }
  req.requested = requested_ptrs.empty() ? nullptr : requested_ptrs.data();
  req.requested_len = static_cast<uint32_t>(requested_ptrs.size());

  auto descriptor = buffer.descriptor();
  const int rc = alnp_build_discovery_request(&req, &descriptor);
  if (rc != 0) {
    return false;
  }
  buffer.setSize(descriptor.len);
  transport_.send(
      std::vector<uint8_t>(buffer.data(), buffer.data() + buffer.size()));
  return true;
}

inline std::vector<uint8_t> AlpineClient::receiveDiscovery(std::size_t max_size) {
  return transport_.receive(max_size);
}

inline std::vector<uint8_t> AlpineClient::buildFrame(const FrameRequest& request) {
  return encode([&](alnp_bytes_t& descriptor, EncodedBuffer& buffer) -> int {
    alnp_frame_t frame;
    frame.channels = reinterpret_cast<const uint16_t*>(request.channels.data());
    frame.channels_len = static_cast<uint32_t>(request.channels.size());
    frame.format = request.format == ChannelFormat::U8 ? ALNP_CHANNEL_U8
                                                       : ALNP_CHANNEL_U16;
    frame.priority = request.priority;
    return alnp_encode_stream_frame(nullptr, &frame, &descriptor);
  });
}

inline std::vector<uint8_t> AlpineClient::buildControl(
    const std::string& session_id,
    uint64_t seq,
    ControlOp op,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& mac) {
  return encode([&](alnp_bytes_t& descriptor, EncodedBuffer& buffer) -> int {
    // This is a placeholder; embed seq/op/payload manually for demonstration.
    return alnp_encode_control(
        nullptr, payload.data(), static_cast<uint32_t>(payload.size()), seq,
        &descriptor);
  });
}

inline void AlpineClient::keepalive(const std::array<uint8_t, 16>& session_id, uint64_t tick_ms) {
  (void)session_id;
  (void)tick_ms;
  // Keepalive helpers can extend this method to push periodic frames via transport.
}

inline std::string AlpineClient::start_stream(const StreamProfile& profile) {
  if (streaming_active_) {
    throw std::runtime_error("stream profile already bound");
  }
  auto compiled = profile.compile();
  streaming_active_ = true;
  config_id_ = compiled.config_id;
  return config_id_;
}

template <typename EncodeFn>
std::vector<uint8_t> AlpineClient::encode(EncodeFn encode) {
  EncodedBuffer buffer(1024);
  auto descriptor = buffer.descriptor();
  encode(descriptor, buffer);
  buffer.setSize(descriptor.len);
  return std::vector<uint8_t>(buffer.data(), buffer.data() + buffer.size());
}

}  // namespace sdk
}  // namespace alnp

#endif  // ALPINE_SDK_HPP
