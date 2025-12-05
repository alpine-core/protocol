#include "alnp.hpp"

constexpr uint8_t kNonce[32] = {0};
constexpr const char* kRequested[] = {"alnp", "stream"};

int main() {
  uint8_t scratch[512];
  alnp::EncodedBuffer buffer(scratch, sizeof(scratch));

  alnp::DiscoveryRequest request;
  request.client_nonce = kNonce;
  request.client_nonce_len = sizeof(kNonce);
  request.requested = kRequested;
  request.requested_len =
      static_cast<uint32_t>(sizeof(kRequested) / sizeof(kRequested[0]));

  return alnp::buildDiscoveryRequest(request, buffer);
}
