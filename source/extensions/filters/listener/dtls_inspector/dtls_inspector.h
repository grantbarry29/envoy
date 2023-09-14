#pragma once

#include "envoy/event/file_event.h"
#include "envoy/event/timer.h"
#include "envoy/extensions/filters/listener/dtls_inspector/v3/dtls_inspector.pb.h"
#include "envoy/network/filter.h"
#include "envoy/stats/histogram.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DtlsInspector {

/**
 * All stats for the TLS inspector. @see stats_macros.h
 */
#define ALL_DTLS_INSPECTOR_STATS(COUNTER, HISTOGRAM)                                                \
  COUNTER(client_hello_too_large)                                                                  \
  COUNTER(tls_found)                                                                               \
  COUNTER(tls_not_found)                                                                           \
  COUNTER(alpn_found)                                                                              \
  COUNTER(alpn_not_found)                                                                          \
  COUNTER(sni_found)                                                                               \
  COUNTER(sni_not_found)                                                                           \
  COUNTER(downstream_rx_errors)                                                                    \
  HISTOGRAM(bytes_processed, Bytes)

/**
 * Definition of all stats for the TLS inspector. @see stats_macros.h
 */
struct DtlsInspectorStats {
  ALL_DTLS_INSPECTOR_STATS(GENERATE_COUNTER_STRUCT, GENERATE_HISTOGRAM_STRUCT)
};

enum class ParseState {
  // Parse result is out. It could be tls or not.
  Done,
  // Parser expects more data.
  Continue,
  // Parser reports unrecoverable error.
  Error
};
/**
 * Global configuration for DTLS inspector.
 */
class Config {
public:
  Config(Stats::Scope& scope,
         const envoy::extensions::filters::listener::dtls_inspector::v3::DtlsInspector& proto_config,
         uint32_t max_client_hello_size = TLS_MAX_CLIENT_HELLO);

  const DtlsInspectorStats& stats() const { return stats_; }
  bssl::UniquePtr<SSL> newSsl();
  bool enableJA3Fingerprinting() const { return enable_ja3_fingerprinting_; }
  uint32_t maxClientHelloSize() const { return max_client_hello_size_; }
  uint32_t initialReadBufferSize() const { return initial_read_buffer_size_; }

  static constexpr size_t TLS_MAX_CLIENT_HELLO = 64 * 1024;

private:
  DtlsInspectorStats stats_;
  bssl::UniquePtr<SSL_CTX> ssl_ctx_;
  const bool enable_ja3_fingerprinting_;
  const uint32_t max_client_hello_size_;
  const uint32_t initial_read_buffer_size_;
};

using DtlsConfigSharedPtr = std::shared_ptr<Config>;

/**
 * DTLS inspector listener filter.
 */
class DtlsFilter : public Network::UdpListenerReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  DtlsFilter(Network::UdpReadFilterCallbacks& callbacks,
    const DtlsConfigSharedPtr& config);
//  DtlsFilter(const DtlsConfigSharedPtr& config);

  // Network::UdpListenerReadFilter callbacks
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb);
  Network::FilterStatus onData(Network::UdpRecvData& client_request) override;
  Network::FilterStatus onReceiveError(Api::IoError::IoErrorCode error_code) override;

private:
  ParseState parseClientHello(const void* data, size_t len, uint64_t bytes_already_processed);
  //ParseState onRead();
  //void onALPN(const unsigned char* data, unsigned int len);
  void onServername(absl::string_view name);
  //void createJA3Hash(const SSL_CLIENT_HELLO* ssl_client_hello);
  uint32_t maxConfigReadBytes() const { return config_->maxClientHelloSize(); }

  DtlsConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{};

  Network::UdpListener& listener_;
  bssl::UniquePtr<SSL> ssl_;
  uint64_t read_{0};
  //bool alpn_found_{false};
  bool clienthello_success_{false};
  // We dynamically adjust the number of bytes requested by the filter up to the
  // maxConfigReadBytes.
  uint32_t requested_read_bytes_;

  // Allows callbacks on the SSL_CTX to set fields in this class.
  friend class Config;
};

} // namespace DtlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
