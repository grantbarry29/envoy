#include "source/extensions/filters/udp/udp_proxy/dtls_proxy/dtls_proxy_filter.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DtlsProxyFilter {

    Network::FilterStatus DtlsProxyFilter::onData(Network::UdpRecvData& client_request) {
        ENVOY_LOG(trace, "dtls inspector: recv: {}");

        ENVOY_LOG(debug, "got dtls session: downstream={} local={}", client_request.addresses_.peer_->asStringView(), client_request.addresses_.local_->asStringView());

        /* 
        // Because we're doing a MSG_PEEK, data we've seen before gets returned every time, so
        // skip over what we've already processed.
        if (static_cast<uint64_t>(raw_slice.len_) > read_) {
            const uint8_t* data = static_cast<const uint8_t*>(raw_slice.mem_) + read_;
            const size_t len = raw_slice.len_ - read_;
            const uint64_t bytes_already_processed = read_;
            read_ = raw_slice.len_;
            ParseState parse_state = parseClientHello(data, len, bytes_already_processed);
            switch (parse_state) {
            case ParseState::Error:
            cb_->socket().ioHandle().close();
            return Network::FilterStatus::StopIteration;
            case ParseState::Done:
            // Finish the inspect.
            return Network::FilterStatus::Continue;
            case ParseState::Continue:
            // Do nothing but wait for the next event.
            return Network::FilterStatus::StopIteration;
            }
            IS_ENVOY_BUG("unexpected tcp filter parse_state");
        }*/
        return Network::FilterStatus::StopIteration;
    }

    Network::FilterStatus DtlsProxyFilter::onReceiveError(Api::IoError::IoErrorCode error_code) {
        config_->stats().downstream_sess_rx_errors_.inc();
        UNREFERENCED_PARAMETER(error_code);
        return Network::FilterStatus::StopIteration;
    }

} // namespace DtlsProxyFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
