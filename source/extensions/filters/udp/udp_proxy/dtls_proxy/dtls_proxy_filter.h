#pragma once

#include "source/extensions/filters/udp/udp_proxy/udp_proxy_filter.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DtlsProxyFilter {

class DtlsProxyFilter : public UdpProxy::UdpProxyFilter {
    Network::FilterStatus onData(Network::UdpRecvData& data) override;
    Network::FilterStatus onReceiveError(Api::IoError::IoErrorCode error_code) override;
    friend class UdpProxyFilter;
};

} // namespace DtlsProxyFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
