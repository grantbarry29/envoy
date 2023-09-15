#include "source/extensions/filters/udp/udp_proxy/config.h"
#include "source/extensions/filters/udp/udp_proxy/dtls_proxy/config.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DtlsProxyFilter {

static Registry::RegisterFactory<DtlsProxyFilterConfigFactory,
                                 Server::Configuration::NamedUdpListenerFilterConfigFactory>
    register_;

} // namespace DtlsProxyFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
