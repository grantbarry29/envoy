#pragma once

#include "envoy/extensions/filters/udp/udp_proxy/v3/udp_proxy.pb.h"
#include "envoy/extensions/filters/udp/udp_proxy/v3/udp_proxy.pb.validate.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DtlsProxyFilter {

/**
 * Config registration for the dTLS proxy filter. @see NamedUdpListenerFilterConfigFactory.
 */
class DtlsProxyFilterConfigFactory
    : public Server::Configuration::NamedUdpListenerFilterConfigFactory {
public:
  // NamedUdpListenerFilterConfigFactory
  Network::UdpListenerFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& config,
                               Server::Configuration::ListenerFactoryContext& context) override {
    auto shared_config = std::make_shared<Envoy::Extensions::UdpFilters::UdpProxy::UdpProxyFilterConfigImpl>(
        context, MessageUtil::downcastAndValidate<
                     const envoy::extensions::filters::udp::udp_proxy::v3::UdpProxyConfig&>(
                     config, context.messageValidationVisitor()));
    return [shared_config](Network::UdpListenerFilterManager& filter_manager,
                           Network::UdpReadFilterCallbacks& callbacks) -> void {
      filter_manager.addReadFilter(std::make_unique<Envoy::Extensions::UdpFilters::UdpProxy::UdpProxyFilter>(callbacks, shared_config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::udp::udp_proxy::v3::UdpProxyConfig>();
  }

  std::string name() const override { return "envoy.filters.udp_listener.dtls_proxy"; }
};

} // namespace DtlsProxyFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
