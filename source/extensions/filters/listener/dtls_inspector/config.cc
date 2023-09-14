#include <string>

#include "dtls_inspector.h"
#include "envoy/extensions/filters/listener/dtls_inspector/v3/dtls_inspector.pb.h"
#include "envoy/extensions/filters/listener/dtls_inspector/v3/dtls_inspector.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/listener/dtls_inspector/dtls_inspector.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DtlsInspector {

/**
 * Config registration for the DTLS inspector filter. @see NamedNetworkFilterConfigFactory.
 */
class DtlsInspectorConfigFactory : public Server::Configuration::NamedUdpListenerFilterConfigFactory {
public:
  // NamedUdpListenerFilterConfigFactory
  Network::UdpListenerFilterFactoryCb createFilterFactoryFromProto(
      const Protobuf::Message& message,
      Server::Configuration::ListenerFactoryContext& context) override {

    // downcast it to the DTLS inspector config
    const auto& proto_config = MessageUtil::downcastAndValidate<
        const envoy::extensions::filters::listener::dtls_inspector::v3::DtlsInspector&>(
        message, context.messageValidationVisitor());

    auto shared_config= std::make_shared<Config>(context.scope(), proto_config);
    return [shared_config](Network::UdpListenerFilterManager& filter_manager,
                           Network::UdpReadFilterCallbacks& callbacks) -> void {
      filter_manager.addReadFilter(std::make_unique<DtlsFilter>(callbacks, shared_config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<
        envoy::extensions::filters::listener::dtls_inspector::v3::DtlsInspector>();
  }

  std::string name() const override { return "envoy.filters.listener.dtls_inspector"; }
};

/**
 * Static registration for the TLS inspector filter. @see RegisterFactory.
 */
REGISTER_FACTORY(DtlsInspectorConfigFactory,
                 Server::Configuration::NamedUdpListenerFilterConfigFactory){
    "envoy.listener.dtls_inspector"};

} // namespace DtlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
