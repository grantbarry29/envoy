load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# DTLS inspector filter for examining various DTLS parameters before routing to a FilterChain.
# Public docs: TODO

envoy_extension_package()

envoy_cc_library(
    name = "dtls_inspector_lib",
    srcs = ["dtls_inspector.cc"],
    hdrs = ["dtls_inspector.h"],
    external_deps = ["ssl"],
    deps = [
        "//envoy/event:dispatcher_interface",
        "//envoy/event:timer_interface",
        "//envoy/network:filter_interface",
        "//envoy/network:listen_socket_interface",
        "//source/common/api:os_sys_calls_lib",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:assert_lib",
        "//source/common/common:hex_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/extensions/filters/listener/dtls_inspector/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//source/extensions/filters/listener/dtls_inspector:dtls_inspector_lib",
        "@envoy_api//envoy/extensions/filters/listener/dtls_inspector/v3:pkg_cc_proto",
    ],
)
