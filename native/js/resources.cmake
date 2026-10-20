# Explicit compile-time source allowlist. No runtime filesystem imports.
set(DMASH_PROTOCOL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../D-MASH PWA/not_messenger/js")
set(DMASH_PROTOCOL_MODULES
 vendor/nacl-fast.min.js vendor/blake3.min.js secure_session.js node_identity.js
 node_relationships_v4.js node_admission_v4.js node_registration_v4.js resource_pow.js
 node_socket_v4.js node_channel_v4.js probe_primitives_v4.js route_discovery_v4.js
 recipient_payload_v4.js node_routing_v4.js node_inbox_v4.js node_local_delivery_v4.js
 node_local_ownership_v4.js)
set(DMASH_PROTOCOL_FILES)
set(DMASH_MANIFEST "{\n  \"files\": [")
set(DMASH_SEPARATOR "")
foreach(module IN LISTS DMASH_PROTOCOL_MODULES)
 set(path "${DMASH_PROTOCOL_ROOT}/${module}")
 list(APPEND DMASH_PROTOCOL_FILES "${path}")
 file(SHA256 "${path}" digest)
 string(APPEND DMASH_MANIFEST "${DMASH_SEPARATOR}\n    {\"name\":\"${module}\",\"sha256\":\"${digest}\"}")
 set(DMASH_SEPARATOR ",")
endforeach()
string(APPEND DMASH_MANIFEST "\n  ]\n}\n")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/native-source-manifest.json" "${DMASH_MANIFEST}")
qt_add_resources(dmash_native_actor dmash_protocol PREFIX "/dmash/js" BASE "${DMASH_PROTOCOL_ROOT}" FILES ${DMASH_PROTOCOL_FILES})
qt_add_resources(dmash_native_actor dmash_platform PREFIX "/dmash/native" BASE "${CMAKE_CURRENT_SOURCE_DIR}/js" FILES "${CMAKE_CURRENT_SOURCE_DIR}/js/nacl_native.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/platform.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/runtime_entry.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/job_runtime.js")
