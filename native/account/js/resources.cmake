set(DMASH_ACCOUNT_PWA "${CMAKE_CURRENT_SOURCE_DIR}/../../D-MASH PWA/not_messenger/js")
set(DMASH_ACCOUNT_MODULES
 vendor/nacl-fast.min.js secure_session.js route_discovery_v4.js recipient_payload_v4.js
 account_pairing_v2.js account_route_binding_v2.js account_route_journal_v2.js
 account_sealed_operation_v4.js account_handshake_v4.js account_session_v4.js
 account_session_store_v4.js account_app_cipher_v4.js account_app_outbox_v4.js
 account_authenticated_history_v4.js account_session_runtime_v4.js account_static_kem_v1.js
 node_bootstrap_control_v4.js node_public_bootstrap_control_v4.js public_account_orchestrator_v4.js
 storage.js saved_messages.js)
set(DMASH_ACCOUNT_RESOURCES)
foreach(module IN LISTS DMASH_ACCOUNT_MODULES)
 set(file "${DMASH_ACCOUNT_PWA}/${module}")
 set_source_files_properties("${file}" PROPERTIES QT_RESOURCE_ALIAS "${module}")
 list(APPEND DMASH_ACCOUNT_RESOURCES "${file}")
endforeach()
qt_add_resources(dmash_account_service dmash_account_modules PREFIX "/dmash/account" FILES ${DMASH_ACCOUNT_RESOURCES})
qt_add_resources(dmash_account_service dmash_account_platform PREFIX "/dmash/account/native" BASE "${CMAKE_CURRENT_SOURCE_DIR}/../js" FILES "${CMAKE_CURRENT_SOURCE_DIR}/../js/platform.js")
qt_add_resources(dmash_account_service dmash_account_entry PREFIX "/dmash/account/native" BASE "${CMAKE_CURRENT_SOURCE_DIR}/js" FILES "${CMAKE_CURRENT_SOURCE_DIR}/js/pending_sends.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/pairing_host.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/idb.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/account_entry.js")
