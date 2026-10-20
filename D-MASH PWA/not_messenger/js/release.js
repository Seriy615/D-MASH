"use strict";

// Runtime installers are synchronous, idempotent stages. Lazy foundation loads
// explicitly compose them; readiness never depends on a polling deadline.
(function runtimeReadiness(global) {
    if (global.DmashRuntimeReadiness) return;
    const stages = new Map();
    let supportDone = false, supportError = null, queued = false;
    let resolveSupport;
    const support = new Promise(resolve => { resolveSupport = resolve; });
    function ready(stage) {
        try { return !!stage.ready(); }
        catch (error) { stage.error = error; return false; }
    }
    function flush() {
        queued = false;
        for (const stage of [...stages.values()].sort((a, b) => a.order - b.order)) {
            if (!stage.after.every(name => stages.has(name) && ready(stages.get(name)))) continue;
            if (ready(stage)) { stage.error = null; continue; }
            try {
                const result = stage.install();
                if (result && typeof result.then === "function") throw new Error("ASYNC_RUNTIME_INSTALLER: " + stage.name);
                stage.error = null;
            } catch (error) { stage.error = error; }
        }
    }
    function schedule() { if (!queued) { queued = true; queueMicrotask(flush); } }
    global.DmashRuntimeReadiness = Object.freeze({
        register(name, order, install, isReady, after = []) {
            if (!stages.has(name)) stages.set(name, { name, order, install, ready: isReady, after, error: null });
            schedule();
        },
        flush,
        supportLoaded() { supportDone = true; supportError = null; resolveSupport(); schedule(); },
        supportFailed(error) { supportDone = false; supportError = error; resolveSupport(); },
        async compose() {
            await support;
            if (!supportDone || supportError) throw supportError || new Error("UI_SUPPORT_NOT_READY");
            flush();
            const pending = [...stages.values()].filter(stage => !ready(stage) || stage.error);
            if (pending.length) {
                const error = new Error("UI_RUNTIME_NOT_READY: " + pending.map(stage => stage.name).join(", "));
                error.cause = pending.find(stage => stage.error)?.error;
                throw error;
            }
            return true;
        }
    });
})(window);


// One visible release identifier for the page and Service Worker generation.
// Review opt-in must be set before loading this script; never inferred from data.
window.DMASH_NODE_PROFILE = window.DMASH_NODE_PROFILE === "managed-v4" ? "managed-v4" : "legacy-migration";
window.DMASH_RELEASE = Object.freeze({ id: "transport-v3-node-preparation-20261020.44" });

/*
 * Runtime repair loader.
 *
 * Do not patch DeviceRoot here at DOMContentLoaded: the legacy shell loads the
 * crypto/core modules lazily after calculator unlock, so a one-shot DOM hook
 * races them. Runtime repair modules wait for the actual objects.
 */
(function loadFunctionalRepair(global) {
    const ver = encodeURIComponent(global.DMASH_RELEASE.id);
    const css = document.createElement("link");
    css.rel = "stylesheet";
    css.href = `css/runtime_fixes.css?r=${ver}`;
    document.head.appendChild(css);

    const support = [
        // Media is used by calls, files and recorded notes. Load its base
        // before any optional repair can stop this sequential loader.
        "js/call_session.js",
        "js/secure_session.js",
        "js/device_client_v3.js",
        "js/device_authority_v3.js",
        "js/device_envelope.js",
        "js/device_inbox.js",
        "js/account_node_inbox_v4.js",
        "js/route_discovery_v4.js",
        "js/account_node_transport_v4.js",
        "js/private_routes_v3.js",
        "js/contact_bootstrap_v3.js",
        "js/contact_flow_v3.js",
        "js/contact_payloads.js",
        "js/contact_transport.js",
        "js/pending_contact_requests.js",
        "js/resource_pow.js",
        "js/ui_global_bridge.js",
        "js/runtime_fixes.js",
        "js/public_contact_runtime.js",
        "js/acceptance_fixes.js",
        "js/acceptance_v50.js",
        "js/acceptance_v51.js",
        "js/call_signaling.js",
        "js/node_service_descriptor_v4.js",
        "js/node_sturn_service_v4.js",
        "js/call_runtime.js",
        "js/account_ratchet.js",
        "js/saved_messages.js",
        "js/chat_cipher.js",
        "js/chat_password.js",
        "js/account_ratchet_runtime.js",
        "js/account_recorded_media.js",
        "js/file_channel.js",
        "js/file_vault.js",
        "js/file_session.js",
        "js/file_runtime.js",
        "js/recorded_note_turn.js",
        "js/acceptance_v52.js",
        "js/acceptance_v54.js",
        "js/acceptance_v55.js",
        "js/account_pairing_v2.js",
        "js/account_route_binding_v2.js",
        "js/account_static_kem_v1.js",
        "js/account_route_journal_v2.js",
        "js/recipient_payload_v4.js",
        "js/vendor/blake3.min.js",
        "js/node_identity.js",
        "js/node_runtime_host_v4.js",
        "js/node_runtime_coordinator_v4.js",
        "js/node_public_bootstrap_control_v4.js",
        "js/node_bootstrap_control_v4.js",
        "js/account_private_pairing_link_v4.js",
        "js/account_sealed_operation_v4.js",
        "js/account_inbox_progress_v4.js",
        "js/account_managed_inbox_v4.js",
        "js/account_handshake_v4.js",
        "js/account_session_store_v4.js",
        "js/account_session_v4.js",
        "js/account_app_cipher_v4.js",
        "js/account_app_outbox_v4.js",
        "js/account_session_runtime_v4.js",
        "js/account_authenticated_history_v4.js",
        "js/account_media_control_v4.js", "js/account_media_bridge_v4.js", "js/account_media_dispatch_v4.js", "js/account_media_authority_v4.js", "js/public_account_orchestrator_v4.js",
        "js/managed_node_catalog_v4.js",
        "js/node_account_ui_v4.js",
        "js/node_root_lifecycle_v4.js"
    ];

    const load = src => new Promise((resolve, reject) => {
        // ui_logic may have appended call_session.js but not evaluated it yet.
        // A matching script element is therefore not proof the media base is
        // available. Re-request this idempotent base and wait for evaluation.
        const mediaBase = src === "js/call_session.js";
        if (mediaBase && typeof global.DmashCallSession?.CallSignalingSession === "function") return resolve();
        const existing = !mediaBase && Array.from(document.scripts).find(script => script.src && new URL(script.src, location.href).pathname.endsWith("/" + src));
        if (existing) return resolve();
        const script = document.createElement("script");
        script.src = `${src}?r=${ver}`;
        script.onload = () => {
            if (mediaBase && typeof global.DmashCallSession?.CallSignalingSession !== "function") {
                reject(new Error("MEDIA_RUNTIME_UNAVAILABLE: call_session.js did not initialize"));
            } else resolve();
        };
        script.onerror = () => reject(new Error(`Failed to load ${src}`));
        document.head.appendChild(script);
    });

    const start = async () => {
        const badge = document.getElementById("dmash-build-id");
        if (badge) badge.textContent = `D-MASH build ${global.DMASH_RELEASE.id}`;
        try {
            for (const src of support) await load(src);
            global.DmashRuntimeReadiness.supportLoaded();
        } catch (error) {
            global.DmashRuntimeReadiness.supportFailed(error);
            console.error("D-MASH functional repair loader failed", error);
            const notice = document.getElementById("dmash-release-notice");
            if (notice) {
                notice.textContent = "D-MASH repair modules failed to load. Reload the application.";
                notice.style.display = "block";
            }
        }
    };

    if (document.readyState === "loading") global.addEventListener("DOMContentLoaded", start, { once: true });
    else void start();
})(window);
