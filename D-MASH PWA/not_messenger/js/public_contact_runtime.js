"use strict";

/* Public Route CONTACT_REQUEST_V1 integration kept separate from shell repair. */
(function (global) {
    const text = value => new TextEncoder().encode(value);
    const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

    async function seal(recipientCertificate, plaintext) {
        if (!global.DeviceRoutes?.verifyCertificate?.(recipientCertificate)) throw new Error("RouteCertificate is invalid");
        const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), char => char.charCodeAt(0));
        const recipient = decode(recipientCertificate.boxPublicKey);
        const ephemeral = global.nacl.box.keyPair();
        const nonce = global.nacl.randomBytes(24);
        const clear = plaintext instanceof Uint8Array ? plaintext : text(String(plaintext));
        const ciphertext = global.nacl.box(clear, nonce, recipient, ephemeral.secretKey);
        const packed = new Uint8Array(1 + 32 + 24 + ciphertext.length);
        packed[0] = 1; packed.set(ephemeral.publicKey, 1); packed.set(nonce, 33); packed.set(ciphertext, 57);
        ephemeral.secretKey.fill(0);
        return b64url(packed);
    }

    function install() {
        const core = global.Core;
        if (!core || core.__dmashPublicContactRuntimeV1 || !global.ContactPayloads || !global.ContactTransport || !global.DeviceRoutes) return false;

        core.sendPublicContactRequest = async function sendPublicContactRequest(descriptor, displayName, intro) {
            if (!descriptor?.r || !descriptor?.c || descriptor.c.routeId !== descriptor.r) throw new Error("D-MASH Contact Link is invalid");
            if (!global.DeviceRoutes.verifyCertificate(descriptor.c)) throw new Error("RouteCertificate signature is invalid");

            let reply = global.DeviceRoutes.current();
            if (!reply) reply = await global.DeviceRoutes.issue({ type: "public-contact", allowedAccounts: [] });
            await global.NodeManager?.probeActivePublicDeviceRoutes?.();

            const requestId = b64url(crypto.getRandomValues(new Uint8Array(32)));
            const request = global.ContactPayloads.validateRequest({
                type: "CONTACT_REQUEST_V1",
                version: 1,
                request_id: requestId,
                sender_display_name: String(displayName || "").trim(),
                intro_message: String(intro || "").trim(),
                reply_route_certificate: reply.certificate,
                bootstrap_encryption_public: reply.certificate.boxPublicKey,
                protocol_capabilities: ["CONTACT_ACCEPT_V1", "DMP_C_V2"]
            });

            const transport = new global.ContactTransport({
                validator: global.ContactPayloads,
                encrypt: ({ plaintext, recipientCertificate }) => seal(recipientCertificate, plaintext),
                submit: async ({ routeLocator, envelope }) => {
                    const ready = await global.NodeManager.routeStatus(routeLocator);
                    if (!ready) throw new Error("RouteID пока не найден в mesh. Получатель должен быть online хотя бы на одной Node.");
                    return global.NodeManager.requestOn(ready.connection, "SUBMIT_CONTACT", {
                        route_locator: routeLocator,
                        envelope,
                        reply_route: reply.routeId
                    });
                },
                decrypt: async () => { throw new Error("outgoing transport only"); },
                dedupe: async () => false,
                store: async () => null
            });

            await transport.deliver({
                routeLocator: descriptor.r,
                recipientCertificate: descriptor.c,
                payload: request
            });
            this.customAlert("ОТПРАВЛЕНО", "Запрос в контакты отправлен через Public Route. AccountID не раскрывался.");
        };

        Object.defineProperty(core, "__dmashPublicContactRuntimeV1", { value: true });
        return true;
    }

    let attempts = 0;
    const timer = setInterval(() => {
        attempts++;
        try { if (install()) clearInterval(timer); } catch (error) { console.error("Public contact runtime install failed", error); }
        if (attempts > 1200) clearInterval(timer);
    }, 100);
    if (document.readyState !== "loading") queueMicrotask(install);
})(window);
