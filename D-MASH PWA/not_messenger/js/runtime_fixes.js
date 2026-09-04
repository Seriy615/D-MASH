"use strict";

/*
 * D-MASH PWA functional repair layer.
 *
 * This file intentionally patches the already-deployed legacy shell instead of
 * replacing the 170k core in one risky rewrite.  Every override preserves the
 * architecture in ROUTING_UPDATE.md:
 *   Device != Account; Public Route != AccountID; Account logout != Device lock.
 */
(function (global) {
    const ROUTE_ACTIVATION_KEY = "dmash_public_route_activation_v1";
    const ROUTE_INDEX_KEY = "dmash/routes/v1/index";
    const POW_DIFFICULTY = 22;
    const GRANT_LIFETIME_SECONDS = 24 * 60 * 60;
    const POW_LIFETIME_SECONDS = 5 * 60;
    const CONTACT_CIPHER_VERSION = 1;
    const CONTACT_REQUEST_TYPE = "CONTACT_REQUEST_V1";
    const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;
    const HEX_32 = /^[0-9a-f]{64}$/i;
    const PRF_AAD = new TextEncoder().encode("dmash/device-root-webauthn-prf-wrap/v1");
    const PRF_WRAP = "webauthn-prf-aes-256-gcm-v1";
    const PRF_BYTES = 32;
    const ROOT_BYTES = 32;
    const IV_BYTES = 12;

    const text = value => new TextEncoder().encode(value);
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const b64url = bytes => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const unb64 = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
    const unb64url = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), char => char.charCodeAt(0));
    const bytesHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
    const sameBytes = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
    const clone = value => JSON.parse(JSON.stringify(value));

    function activationState() {
        try {
            const state = JSON.parse(localStorage.getItem(ROUTE_ACTIVATION_KEY) || "{}");
            return state && typeof state === "object" && !Array.isArray(state) ? state : {};
        } catch (_) { return {}; }
    }
    function saveActivationState(state) { localStorage.setItem(ROUTE_ACTIVATION_KEY, JSON.stringify(state)); }
    function routeGeneration(routeId) {
        try {
            const index = JSON.parse(localStorage.getItem(ROUTE_INDEX_KEY) || "{}");
            if (index.current?.certificate?.routeId === routeId) return 1 + (index.previous ? 1 : 0);
            if (index.previous?.certificate?.routeId === routeId) return 1;
        } catch (_) {}
        return 1;
    }
    function routePrivateRecord(routeId) {
        const index = JSON.parse(localStorage.getItem(ROUTE_INDEX_KEY) || "{}");
        return [index.current, index.previous].find(route => route?.certificate?.routeId === routeId) || null;
    }

    /* ---------------- MULTI-CREDENTIAL DEVICE BIOMETRICS ---------------- */
    function patchBiometrics() {
        const root = global.DeviceRoot;
        if (!root || root.__dmashMultiBiometricV2) return false;

        root.enrollWebAuthnPrf = async function enrollMultipleWebAuthnCredentials() {
            this._requireCrypto();
            this._requireWebAuthn();
            if (!this.state?.root || !this.state?.record) {
                throw new global.DeviceRootError("DEVICE_LOCKED", "Сначала разблокируйте устройство Master-кодом.");
            }

            const record = this.state.record;
            const wraps = Array.isArray(record.biometricWraps)
                ? record.biometricWraps.map(clone)
                : (record.biometricWrap ? [clone(record.biometricWrap)] : []);
            if (wraps.length >= 8) throw new global.DeviceRootError("WEBAUTHN_LIMIT", "На устройство уже добавлено 8 биометрических ключей.");

            // March 2026 behavior: every enrollment creates a distinct platform
            // credential with a fresh user handle. All device credentials use
            // one PRF input so a single allowCredentials assertion can select
            // any enrolled finger/passkey and unwrap the same DeviceRoot.
            const salt = wraps[0]?.prfSalt ? unb64(wraps[0].prfSalt) : new Uint8Array(PRF_BYTES);
            if (salt.length !== PRF_BYTES) throw new global.DeviceRootError("STORAGE_CORRUPT", "Biometric PRF salt is invalid.");
            const userId = this._crypto.getRandomValues(new Uint8Array(16));
            let credential;
            try {
                credential = await this._credentials().create({ publicKey: {
                    challenge: this._webauthnChallenge(),
                    rp: { name: "MathPro Security", id: global.location?.hostname },
                    user: {
                        id: userId,
                        name: `device-${wraps.length + 1}-${Date.now()}`,
                        displayName: `D-MASH Device ${wraps.length + 1}`
                    },
                    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                    authenticatorSelection: {
                        authenticatorAttachment: "platform",
                        userVerification: "required",
                        residentKey: "required"
                    },
                    extensions: { prf: { eval: { first: salt } } }
                } });
            } catch (error) {
                throw new global.DeviceRootError("WEBAUTHN_ENROLLMENT_FAILED", error?.message || "Биометрический ключ не создан.");
            }

            const credentialId = unb64(this._credentialId(credential));
            let output;
            try {
                // Exactly as in the March implementation, prefer the PRF result
                // returned by create(). A second biometric prompt is only a
                // compatibility fallback for platforms that omit it on create.
                try { output = this._prfResult(credential); }
                catch (_) { output = await this._getPrfAssertion(credentialId, salt); }
                const key = await this._prfWrapKey(output);
                const iv = this._crypto.getRandomValues(new Uint8Array(IV_BYTES));
                const ciphertext = await this._crypto.subtle.encrypt(
                    { name: "AES-GCM", iv, additionalData: PRF_AAD }, key, this.state.root
                );
                const wrap = {
                    wrap: PRF_WRAP,
                    credentialId: b64(credentialId),
                    prfSalt: b64(salt),
                    iv: b64(iv),
                    wrappedRoot: b64(new Uint8Array(ciphertext)),
                    addedAt: Date.now()
                };
                wraps.push(wrap);
                const next = { ...record, biometricWraps: wraps, biometricWrap: wraps[0] };
                await this._store().put(next);
                this.state.record = next;
                return Object.freeze({ enrolled: true, credentialCount: wraps.length });
            } finally { output?.fill?.(0); }
        };

        root.unlockWithWebAuthnPrf = async function unlockWithAnyWebAuthnCredential() {
            this._requireCrypto();
            this._requireWebAuthn();
            const record = await this._store().get();
            const wraps = Array.isArray(record?.biometricWraps) && record.biometricWraps.length
                ? record.biometricWraps
                : (record?.biometricWrap ? [record.biometricWrap] : []);
            if (!wraps.length) throw new global.DeviceRootError("WEBAUTHN_NOT_ENROLLED", "Биометрия устройства ещё не настроена.");

            // All newly enrolled credentials share the first persisted PRF
            // input. Historical singular records become that first input.
            const salt = unb64(wraps[0].prfSalt);
            const allowCredentials = wraps.map(wrap => ({ type: "public-key", id: unb64(wrap.credentialId) }));
            let assertion;
            try {
                assertion = await this._credentials().get({ publicKey: {
                    challenge: this._webauthnChallenge(),
                    timeout: 60000,
                    userVerification: "required",
                    allowCredentials,
                    extensions: { prf: { eval: { first: salt } } }
                } });
            } catch (_) {
                throw new global.DeviceRootError("WEBAUTHN_ASSERTION_FAILED", "Биометрическая проверка отменена или не прошла.");
            }

            const assertionId = unb64(this._credentialId(assertion));
            const selected = wraps.find(wrap => sameBytes(unb64(wrap.credentialId), assertionId));
            if (!selected) throw new global.DeviceRootError("WEBAUTHN_UNKNOWN_CREDENTIAL", "Этот биометрический ключ не привязан к устройству.");
            let output;
            try {
                output = this._prfResult(assertion);
                const key = await this._prfWrapKey(output);
                const plaintext = await this._crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: unb64(selected.iv), additionalData: PRF_AAD }, key, unb64(selected.wrappedRoot)
                );
                const unlockedRoot = new Uint8Array(plaintext);
                if (unlockedRoot.length !== ROOT_BYTES) throw new Error("invalid DeviceRoot length");
                const identity = await this.deviceIdentity(unlockedRoot);
                this.state = { root: unlockedRoot, identity, created: false, record };
                return this.state;
            } catch (error) {
                if (this.state?.root) this.lock();
                if (error instanceof global.DeviceRootError) throw error;
                throw new global.DeviceRootError("WEBAUTHN_UNLOCK_FAILED", "Биометрический ключ не смог открыть DeviceRoot.");
            } finally { output?.fill?.(0); }
        };

        Object.defineProperty(root, "__dmashMultiBiometricV2", { value: true });
        return true;
    }

    // WebAuthn must start from a trusted pointer event on strict browsers.
    // Keep the three-second qualification, then start the actual WebAuthn call
    // synchronously inside pointerup.
    function patchBiometricGesture() {
        const ui = global.ui;
        if (!ui || ui.__dmashTrustedBiometricGesture) return false;
        const keypad = document.getElementById("keypad");
        if (!keypad) return false;
        const perform = ui.handleBiometricHold.bind(ui);
        ui._dmashQualifiedBiometricToken = null;
        ui.handleBiometricHold = function qualifyBiometricHold(token) {
            this._dmashQualifiedBiometricToken = token;
            this._suppressToken = token;
            return Promise.resolve(false);
        };
        const tokenFor = event => event.target?.closest?.("[data-calc-token]")?.dataset?.calcToken || null;
        keypad.addEventListener("pointerup", event => {
            const token = tokenFor(event);
            if (!token || ui._dmashQualifiedBiometricToken !== token) return;
            ui._dmashQualifiedBiometricToken = null;
            ui._suppressToken = token;
            void perform(token);
        }, true);
        keypad.addEventListener("pointercancel", () => { ui._dmashQualifiedBiometricToken = null; }, true);
        Object.defineProperty(ui, "__dmashTrustedBiometricGesture", { value: true });
        return true;
    }

    /* ---------------- PUBLIC ROUTE REGISTRATION + POW ---------------- */
    function patchNodeManager() {
        const manager = global.NodeManager;
        if (!manager || manager.__dmashPublicRouteActivationV2 || !global.DmashResourcePow) return false;
        const originalOnMessage = manager.onMessage.bind(manager);
        manager._publicLocatorRoutes = manager._publicLocatorRoutes || new Map();

        manager.onMessage = function patchedOnMessage(connection, event) {
            try {
                const message = JSON.parse(event.data);
                if (message?.type === "CHALLENGE" && HEX_32.test(message.node_id || "")) connection.nodeId = message.node_id.toLowerCase();
                if (message?.type === "AUTH_OK" && HEX_32.test(message.node_id || "")) connection.nodeId = message.node_id.toLowerCase();
                if (message?.type === "DELIVERY_AVAILABLE" && message.locator_handle) {
                    queueMicrotask(() => this.ingestPublicRouteDelivery(message.locator_handle).catch(error => {
                        global.Core?.shmon?.("WARN", `Public contact delivery deferred: ${error.message}`);
                    }));
                }
            } catch (_) {}
            return originalOnMessage(connection, event);
        };

        manager.deviceNodeDnss = async function deviceNodeDnss(nodeId) {
            if (!HEX_32.test(nodeId || "")) throw new Error("NodeID unavailable for DNSS");
            const material = await global.DeviceRoot.deviceMaterial(
                `dnss/v1/${nodeId.toLowerCase()}`,
                () => crypto.getRandomValues(new Uint8Array(16))
            );
            if (!(material instanceof Uint8Array) || material.length !== 16) throw new Error("DNSS material corrupt");
            return new Uint8Array(material);
        };

        manager.activatePublicRouteOnConnection = async function activatePublicRouteOnConnection(route, connection, options = {}) {
            if (!route?.routeId || !connection || connection.state !== "connected") return { state: "NODE_NOT_CONNECTED" };
            const nodeId = (connection.nodeId || connection.endpoint?.nodeId || "").toLowerCase();
            if (!HEX_32.test(nodeId)) throw new Error("Entry Node identity is unavailable");
            for (const capability of ["REGISTER_INBOUND_LOCATOR", "START_PROBE"]) {
                if (!connection.capabilities?.has(capability)) throw new Error(`Node lacks ${capability}`);
            }

            const now = Math.floor(Date.now() / 1000);
            const all = activationState();
            const nodeState = all[nodeId] && typeof all[nodeId] === "object" ? all[nodeId] : { dnssRegistered: false, routes: {} };
            nodeState.routes ||= {};
            const existing = nodeState.routes[route.routeId];
            const registrationAlive = !options.forceRegistration && existing?.expiresAt > now + 60;

            if (!registrationAlive) {
                for (const capability of ["REGISTER_DNSS", "REGISTER_ENTRY_GRANT"]) {
                    if (!connection.capabilities?.has(capability)) throw new Error(`Node lacks ${capability}`);
                }
                const transport = await global.DeviceRoot.transportIdentity(nodeId);
                const transportKey = global.Core.bytesToHex(transport.signing.publicKey);
                const dnss = await this.deviceNodeDnss(nodeId);
                const powExpiry = now + POW_LIFETIME_SECONDS;

                const registerDnss = async forcePow => {
                    const payload = { dnss: bytesHex(dnss) };
                    if (forcePow || !nodeState.dnssRegistered) {
                        payload.pow = await global.DmashResourcePow.mineActivationPow({
                            nodeId, activationType: "DNSS", deviceTransportKey: transportKey,
                            resource: dnss, expiresAt: powExpiry, difficulty: POW_DIFFICULTY
                        });
                    }
                    return this.requestOn(connection, "REGISTER_DNSS", payload);
                };

                try { await registerDnss(false); }
                catch (error) {
                    if (nodeState.dnssRegistered && /INVALID_RESOURCE_POW/.test(error.message)) await registerDnss(true);
                    else throw error;
                }
                nodeState.dnssRegistered = true;

                const grant = await global.DeviceRoutes.issueEntryGrant(route.routeId, nodeId, {
                    generation: routeGeneration(route.routeId),
                    createdAt: now,
                    expiresAt: now + GRANT_LIFETIME_SECONDS
                });
                const grantPow = await global.DmashResourcePow.mineActivationPow({
                    nodeId, activationType: "ENTRY_GRANT", deviceTransportKey: transportKey,
                    resource: route.routeId, expiresAt: powExpiry, difficulty: POW_DIFFICULTY
                });
                await this.requestOn(connection, "REGISTER_ENTRY_GRANT", { entry_grant: grant, pow: grantPow });
                nodeState.routes[route.routeId] = { expiresAt: grant.expires_at, generation: grant.generation };
                all[nodeId] = nodeState; saveActivationState(all);
            }

            const inbound = await this.requestOn(connection, "REGISTER_INBOUND_LOCATOR", { locator: route.routeId });
            if (inbound?.locator_handle) this._publicLocatorRoutes.set(inbound.locator_handle, route.routeId);
            await this.requestOn(connection, "START_PROBE", {
                route_locator: route.routeId,
                back_route_locator: route.routeId,
                hop_limit: 15
            });
            return { state: registrationAlive ? "READVERTISED" : "ACTIVATED", locator_handle: inbound?.locator_handle || null };
        };

        manager.probeActivePublicDeviceRoutes = async function repairedPublicRouteProbe(connection = null) {
            const routes = this.activePublicDeviceRoutes();
            const connections = connection ? [connection] : this.connectedConnections();
            const results = [];
            for (const node of connections) {
                for (const route of routes) {
                    try { results.push({ status: "fulfilled", value: await this.activatePublicRouteOnConnection(route, node) }); }
                    catch (reason) { results.push({ status: "rejected", reason }); }
                }
            }
            return results;
        };

        manager.ingestPublicRouteDelivery = async function ingestPublicRouteDelivery(locatorHandle) {
            const routeId = this._publicLocatorRoutes.get(locatorHandle);
            if (!routeId || !global.Core?.ingestPublicContactPacket) return;
            const pulled = await this.pull(locatorHandle);
            for (const packet of pulled.packets || []) {
                const envelope = packet?.envelope;
                if (envelope?.type !== CONTACT_REQUEST_TYPE) continue;
                try {
                    await global.Core.ingestPublicContactPacket(routeId, packet);
                    await this.ack(packet.id || envelope.delivery_id || envelope.request_id, packet._nodeUrl);
                } catch (error) {
                    global.Core?.shmon?.("WARN", `CONTACT_REQUEST_V1 rejected: ${error.message}`);
                }
            }
        };

        Object.defineProperty(manager, "__dmashPublicRouteActivationV2", { value: true });
        return true;
    }

    /* ---------------- PUBLIC CONTACT CRYPTO / LINKS ---------------- */
    async function routeBoxSecret(routeId) {
        const route = routePrivateRecord(routeId);
        if (!route?.materialName) throw new Error("Route private material not found");
        const encoded = await global.DeviceRoot.deviceMaterial(route.materialName, () => { throw new Error("Route material missing"); });
        try {
            const material = JSON.parse(new TextDecoder().decode(encoded));
            const secret = unb64url(material.boxSecretKey);
            if (secret.length !== 32) throw new Error("Route box key corrupt");
            return secret;
        } finally { encoded.fill(0); }
    }

    async function sealForRouteCertificate(certificate, plaintext) {
        if (!global.DeviceRoutes.verifyCertificate(certificate)) throw new Error("Invalid RouteCertificate");
        const recipient = unb64url(certificate.boxPublicKey);
        const ephemeral = global.nacl.box.keyPair();
        const nonce = global.nacl.randomBytes(24);
        const clear = plaintext instanceof Uint8Array ? plaintext : text(String(plaintext));
        const ciphertext = global.nacl.box(clear, nonce, recipient, ephemeral.secretKey);
        ephemeral.secretKey.fill(0);
        const packed = new Uint8Array(1 + 32 + 24 + ciphertext.length);
        packed[0] = CONTACT_CIPHER_VERSION;
        packed.set(ephemeral.publicKey, 1);
        packed.set(nonce, 33);
        packed.set(ciphertext, 57);
        return b64url(packed);
    }

    async function openForLocalRoute(routeId, encoded) {
        const packed = unb64url(encoded);
        if (packed.length < 58 || packed[0] !== CONTACT_CIPHER_VERSION) throw new Error("Unsupported contact cipher");
        const ephemeral = packed.slice(1, 33);
        const nonce = packed.slice(33, 57);
        const ciphertext = packed.slice(57);
        const secret = await routeBoxSecret(routeId);
        try {
            const clear = global.nacl.box.open(ciphertext, nonce, ephemeral, secret);
            if (!clear) throw new Error("Contact request authentication failed");
            return new Uint8Array(clear);
        } finally { secret.fill(0); }
    }

    function normalizeDmashFragment(value) {
        const source = String(value || "").trim();
        if (source.startsWith("#/")) return source;
        try {
            const url = new URL(source, global.location.href);
            return url.hash || source;
        } catch (_) { return source; }
    }

    function patchCore() {
        const core = global.Core;
        if (!core || core.__dmashFunctionalRepairV2) return false;

        // COPY means the visible 64-char Account ID again. Pairing QR remains a
        // richer payload, but copying an ID must never silently copy JSON.
        core.copyMyId = async function copyRawAccountId() {
            const id = this.keys?.server_id || this.keys?.pub_hex;
            if (!HEX_32.test(id || "")) return this.customAlert("ОШИБКА", "Публичный ID аккаунта не готов.");
            try {
                await navigator.clipboard.writeText(id.toLowerCase());
                this.customAlert("СКОПИРОВАНО", "ID аккаунта (64 знака) скопирован.");
            } catch (_) {
                this.customPrompt("ID АККАУНТА", "Скопируйте вручную:", () => {}, { value: id.toLowerCase(), readOnly: true });
            }
        };

        core.copyPairingPackage = async function copyPairingPackage() {
            const id = this.keys?.server_id || this.keys?.pub_hex;
            if (!HEX_32.test(id || "")) throw new Error("Account ID unavailable");
            const contribution = await this.ensurePairingContribution();
            const payload = JSON.stringify({ type: "DMASH_PAIRING_V1", version: 1, user_id: id.toLowerCase(), contribution });
            await navigator.clipboard.writeText(payload);
            this.customAlert("СКОПИРОВАНО", "Pairing package скопирован.");
        };

        const originalLaunchWorkspace = core.launchWorkspace.bind(core);
        core.launchWorkspace = async function repairedWorkspace() {
            const result = await originalLaunchWorkspace();
            document.querySelector("#workspace .network-card")?.remove();
            return result;
        };

        // Account settings now contain Account things only. Device Nodes,
        // Public Routes, Master code and biometrics live in Global Settings.
        core.openSettings = function accountOnlySettings() {
            if (!this.activeIdentity) return global.ui?.renderGlobalSettings?.();
            const accountId = this.keys?.server_id || this.keys?.pub_hex || this.activeIdentity;
            const h = `
                <div class="dmash-settings-title">НАСТРОЙКИ АККАУНТА</div>
                <div class="dmash-settings-note">Только параметры текущего аккаунта. Узлы, Public Routes и DeviceRoot здесь не настраиваются.</div>
                <div class="dmash-settings-list">
                    <div class="dmash-account-identity">${this.escapeHtml(String(accountId))}</div>
                    <button class="sys-modal-btn" onclick="Core.copyMyId()">КОПИРОВАТЬ ID АККАУНТА</button>
                    <button class="sys-modal-btn" onclick="Core.setupLazyLogin()">БЕСПАРОЛЬНЫЙ ВХОД АККАУНТА</button>
                    <button class="sys-modal-btn" onclick="Core.openAccountManager()">РЕЕСТР АККАУНТОВ</button>
                    <button class="sys-modal-btn primary" onclick="Core.closeModal()">ЗАКРЫТЬ</button>
                </div>`;
            this.openModal("АККАУНТ", h);
        };

        // Logout Account, not Device.  Preserve DeviceRoot, NodeManager,
        // device-level route state and the selector.  The old implementation
        // nulled deviceState and cleared all sessionStorage, which caused the
        // black-screen/locked-state regression.
        core.accountLogout = async function repairedAccountLogout() {
            const zero = value => {
                if (value instanceof Uint8Array) value.fill(0);
                else if (value && typeof value === "object") Object.values(value).forEach(zero);
            };
            const preservedDeviceState = global.DeviceRoot?.state || this.deviceState;
            try {
                if (this.callState !== "idle" || this.peerConnection || this.localStream) this.endCall?.();
                this.killAllMedia?.();
                if (this.peerConnection) { this.peerConnection.close(); this.peerConnection = null; }
                if (this.syncInterval) { clearInterval(this.syncInterval); this.syncInterval = null; }
                if (this.blobURLs) { this.blobURLs.forEach(url => URL.revokeObjectURL(url)); this.blobURLs = []; }
                zero(this.gammaKeys); zero(this.keys);
                this.gammaKeys = { master: null, sign: null, box: null };
                this.keys = { sign: null, box: null, pub_hex: null };
                this.blindSalt?.fill?.(0); this.blindSalt = null;
                this.privateRouteProbeGeneration++;
                this.activeIdentity = null; this.activePeerId = null; this.openingPeerId = null;
                this.pendingInboundByPeer?.clear?.(); this.historyPrefetch?.clear?.();
                this.isSyncing = false; this.chatOffset = 0; this.isLoadingHistory = false;
                this.pendingContactRequestStore = null;
                this.deviceState = preservedDeviceState;
                if (preservedDeviceState?.identity) {
                    this.device = Object.freeze({
                        id: preservedDeviceState.identity.deviceId,
                        fingerprints: preservedDeviceState.identity.fingerprints,
                        signing: preservedDeviceState.identity.signing,
                        agreement: preservedDeviceState.identity.agreement
                    });
                }
                this.closeModal?.();
                const workspace = document.getElementById("workspace");
                if (workspace) { workspace.replaceChildren(); workspace.style.display = "none"; }
                const calculator = document.getElementById("app-container");
                if (calculator) { calculator.style.display = "none"; calculator.style.opacity = "1"; }
                if (global.ui) { ui.mode = 0; ui.resetCalculator?.(); }
                await global.ui?.show_gate?.();
            } catch (error) {
                this.shmon?.("ERR", `Account logout UI recovery: ${error.message}`);
                const layer = document.getElementById("settings-layer");
                if (layer) layer.style.setProperty("display", "flex", "important");
                await global.ui?.show_gate?.();
            }
        };

        // Re-arm the pairing-derived route immediately before the legacy SOS
        // key exchange. This makes the button recover from a route that was not
        // ready when the two QR codes were scanned.
        core.beginKeyExchange = async function beginKeyExchange() {
            if (!this.activePeerId) return this.customAlert("КЛЮЧИ", "Сначала выберите контакт.");
            try {
                const alias = await global.Storage.getAlias(this.activePeerId, "L1");
                const peer = await global.Storage.getBox("blind_peers", alias);
                if (!peer?.pairingContribution) {
                    return this.customAlert("КЛЮЧИ", "Сначала отсканируйте Pairing QR этого контакта.");
                }
                await this.ensureAutomaticMeshRoute(this.activePeerId, peer.pairingContribution);
                await this.sendMessage({ type: "sys", content: "key-exchange" }, "SOS");
                setTimeout(() => this.syncNetwork?.(), 300);
            } catch (error) { this.customAlert("ОБМЕН КЛЮЧАМИ", error.message); }
        };
        const originalLoadChat = core.loadChat?.bind(core);
        if (originalLoadChat) {
            core.loadChat = async function repairedLoadChat(...args) {
                const result = await originalLoadChat(...args);
                const button = document.querySelector("#init-zone button");
                if (button) { button.onclick = () => this.beginKeyExchange(); button.textContent = "ОБМЕНЯТЬСЯ КЛЮЧАМИ"; }
                return result;
            };
        }

        core.copyPublicContactLink = async function copyPublicContactLink(routeId) {
            const route = global.DeviceRoutes.list().find(item => item.routeId === routeId);
            if (!route) throw new Error("Public Route not found");
            const link = new URL(global.location.href);
            link.hash = global.serializeDmashContactUri({ v: 1, r: route.routeId, c: route.certificate }).slice(1);
            try { await navigator.clipboard.writeText(link.href); this.customAlert("СКОПИРОВАНО", "D-MASH Contact Link скопирован."); }
            catch (_) { this.customPrompt("CONTACT LINK", "Скопируйте вручную:", () => {}, { value: link.href, readOnly: true }); }
        };

        core.sendPublicContactRequest = async function sendPublicContactRequest(descriptor, displayName, intro) {
            if (!global.ContactPayloads || !global.ContactTransport) throw new Error("Contact transport modules unavailable");
            if (!global.DeviceRoutes.verifyCertificate(descriptor.c)) throw new Error("RouteCertificate is invalid");
            let reply = global.DeviceRoutes.current();
            if (!reply) reply = await global.DeviceRoutes.issue({ type: "public-contact", allowedAccounts: [] });
            await global.NodeManager?.probeActivePublicDeviceRoutes?.();
            const requestId = b64url(crypto.getRandomValues(new Uint8Array(32)));
            const request = {
                type: "CONTACT_REQUEST_V1", version: 1, request_id: requestId,
                sender_display_name: String(displayName || "").trim(),
                intro_message: String(intro || "").trim(),
                reply_route_certificate: reply.certificate,
                bootstrap_encryption_public: reply.certificate.boxPublicKey,
                protocol_capabilities: ["CONTACT_ACCEPT_V1", "DMP_C_V2"]
            };
            const validator = global.ContactPayloads;
            const transport = new global.ContactTransport({
                validator,
                encrypt: ({ plaintext, recipientCertificate }) => sealForRouteCertificate(recipientCertificate, plaintext),
                submit: async ({ routeLocator, envelope }) => {
                    const ready = await global.NodeManager.routeStatus(routeLocator);
                    if (!ready) throw new Error("RouteID пока не найден в mesh. Получатель должен быть online хотя бы на одной Node.");
                    return global.NodeManager.requestOn(ready.connection, "SUBMIT_CONTACT", {
                        route_locator: routeLocator, envelope, reply_route: reply.routeId
                    });
                },
                decrypt: async () => { throw new Error("outgoing transport only"); },
                dedupe: async () => false,
                store: async () => null
            });
            await transport.deliver({ routeLocator: descriptor.r, payload: request });
            this.customAlert("ОТПРАВЛЕНО", "Запрос в контакты отправлен через Public Route. AccountID не раскрывался.");
        };

        core.startPublicContactFlow = async function startPublicContactFlow(descriptor) {
            let defaultName = "";
            try { defaultName = (await this.getQuickNameRegistry().list())[0]?.name || ""; } catch (_) {}
            this.customPrompt("КАКОЕ ИМЯ ПОКАЗАТЬ?", "Имя для первого запроса:", name => {
                if (!name?.trim()) return;
                this.customPrompt("ПЕРВОЕ СООБЩЕНИЕ", "Коротко объясните, кто вы:", intro => {
                    void this.sendPublicContactRequest(descriptor, name, intro || "").catch(error => this.customAlert("CONTACT ROUTE", error.message));
                });
            }, { value: defaultName });
        };

        core.ingestPublicContactPacket = async function ingestPublicContactPacket(routeId, packet) {
            const envelope = packet?.envelope;
            if (!envelope || envelope.type !== CONTACT_REQUEST_TYPE || !B64URL_32.test(envelope.request_id || "")) throw new Error("Invalid contact envelope");
            const plaintext = await openForLocalRoute(routeId, envelope.ciphertext);
            const request = global.ContactPayloads.deserializeRequest(plaintext);
            if (request.request_id !== envelope.request_id) throw new Error("Contact request binding mismatch");
            const replyDescriptor = { v: 1, r: request.reply_route_certificate.routeId, c: request.reply_route_certificate };
            const replyRoute = global.serializeDmashContactUri(replyDescriptor);
            const stored = await this.getPendingContactRequestStore().addContactRequest({
                requestId: request.request_id,
                displayName: request.sender_display_name,
                intro: request.intro_message,
                replyRoute,
                bootstrap: { contact_request: request },
                receivedRoute: routeId
            });
            if (!stored.duplicate) this.customAlert("НОВЫЙ КОНТАКТ", `${this.escapeHtml(request.sender_display_name)} отправил запрос.`);
            return stored;
        };

        const originalAddPeerFlow = core.addPeerFlow.bind(core);
        core.addPeerFlow = async function repairedAddPeerFlow(value) {
            const fragment = normalizeDmashFragment(value);
            try {
                if (fragment.startsWith("#/c/")) {
                    const descriptor = global.parseDmashContactUri(fragment);
                    if (descriptor.r && descriptor.c) return this.startPublicContactFlow(descriptor);
                    if (descriptor.i && descriptor.p) {
                        return originalAddPeerFlow(JSON.stringify({ type: "DMASH_PAIRING_V1", version: 1, user_id: descriptor.i, contribution: descriptor.p }));
                    }
                }
                if (fragment.startsWith("#/r/")) {
                    const descriptor = global.parseDmashRouteUri(fragment);
                    return this.startPublicContactFlow(descriptor);
                }
                if (B64URL_32.test(fragment)) {
                    return this.customAlert("ROUTE ID", "Одного RouteID недостаточно для первого E2EE-запроса: нужен D-MASH Contact Link с RouteCertificate/RouteBoxPublic. Попросите нажать «КОПИРОВАТЬ CONTACT LINK».");
                }
            } catch (error) { return this.customAlert("D-MASH LINK", error.message); }
            return originalAddPeerFlow(value);
        };

        core.addPeerPrompt = function repairedAddPeerPrompt() {
            this.customPrompt("ДОБАВИТЬ КОНТАКТ", "Вставьте D-MASH Contact Link, Pairing package или 64-значный Account ID:", value => {
                if (value?.trim()) void this.addPeerFlow(value.trim());
            });
        };

        Object.defineProperty(core, "__dmashFunctionalRepairV2", { value: true });
        return true;
    }

    /* ---------------- GLOBAL SETTINGS / PUBLIC ROUTE UI ---------------- */
    function patchUi() {
        const ui = global.ui;
        if (!ui || ui.__dmashFunctionalRepairV2) return false;

        ui.renderGlobalSettings = function repairedGlobalSettings() {
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return;
            const panic = localStorage.getItem("cfg_panic_gesture") === "true";
            gateBox.innerHTML = `
                <div class="dmash-settings-title">НАСТРОЙКИ УСТРОЙСТВА</div>
                <div class="dmash-settings-note">Device-level настройки. Они не принадлежат выбранному аккаунту.</div>
                <div class="dmash-settings-list">
                    <button class="dmash-settings-card" onclick="ui.openPublicRoutes()"><b>ПУБЛИЧНЫЕ МАРШРУТЫ</b><small>RouteID, Contact Link, активация и PoW</small></button>
                    <button class="dmash-settings-card" onclick="ui.renderGlobalQuickNames()"><b>БЫСТРЫЕ ИМЕНА</b><small>Локальный зашифрованный реестр</small></button>
                    <button class="dmash-settings-card" onclick="ui.renderGlobalNodes()"><b>УЗЛЫ</b><small>Подключения этого устройства</small></button>
                    <button class="dmash-settings-card" onclick="Core.openPendingContacts()"><b>ЗАПРОСЫ В КОНТАКТЫ</b><small>Входящие Public Route requests</small></button>
                    <button class="dmash-settings-card" onclick="Core.setupTelegram()"><b>ТЕЛЕГРАМ-МАЯК</b><small>Device notification beacon</small></button>
                    <button class="dmash-settings-card" onclick="Core.toggleFlipper()"><b>ЭКСТРЕННЫЙ ФЛИП-ЛОК: ${panic ? "ВКЛ" : "ВЫКЛ"}</b><small>Блокирует устройство, не Account</small></button>
                    <button class="dmash-settings-card" onclick="ui.startMasterReconfiguration()"><b>СМЕНИТЬ MASTER-КОД</b><small>Перешифровать тот же DeviceRoot</small></button>
                    <button class="dmash-settings-card" onclick="ui.beginBiometricTriggerSetup()"><b>БИОМЕТРИЯ УСТРОЙСТВА</b><small>Можно привязать несколько platform credentials</small></button>
                </div>
                <button class="gate-btn dmash-settings-back" onclick="ui.show_gate()">НАЗАД К АККАУНТАМ</button>`;
        };

        ui._routeStatusText = "";
        ui._routeStatusClass = "";
        ui.setRouteStatus = function setRouteStatus(message, kind = "") {
            this._routeStatusText = message || ""; this._routeStatusClass = kind;
            const box = document.getElementById("dmash-route-status");
            if (box) { box.textContent = this._routeStatusText; box.className = `dmash-route-status ${kind}`; }
        };

        ui.openPublicRoutes = function repairedPublicRoutes() {
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return;
            try {
                const routes = global.DeviceRoutes.list();
                const rows = routes.map(route => `
                    <div class="dmash-route-row">
                        <div class="dmash-route-state">${route.current ? "CURRENT" : "PREVIOUS"} · ${route.active ? "ACTIVE" : "INACTIVE"}</div>
                        <div class="dmash-route-id">${route.routeId}</div>
                        <div class="dmash-route-actions">
                            <button class="gate-btn" onclick="Core.copyPublicContactLink('${route.routeId}')">КОПИРОВАТЬ CONTACT LINK</button>
                            <button class="gate-btn secondary" onclick="ui.togglePublicRoute('${route.routeId}')">${route.active ? "DEACTIVATE" : "ACTIVATE"}</button>
                            ${route.current ? '<button class="gate-btn secondary" onclick="ui.reissuePublicRoute()">REISSUE</button>' : ""}
                        </div>
                    </div>`).join("") || '<div class="dmash-settings-note">PUBLIC ROUTES ЕЩЁ НЕ СОЗДАНЫ.</div>';
                gateBox.innerHTML = `
                    <div class="dmash-settings-title">PUBLIC ROUTES</div>
                    <div class="dmash-settings-note">RouteID = RouteSignPublic. Новый Route регистрируется на подключённых Node с resource PoW; reconnect только повторяет Probe.</div>
                    <div id="dmash-route-status" class="dmash-route-status ${this._routeStatusClass}">${this._routeStatusText}</div>
                    ${rows}
                    <button class="gate-btn" onclick="ui.createPublicRoute()">CREATE PUBLIC ROUTE</button>
                    <button class="gate-btn dmash-settings-back" onclick="ui.renderGlobalSettings()">НАЗАД</button>`;
            } catch (error) { global.Core?.customAlert?.("PUBLIC ROUTES", error.message); }
        };

        ui.createPublicRoute = async function repairedCreatePublicRoute() {
            try {
                this.setRouteStatus("Генерация Route keypair…");
                const route = await global.DeviceRoutes.issue({ type: "public-contact", allowedAccounts: [] });
                this.openPublicRoutes(); this.setRouteStatus("Route создан. Выполняется Node-bound PoW…");
                const connected = global.NodeManager?.connectedConnections?.() || [];
                if (!connected.length) {
                    this.setRouteStatus("Route создан локально. PoW выполнится при первом подключении к Node.");
                    return route;
                }
                const results = await global.NodeManager.probeActivePublicDeviceRoutes();
                const failures = results.filter(item => item.status === "rejected");
                if (failures.length === results.length) throw failures[0]?.reason || new Error("Route activation failed");
                this.setRouteStatus("Route зарегистрирован: EntryGrant + PoW + Probe готовы.", "ok");
            } catch (error) { this.setRouteStatus(error.message, "error"); }
        };

        ui.reissuePublicRoute = async function repairedReissuePublicRoute() {
            try {
                const route = await global.DeviceRoutes.reissue();
                this.openPublicRoutes(); this.setRouteStatus("Новый RouteID создан. Выполняется новый PoW…");
                const connected = global.NodeManager?.connectedConnections?.() || [];
                if (connected.length) await global.NodeManager.probeActivePublicDeviceRoutes();
                this.setRouteStatus(connected.length ? "Reissue зарегистрирован и объявлен." : "Reissue локальный; PoW при подключении к Node.", "ok");
                return route;
            } catch (error) { this.setRouteStatus(error.message, "error"); }
        };

        ui.togglePublicRoute = async function repairedTogglePublicRoute(id) {
            const route = global.DeviceRoutes.list().find(item => item.routeId === id);
            if (!route) return;
            global.DeviceRoutes.activate(id, !route.active);
            this.openPublicRoutes();
            if (!route.active) {
                try { await global.NodeManager.probeActivePublicDeviceRoutes(); this.setRouteStatus("Route активирован и объявлен.", "ok"); }
                catch (error) { this.setRouteStatus(error.message, "error"); }
            }
        };

        const originalShowGate = ui.show_gate.bind(ui);
        ui.show_gate = async function repairedShowGate(...args) {
            const result = await originalShowGate(...args);
            // Continue a validated fragment deep link after Device unlock. The
            // descriptor stays in the fragment/session, never in a query string.
            if (global.DeviceRoot?.state && /^#\/(?:c|r)\//.test(global.location.hash || "") && global.Core) {
                const pending = global.location.hash;
                history.replaceState(null, "", global.location.pathname + global.location.search);
                setTimeout(() => void global.Core.addPeerFlow(pending), 0);
            }
            return result;
        };

        Object.defineProperty(ui, "__dmashFunctionalRepairV2", { value: true });
        return true;
    }

    function install() {
        const a = patchBiometrics();
        const b = patchBiometricGesture();
        const c = patchNodeManager();
        const d = patchCore();
        const e = patchUi();
        return a && b && c && d && e;
    }

    let attempts = 0;
    const timer = setInterval(() => {
        attempts++;
        try { if (install()) clearInterval(timer); }
        catch (error) { console.error("D-MASH functional repair install failed", error); }
        if (attempts > 1200) clearInterval(timer);
    }, 100);
    if (document.readyState !== "loading") queueMicrotask(install);
})(window);
