"use strict";

/*
 * D-MASH real-browser acceptance fixes v50.
 * Loaded after runtime_fixes/public_contact_runtime/acceptance_fixes.
 * This file intentionally wins the final override order for user-visible
 * acceptance regressions without changing Device/Account/Route authority.
 */
(function installAcceptanceV50(global) {
    const PATCH = "__dmashAcceptanceV50";
    const ROOT_PATCH = "__dmashAcceptanceV50Root";
    const ACCOUNT_BIO_VERSION = 1;
    const ACCOUNT_BIO_WRAP = "webauthn-prf-aes-256-gcm-v1";
    const DEVICE_PRF_AAD = new TextEncoder().encode("dmash/device-root-webauthn-prf-wrap/v1");
    const ROOT_BYTES = 32;
    const PRF_BYTES = 32;
    const IV_BYTES = 12;
    const utf8 = value => new TextEncoder().encode(String(value));
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
    const b64url = bytes => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const decodeB64url = value => Uint8Array.from(atob(String(value).replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - String(value).length % 4) % 4)), c => c.charCodeAt(0));
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    const esc = value => global.Core?.escapeHtml
        ? global.Core.escapeHtml(String(value ?? ""))
        : String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

    function appStorage() {
        try {
            // storage.js declares a classic-script lexical const named Storage,
            // which shadows the browser Storage constructor for later scripts.
            if (typeof Storage !== "undefined" && Storage && typeof Storage.getAllRegistryAccounts === "function") return Storage;
        } catch (_) {}
        if (global.DMashStorage && typeof global.DMashStorage.getAllRegistryAccounts === "function") return global.DMashStorage;
        return null;
    }

    function appSys() {
        try {
            if (typeof sys !== "undefined" && sys && typeof sys.loadAllLibs === "function") return sys;
        } catch (_) {}
        return global.DMashSys && typeof global.DMashSys.loadAllLibs === "function" ? global.DMashSys : null;
    }

    function exposeLegacyLexicals() {
        const storage = appStorage();
        const system = appSys();
        if (storage) global.DMashStorage = storage;
        if (system) global.DMashSys = system;
    }

    function scheduleReload(delay = 180) {
        setTimeout(() => global.location.reload(), delay);
    }

    function validRootRecord(record) {
        return !!record && record.id === "root" && record.version === 1 &&
            typeof record.wrapSalt === "string" && !!record.wrapSalt &&
            typeof record.iv === "string" && !!record.iv &&
            typeof record.wrappedRoot === "string" && !!record.wrappedRoot;
    }

    function biometricWraps(record) {
        if (Array.isArray(record?.biometricWraps) && record.biometricWraps.length) return record.biometricWraps;
        return record?.biometricWrap ? [record.biometricWrap] : [];
    }

    function prfResult(credential) {
        const result = credential?.getClientExtensionResults?.()?.prf?.results?.first;
        const bytes = result instanceof ArrayBuffer ? new Uint8Array(result)
            : (ArrayBuffer.isView(result) ? new Uint8Array(result.buffer, result.byteOffset, result.byteLength) : null);
        if (!bytes || bytes.length !== PRF_BYTES) throw new Error("WebAuthn PRF result unavailable");
        return new Uint8Array(bytes);
    }

    async function sha256Hex(value) {
        return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(value))));
    }

    function patchDeviceRoot(root) {
        if (!root || root[ROOT_PATCH]) return false;
        if (typeof root.prepareWebAuthnUnlock !== "function" || typeof root.prepareUnlock !== "function") throw new Error("VERSIONED_DEVICE_ROOT_REQUIRED");
        const previousEnroll = root.enrollWebAuthnPrf.bind(root);

        root.__dmashBiometricRecordCache = null;
        root.refreshBiometricRecordCache = async function refreshBiometricRecordCache() {
            try {
                const record = await this._store().get();
                this.__dmashBiometricRecordCache = record || null;
                return record;
            } catch (_) {
                this.__dmashBiometricRecordCache = null;
                return null;
            }
        };
        void root.refreshBiometricRecordCache();

        root.enrollWebAuthnPrf = async function guardedEnrollment() {
            const result = await previousEnroll();
            await this.refreshBiometricRecordCache();
            return result;
        };
        // Prepared APIs preserve trusted synchronous OS invocation, root epoch,
        // current persisted biometric binding and temporary-secret ownership.
        root.unlockWithWebAuthnPrf = async function cachedWebAuthnUnlock() {
            const handle = await this.prepareWebAuthnUnlock({ record: this.__dmashBiometricRecordCache });
            try { return await this.publishPrepared(handle); } finally { handle.dispose(); }
        };

        Object.defineProperty(root, ROOT_PATCH, { value: true });
        return true;
    }

    async function verifyAccountPassphrase(identity, passphrase, expectedAccountId) {
        const result = await global.argon2.hash({
            pass: passphrase,
            salt: identity + "D_MASH_GAMMA_V1_STABLE",
            time: 3,
            mem: 65536,
            hashLen: 128,
            type: 0 /* deployed Account Argon2d; separate from local credentials */
        });
        const full = result.hash instanceof Uint8Array ? result.hash : new Uint8Array(result.hash || []);
        if (full.length !== 128) return false;
        const signing = global.nacl.sign.keyPair.fromSeed(full.slice(64, 96));
        const actual = hex(signing.publicKey);
        full.fill(0);
        signing.secretKey.fill(0);
        return actual === expectedAccountId;
    }

    const accountAad = identity => utf8(`dmash/account-biometric/v1|${identity}`);

    function plainCertificate(input) {
        if (!input || typeof input !== "object") throw new Error("RouteCertificate отсутствует.");
        return {
            version: Number(input.version),
            routeId: String(input.routeId || ""),
            signingPublicKey: String(input.signingPublicKey || ""),
            boxPublicKey: String(input.boxPublicKey || ""),
            issuedAt: Number(input.issuedAt),
            signature: String(input.signature || "")
        };
    }

    async function sealForCertificate(certificate, plaintext) {
        if (!global.DeviceRoutes.verifyCertificate(certificate)) throw new Error("RouteCertificate signature is invalid");
        const recipient = decodeB64url(certificate.boxPublicKey);
        const ephemeral = global.nacl.box.keyPair();
        const nonce = global.nacl.randomBytes(24);
        const clear = plaintext instanceof Uint8Array ? plaintext : utf8(String(plaintext));
        const ciphertext = global.nacl.box(clear, nonce, recipient, ephemeral.secretKey);
        ephemeral.secretKey.fill(0);
        const packed = new Uint8Array(1 + 32 + 24 + ciphertext.length);
        packed[0] = 1;
        packed.set(ephemeral.publicKey, 1);
        packed.set(nonce, 33);
        packed.set(ciphertext, 57);
        return b64url(packed);
    }

    function connectedNodeCount() {
        const manager = global.NodeManager;
        if (!manager) return 0;
        try {
            if (typeof manager.connectedConnections === "function") return manager.connectedConnections().length;
        } catch (_) {}
        let count = 0;
        try {
            for (const connection of manager.connections?.values?.() || []) if (connection?.state === "connected") count++;
        } catch (_) {}
        return count;
    }

    async function incomingContactCount() {
        try {
            if (!global.DeviceRoot?.state?.root || !global.Core?.getPendingContactRequestStore) return 0;
            const list = await global.Core.getPendingContactRequestStore().list();
            return list.filter(item => item?.status === "pending").length;
        } catch (_) { return 0; }
    }

    async function refreshMetrics() {
        const connected = connectedNodeCount();
        const incoming = await incomingContactCount();
        document.querySelectorAll("[data-dmash-connected-nodes]").forEach(el => { el.textContent = `Connected ${connected} Nodes`; });
        document.querySelectorAll("[data-dmash-incoming-contacts]").forEach(el => { el.textContent = `Incoming Contacts: ${incoming}`; });
        return { connected, incoming };
    }

    function patchCore(core) {
        if (!core || core[PATCH]) return false;
        const storage = appStorage();
        if (!storage) return false;

        // Never replace DeviceRoot automatically after a verified master code.
        core.recoverDeviceAfterConfirmedMaster = async function noAutomaticRootReplacement() {
            throw new global.DeviceRootError("RECOVERY_REQUIRED", "Не удалось открыть сохранённые данные устройства. Данные и ключи не удалены; требуется восстановление доступа.");
        };

        // Completed security workflows return to a clean fresh page.
        if (!core.__dmashV50ReloadHooks) {
            const originalDeviceBio = core.setupDeviceBiometrics?.bind(core);
            if (originalDeviceBio) core.setupDeviceBiometrics = async function(...args) {
                const result = await originalDeviceBio(...args);
                if (result !== false) scheduleReload(220);
                return result;
            };
            // terminateSession already clears RAM and restores the calculator
            // synchronously. A delayed reload discards the next PIN keystrokes.
            Object.defineProperty(core, "__dmashV50ReloadHooks", { value: true });
        }

        core.setupLazyLogin = function retiredPasswordlessAccount() {
            this.customAlert("ОТКЛЮЧЕНО", "Беспарольный вход удалён. Используйте отдельную биометрию аккаунта.");
        };
        core.lazyLogin = async function retiredPasswordlessRuntime() { return false; };
        core._accountBiometricCache = core._accountBiometricCache || new Map();
        core._pendingAccountBiometric = null;

        core.setupAccountBiometrics = function setupAccountBiometricsV50() {
            if (!this.activeIdentity || !this.keys?.server_id) return this.customAlert("БИОМЕТРИЯ АККАУНТА", "Сначала войдите в аккаунт.");
            this.openModal("БИОМЕТРИЯ АККАУНТА", `
                <div class="dmash-settings-note">Отдельная WebAuthn-привязка текущего Account. Она не разблокирует DeviceRoot.</div>
                <input id="dmash-account-bio-pass" class="gate-input" type="password" autocomplete="current-password" placeholder="КЛЮЧ АККАУНТА">
                <button class="dmash-settings-action" onclick="Core.verifyAccountBiometricSecret()">ПРОВЕРИТЬ КЛЮЧ</button>
                <button class="dmash-settings-action primary" onclick="Core.closeModal()">ОТМЕНА</button>`);
        };

        core.verifyAccountBiometricSecret = async function verifyAccountBiometricSecretV50() {
            const input = document.getElementById("dmash-account-bio-pass");
            const passphrase = input?.value || "";
            if (!passphrase || !this.activeIdentity || !this.keys?.server_id) return;
            try {
                const ok = await verifyAccountPassphrase(this.activeIdentity, passphrase, this.keys.server_id);
                if (!ok) throw new Error("Ключ аккаунта неверен.");
                const secretBytes = utf8(passphrase);
                if (input) input.value = "";
                this._pendingAccountBiometric?.secretBytes?.fill?.(0);
                this._pendingAccountBiometric = { identity: this.activeIdentity, secretBytes, expiresAt: Date.now() + 60000 };
                this.openModal("БИОМЕТРИЯ АККАУНТА", `
                    <div class="dmash-settings-note">Ключ подтверждён. Следующее нажатие создаст отдельный credential этого аккаунта.</div>
                    <button class="dmash-settings-action" onclick="Core.finishAccountBiometricEnrollment()">ПРИВЯЗАТЬ БИОМЕТРИЮ</button>
                    <button class="dmash-settings-action primary" onclick="Core.closeModal()">ОТМЕНА</button>`);
            } catch (error) { this.customAlert("БИОМЕТРИЯ АККАУНТА", error.message); }
        };

        core.finishAccountBiometricEnrollment = async function finishAccountBiometricEnrollmentV50() {
            const pending = this._pendingAccountBiometric;
            if (!pending || pending.identity !== this.activeIdentity || pending.expiresAt < Date.now()) {
                pending?.secretBytes?.fill?.(0);
                this._pendingAccountBiometric = null;
                return this.customAlert("БИОМЕТРИЯ АККАУНТА", "Проверка ключа истекла. Начните заново.");
            }
            if (global.isSecureContext !== true || typeof navigator.credentials?.create !== "function") {
                return this.customAlert("БИОМЕТРИЯ АККАУНТА", "WebAuthn недоступен в этом браузере.");
            }
            const prfSalt = crypto.getRandomValues(new Uint8Array(PRF_BYTES));
            const userId = crypto.getRandomValues(new Uint8Array(16));
            try {
                const credential = await navigator.credentials.create({ publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rp: { name: "D-MASH Account", id: global.location.hostname },
                    user: { id: userId, name: `dmash-account-${Date.now()}`, displayName: "D-MASH Account" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "required" },
                    attestation: "none",
                    extensions: { prf: { eval: { first: prfSalt } } }
                } });
                const output = prfResult(credential);
                const key = await crypto.subtle.importKey("raw", output, "AES-GCM", false, ["encrypt"]);
                const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
                const encrypted = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv, additionalData: accountAad(pending.identity) },
                    key,
                    pending.secretBytes
                );
                const binding = {
                    version: ACCOUNT_BIO_VERSION,
                    wrap: ACCOUNT_BIO_WRAP,
                    credentialId: b64(new Uint8Array(credential.rawId)),
                    prfSalt: b64(prfSalt),
                    iv: b64(iv),
                    ciphertext: b64(new Uint8Array(encrypted)),
                    addedAt: Date.now()
                };
                await storage.updateAccountAuth(pending.identity, { accountBiometric: binding, bio: true, lazy: false, lazy_key: null });
                this._accountBiometricCache.set(pending.identity, binding);
                pending.secretBytes.fill(0);
                this._pendingAccountBiometric = null;
                this.customAlert("ГОТОВО", "Биометрия аккаунта привязана.");
                scheduleReload(320);
            } catch (error) {
                this.customAlert("БИОМЕТРИЯ АККАУНТА", error?.message || "PRF недоступен на этой платформе.");
            }
        };

        core.accountBiometricLogin = async function accountBiometricLoginV50(identity) {
            const binding = this._accountBiometricCache.get(identity);
            if (!binding || binding.version !== ACCOUNT_BIO_VERSION || binding.wrap !== ACCOUNT_BIO_WRAP) {
                return this.customAlert("БИОМЕТРИЯ АККАУНТА", "Для этого аккаунта биометрия не настроена.");
            }
            let assertionPromise;
            try {
                // Starts synchronously from the Account selector click.
                assertionPromise = navigator.credentials.get({ publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rpId: global.location.hostname,
                    allowCredentials: [{ type: "public-key", id: unb64(binding.credentialId) }],
                    userVerification: "required",
                    extensions: { prf: { eval: { first: unb64(binding.prfSalt) } } }
                } });
            } catch (error) {
                return this.customAlert("БИОМЕТРИЯ АККАУНТА", error?.message || "WebAuthn не запустился.");
            }
            let secretBytes;
            try {
                const assertion = await assertionPromise;
                const output = prfResult(assertion);
                const key = await crypto.subtle.importKey("raw", output, "AES-GCM", false, ["decrypt"]);
                const plaintext = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: unb64(binding.iv), additionalData: accountAad(identity) },
                    key,
                    unb64(binding.ciphertext)
                );
                secretBytes = new Uint8Array(plaintext);
                const passphrase = new TextDecoder().decode(secretBytes);
                await this.boot(identity, passphrase, { register: false });
                if (this.activeIdentity !== identity || !this.keys?.sign) throw new Error("Аккаунт не открылся.");
            } catch (error) {
                this.customAlert("БИОМЕТРИЯ АККАУНТА", error?.message || "Биометрический вход не удался.");
            } finally { secretBytes?.fill?.(0); }
        };

        core.openAccountManager = async function accountManagerV50() {
            try {
                const accounts = await storage.getAllRegistryAccounts();
                const rows = accounts.map(account => {
                    return `<div class="dmash-registry-row">
                        <div class="dmash-registry-id">${esc(account.id)}</div>
                        <div class="dmash-registry-state">${account.accountBiometric ? "BIOMETRIC · " : ""}${account.id === this.activeIdentity ? "ACTIVE" : "LOCAL"}</div>
                        ${account.id !== this.activeIdentity ? `<button class="gate-btn danger" ${global.Core.dataActionAttributes("removeAccountFlow", [account.id])}>УДАЛИТЬ</button>` : ""}
                    </div>`;
                }).join("") || '<div class="dmash-settings-note">Реестр аккаунтов пуст.</div>';
                this.openModal("РЕЕСТР АККАУНТОВ", `
                    <div class="dmash-registry-list">${rows}</div>
                    <button class="dmash-settings-action primary" onclick="Core.closeModal()">НАЗАД</button>`);
            } catch (error) { this.customAlert("РЕЕСТР АККАУНТОВ", error.message); }
        };

        // Always provide an explicit way out of the installation-scoped inbox.
        const originalPending = core.openPendingContacts?.bind(core);
        if (originalPending) core.openPendingContacts = async function pendingContactsWithClose(...args) {
            await originalPending(...args);
            const box = document.querySelector("#sys-modal .sys-modal-box");
            if (box && !box.querySelector("[data-dmash-pending-close]")) {
                const button = document.createElement("button");
                button.className = "dmash-settings-action primary";
                button.dataset.dmashPendingClose = "1";
                button.textContent = "НАЗАД";
                button.addEventListener("click", () => this.closeModal());
                box.appendChild(button);
            }
            void refreshMetrics();
        };

        // Final Public Route sender override. This installs only after both old
        // repair layers have installed, so no later timer can replace it with
        // the obsolete deliver() call that omitted recipientCertificate.
        core.sendPublicContactRequest = async function sendPublicContactRequestV50(descriptor, displayName, intro) {
            const requestAccountSlot = this.activeIdentity;
            if (global.ContactFlowV3 && !requestAccountSlot) throw Error('Откройте Account для нового контакта');
            if (!descriptor?.r || !descriptor?.c) throw new Error("D-MASH Contact Link is invalid");
            const recipientCertificate = plainCertificate(descriptor.c);
            if (recipientCertificate.routeId !== String(descriptor.r)) throw new Error("RouteCertificate does not match RouteID");
            if (!global.DeviceRoutes.verifyCertificate(recipientCertificate)) throw new Error("RouteCertificate signature is invalid");

            // Proof workers are shared with DNSS/route restoration. Their API
            // exposes only cancelAll(), so cancellation invalidates this owner
            // without aborting unrelated work or deleting a durable request.
            if (this._publicRequestPreparation) throw new Error('Запрос уже готовится.');
            const rootState = global.DeviceRoot?.state;
            const accountKeys = this.keys, accountSalt = this.blindSalt, bootAttempt = this._accountBootAttempt;
            const operation = { cancelled: false, durable: false };
            let unlisten, watch, timeout;
            const cleanup = () => { clearInterval(watch); clearTimeout(timeout); unlisten?.(); };
            this._publicRequestPreparation = operation;
            const ownsAccount = () => this.activeIdentity === requestAccountSlot && global.DeviceRoot?.state === rootState && this.keys === accountKeys && this.blindSalt === accountSalt && this._accountBootAttempt === bootAttempt && !this._accountTransitioning;
            const ownsModal = () => this._publicRequestPreparation === operation && !!document.querySelector('[data-public-request-preparation]');
            const closePreparation = () => { if (ownsModal()) this.closeModal(); };
            const invalidate = () => { operation.cancelled = true; closePreparation(); cleanup(); if (this._publicRequestPreparation === operation) this._publicRequestPreparation = null; };
            const cancel = () => { if (!operation.durable) invalidate(); };
            const check = () => {
                if (operation.cancelled || !ownsAccount() || this._publicRequestPreparation !== operation) {
                    const error = new Error('Public request preparation cancelled');
                    error.publicRequestCancelled = true;
                    throw error;
                }
            };
            const markDurable = () => {
                check(); operation.durable = true;
                const note = document.querySelector('[data-public-request-preparation]');
                if (note) note.textContent = 'Сохраняем запрос. Его состояние появится в списке контактов.';
                const button = document.querySelector('[data-public-request-cancel]');
                if (button) { button.disabled = true; button.textContent = 'СОХРАНЯЕМ ЗАПРОС…'; }
            };
            this.openModal('ГОТОВИМ ЗАПРОС', `<div data-public-request-preparation class="dmash-settings-note">Готовим защищённый маршрут. Это может занять до 90 секунд. Запрос ещё не отправлен.</div><button class="dmash-settings-action primary" data-public-request-cancel>ОТМЕНА</button>`);
            document.querySelector('[data-public-request-cancel]')?.addEventListener('click', cancel);
            unlisten = global.DeviceRoot?.onLock?.(invalidate);
            watch = setInterval(() => { if (!ownsAccount()) invalidate(); }, 250);
            timeout = setTimeout(() => {
                if (!operation.durable && !operation.cancelled) {
                    cancel();
                    if (ownsAccount()) this.customAlert('ЗАПРОС НЕ ОТПРАВЛЕН', 'Подготовка маршрута заняла слишком долго. Попробуйте ещё раз.');
                }
            }, 90000);
            try {
            let reply = global.DeviceRoutes.currentActivePublicRoute ? global.DeviceRoutes.currentActivePublicRoute() : global.DeviceRoutes.current();
            if (!reply) reply = await global.DeviceRoutes.issue({ type: "public-contact", allowedAccounts: [] });
            check();
            const durableFlow = global.ContactFlowV3 && global.NodeManager.transportMode !== 'legacy';
            // The durable dispatcher activates the reply route itself. Persist
            // first so slow proof work has a visible, restart-safe waiting card.
            if (!durableFlow) await global.NodeManager?.probeActivePublicDeviceRoutes?.();
            check();
            const replyCertificate = plainCertificate(reply.certificate);
            const requestId = b64url(crypto.getRandomValues(new Uint8Array(32)));
            const request = global.ContactPayloads.validateRequest({
                type: "CONTACT_REQUEST_V1",
                version: 1,
                request_id: requestId,
                sender_display_name: String(displayName || "").trim(),
                intro_message: String(intro || "").trim(),
                reply_route_certificate: replyCertificate,
                bootstrap_encryption_public: replyCertificate.boxPublicKey,
                protocol_capabilities: ["CONTACT_BOOTSTRAP_V3", "DMP_C_V3"]
            });

            let deferred=false;
            const transport = new global.ContactTransport({
                validator: global.ContactPayloads,
                encrypt: ({ plaintext, recipientCertificate: certificate }) => sealForCertificate(certificate, plaintext),
                submit: async ({ routeLocator, envelope }) => {
                    check();
                    if(durableFlow){
                        const flow=core.getContactFlowV3();
                        markDurable();
                        await flow.recordOutgoing(request,recipientCertificate,requestAccountSlot,envelope);
                        check();
                        deferred = true;
                        // Existing flow owns retries and records delivery errors.
                        // Keep this UI result truthful: locally saved, not SENT.
                        void flow.dispatchInitial(request.request_id,requestAccountSlot).catch(() => {});
                        return {state:'REQUEST_DEFERRED'};
                    }
                    const ready = global.NodeManager.ensurePublicRouteV3
                        ? await global.NodeManager.ensurePublicRouteV3(routeLocator, reply.routeId)
                        : await global.NodeManager.routeStatus(routeLocator);
                    check();
                    if (!ready) throw new Error("RouteID пока не найден в mesh. Получатель должен быть online хотя бы на одной Node.");
                    if (ready.connection.client) {
                        markDurable();
                        await core.getContactFlowV3().recordOutgoing(request, recipientCertificate, requestAccountSlot);
                        check();
                        return global.NodeManager.submitDeviceEnvelopeV3(routeLocator, 'CONN_REQUEST', envelope, recipientCertificate, ready.connection);
                    }
                    markDurable();
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
                routeLocator: String(descriptor.r),
                recipientCertificate,
                payload: request
            });
            check();
            this.customAlert(deferred?'ЗАПРОС СОХРАНЁН':'ОТПРАВЛЕНО',deferred?'Запрос появится у собеседника после восстановления маршрута. Повторы выполняются автоматически.':'Запрос в контакты отправлен через Public Route.');
            } catch (error) {
                if (!error.publicRequestCancelled && ownsAccount() && !operation.cancelled) this.customAlert('CONTACT ROUTE', error.message);
            } finally {
                cleanup();
                closePreparation();
                if (this._publicRequestPreparation === operation) this._publicRequestPreparation = null;
            }
        };

        // Quick Names are a chooser, not a prefilled text field.
        core.startPublicContactFlow = async function publicContactQuickNameChooser(descriptor) {
            this._pendingPublicContactDescriptor = descriptor;
            let entries = [];
            try { entries = await this.getQuickNameRegistry().list(); } catch (_) {}
            const buttons = entries.map(entry => {
                return `<button class="dmash-quick-choice" ${global.Core.dataActionAttributes("choosePublicContactQuickName", [entry.id])}>
                    <b>${esc(entry.name)}</b><small>${esc(entry.value)}</small>
                </button>`;
            }).join("");
            this.openModal("КАКОЕ ИМЯ ПОКАЗАТЬ?", `
                <div class="dmash-settings-note">Выберите Quick Name или введите отдельное имя только для этого запроса.</div>
                <div class="dmash-quick-choice-list">${buttons || '<div class="dmash-settings-note">Quick Names не созданы.</div>'}</div>
                <button class="dmash-settings-action" onclick="Core.useCustomPublicContactName()">ВВЕСТИ ДРУГОЕ ИМЯ</button>
                <button class="dmash-settings-action primary" onclick="Core.closeModal()">ОТМЕНА</button>`);
        };

        core.choosePublicContactQuickName = async function choosePublicContactQuickName(id) {
            try {
                const registry = this.getQuickNameRegistry();
                const entries = await registry.list();
                const entry = entries.find(item => item.id === id);
                if (!entry) throw new Error("Quick Name не найден.");
                await registry.markRecent(id).catch(() => {});
                return this.continuePublicContactFlow(entry.value);
            } catch (error) { this.customAlert("QUICK NAME", error.message); }
        };

        core.useCustomPublicContactName = function useCustomPublicContactName() {
            this.customPrompt("ИМЯ", "Имя для первого запроса:", name => {
                if (name?.trim()) this.continuePublicContactFlow(name.trim());
            });
        };

        core.continuePublicContactFlow = function continuePublicContactFlow(name) {
            const descriptor = this._pendingPublicContactDescriptor;
            if (!descriptor) return this.customAlert("CONTACT ROUTE", "Contact Link потерян. Откройте его ещё раз.");
            this.customPrompt("ПЕРВОЕ СООБЩЕНИЕ", "Коротко объясните, кто вы:", intro => {
                void this.sendPublicContactRequest(descriptor, name, intro || "").catch(error => this.customAlert("CONTACT ROUTE", error.message));
            });
        };

        // Workspace: tiny connection line under the visible Account ID.
        const originalLaunch = core.launchWorkspace?.bind(core);
        if (originalLaunch) core.launchWorkspace = async function workspaceMetrics(...args) {
            const result = await originalLaunch(...args);
            const idCard = document.querySelector(".sidebar .my-id-card:not(.network-card)");
            if (idCard && !idCard.querySelector("[data-dmash-connected-nodes]")) {
                const status = document.createElement("div");
                status.className = "dmash-id-connection-line";
                status.dataset.dmashConnectedNodes = "1";
                idCard.appendChild(status);
            }
            void refreshMetrics();
            return result;
        };

        // Contact-count UI follows actual inbox changes.
        const originalIngest = core.ingestPublicContactPacket?.bind(core);
        if (originalIngest) core.ingestPublicContactPacket = async function(...args) {
            const result = await originalIngest(...args);
            global.dispatchEvent(new CustomEvent("dmash-incoming-contacts-changed"));
            return result;
        };
        for (const name of ["acceptPendingContactRequest", "rejectPendingContactRequest"]) {
            const original = core[name]?.bind(core);
            if (!original) continue;
            core[name] = async function(...args) {
                const result = await original(...args);
                global.dispatchEvent(new CustomEvent("dmash-incoming-contacts-changed"));
                return result;
            };
        }

        // Account settings: passwordless removed, Account biometric explicit.
        core.openSettings = function accountSettingsV50() {
            if (!this.activeIdentity) return global.ui?.renderGlobalSettings?.();
            const accountId = this.keys?.server_id || this.keys?.pub_hex || this.activeIdentity;
            const panic = localStorage.getItem("cfg_panic_gesture") === "true";
            this.openModal("АККАУНТ", `
                <div class="dmash-settings-title">НАСТРОЙКИ АККАУНТА</div>
                <div class="dmash-settings-note">Настройки текущего аккаунта. Флип-лок действует на всё устройство.</div>
                <div class="dmash-settings-list">
                    <div class="dmash-account-identity">${esc(accountId)}</div>
                    <button class="dmash-settings-action" onclick="Core.copyMyId()">КОПИРОВАТЬ ID АККАУНТА</button>
                    <button class="dmash-settings-action" onclick="Core.setupAccountBiometrics()">БИОМЕТРИЯ АККАУНТА</button>
                    <button class="dmash-settings-action" onclick="Core.showMyQR()">PUBLIC / PRIVATE QR</button>
                    <button class="dmash-settings-action" onclick="Core.openPendingContacts()">ЗАПРОСЫ В КОНТАКТЫ</button>
                    <button class="dmash-settings-action" onclick="NodeManager.renderSettings()">УЗЛЫ И ПОДКЛЮЧЕНИЕ</button>
                    <button class="dmash-settings-action" onclick="Core.toggleFlipper()">ЭКСТРЕННЫЙ ФЛИП-ЛОК УСТРОЙСТВА: ${panic ? "ВКЛ" : "ВЫКЛ"}</button>
                    <button class="dmash-settings-action primary" onclick="Core.closeModal()">ЗАКРЫТЬ</button>
                </div>`);
        };

        Object.defineProperty(core, PATCH, { value: true });
        return true;
    }

    function patchUi(ui) {
        if (!ui || ui[PATCH]) return false;

        // Important: no short-click biometric listener here. runtime_fixes.js
        // keeps the 3s qualifier and invokes WebAuthn from trusted pointerup.
        ui.renderAccountSelector = async function accountSelectorV50(accounts) {
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return;
            const core = global.Core;
            if (core?._accountBiometricCache) {
                core._accountBiometricCache.clear();
                for (const account of accounts) if (account?.accountBiometric) core._accountBiometricCache.set(account.id, account.accountBiometric);
            }
            const rows = accounts.map(account => {
                return `<div class="dmash-account-select-row">
                    <button class="gate-btn dmash-account-select-main" ${global.Core.dataActionAttributes("renderLoginForm", [account.id])}>${esc(account.id)}</button>
                    ${account.accountBiometric ? `<button class="gate-btn dmash-account-bio-button" ${global.Core.dataActionAttributes("accountBiometricLogin", [account.id])}>БИОМЕТРИЯ</button>` : ""}
                </div>`;
            }).join("");
            gateBox.innerHTML = `
                <div class="dmash-selector-head">
                    <div id="gate-status-text">КТО ЗАХОДИТ?</div>
                    <button id="global-settings-button" class="gate-btn" onclick="ui.renderGlobalSettings()">⚙</button>
                </div>
                <div class="acc-list-scroll">${rows}</div>
                <div class="dmash-gate-metrics">
                    <span data-dmash-connected-nodes>Connected 0 Nodes</span>
                    <span data-dmash-incoming-contacts>Incoming Contacts: 0</span>
                </div>
                <button class="gate-btn" onclick="ui.renderLoginForm()">+ НОВЫЙ ВХОД</button>`;
            void refreshMetrics();
            global.Core.bindDataActions(gateBox);
        };

        Object.defineProperty(ui, PATCH, { value: true });
        return true;
    }

    function warmColdStartBiometrics() {
        if (!localStorage.getItem("cfg_biometric_trigger") || global.__dmashV50WarmupStarted) return;
        const system = appSys();
        if (!system) return;
        global.__dmashV50WarmupStarted = true;
        void system.loadAllLibs().then(() => {
            exposeLegacyLexicals();
            void global.DeviceRoot?.refreshBiometricRecordCache?.();
        }).catch(() => { global.__dmashV50WarmupStarted = false; });
    }

    function prerequisitesReady() {
        const core = global.Core;
        return !!(
            core && global.ui && global.DeviceRoot && appStorage() &&
            global.ContactPayloads && global.ContactTransport && global.DeviceRoutes && global.NodeManager &&
            core.__dmashFunctionalRepairV2 && core.__dmashPublicContactRuntimeV1 && core.dmashAcceptanceFixesV1
        );
    }

    function install() {
        exposeLegacyLexicals();
        warmColdStartBiometrics();
        if (!prerequisitesReady()) return false;
        patchDeviceRoot(global.DeviceRoot);
        patchCore(global.Core);
        patchUi(global.ui);
        void global.DeviceRoot.refreshBiometricRecordCache?.();
        void refreshMetrics();
        return !!(global.Core?.[PATCH] && global.ui?.[PATCH]);
    }

    global.addEventListener("dmash-node-state", () => void refreshMetrics());
    global.addEventListener("dmash-incoming-contacts-changed", () => void refreshMetrics());

    if (global.DmashRuntimeReadiness) {
        let warmupChecked = false;
        global.DmashRuntimeReadiness.register("acceptance-v50-ui", 50, () => { exposeLegacyLexicals(); if (global.ui) patchUi(global.ui); }, () => !!global.ui?.[PATCH], ["acceptance-ui"]);
        global.DmashRuntimeReadiness.register("acceptance-v50", 50, install, () => !!(global.Core?.[PATCH] && global.DeviceRoot?.[ROOT_PATCH]), ["acceptance-core"]);
        global.DmashRuntimeReadiness.register("acceptance-v50-warmup", 51, () => { warmColdStartBiometrics(); warmupChecked = true; }, () => warmupChecked, ["foundation-loader", "acceptance-v50-ui"]);
        return;
    }
    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        try { if (install()) clearInterval(timer); }
        catch (error) { console.error("D-MASH acceptance v50 install failed", error); }
        if (attempts > 2400) clearInterval(timer);
    }, 50);
    queueMicrotask(() => {
        try { install(); }
        catch (error) { console.error("D-MASH acceptance v50 install failed", error); }
    });
})(window);
