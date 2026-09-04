"use strict";

/*
 * Real-browser stability fixes found during m1.5 acceptance testing.
 * Loaded after acceptance_fixes.js and intentionally keeps Device / Account /
 * Route authority separated.
 */
(function installStabilityFixes(global) {
    const PATCH = "__dmashStabilityFixesV1";
    const DEVICE_PRF_AAD = new TextEncoder().encode("dmash/device-root-webauthn-prf-wrap/v1");
    const ACCOUNT_BIO_VERSION = 1;
    const ACCOUNT_BIO_WRAP = "webauthn-prf-aes-256-gcm-v1";
    const ROOT_BYTES = 32;
    const IV_BYTES = 12;
    const PRF_BYTES = 32;
    const utf8 = value => new TextEncoder().encode(String(value));
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    const esc = value => global.Core?.escapeHtml
        ? global.Core.escapeHtml(String(value ?? ""))
        : String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

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
        if (!root || root[PATCH]) return false;

        const previousEnroll = root.enrollWebAuthnPrf.bind(root);
        const previousRewrap = root.rewrapMasterPin.bind(root);

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

        // Enrollment must never be able to destroy the Argon2 master wrap. The
        // previous multi-credential layer trusted state.record blindly. Always
        // start from the canonical persisted root record and verify it again
        // after the WebAuthn update; restore the snapshot on any regression.
        root.enrollWebAuthnPrf = async function guardedDeviceBiometricEnrollment() {
            const store = this._store();
            let before = await store.get();
            if (!validRootRecord(before) && validRootRecord(this.state?.record)) {
                before = this.state.record;
                await store.put(before);
            }
            if (!validRootRecord(before)) {
                throw new global.DeviceRootError("STORAGE_CORRUPT", "Master-wrap DeviceRoot повреждён. Биометрия не будет менять запись.");
            }
            if (this.state) this.state.record = before;
            try {
                const result = await previousEnroll();
                const after = await store.get();
                if (!validRootRecord(after)) throw new Error("biometric enrollment damaged the master wrap");
                this.__dmashBiometricRecordCache = after;
                if (this.state) this.state.record = after;
                return result;
            } catch (error) {
                await store.put(before).catch(() => {});
                this.__dmashBiometricRecordCache = before;
                if (this.state) this.state.record = before;
                if (error instanceof global.DeviceRootError) throw error;
                throw new global.DeviceRootError("WEBAUTHN_ENROLLMENT_FAILED", error?.message || "Biometric enrollment failed");
            }
        };

        // Cold-start biometric unlock must call navigator.credentials.get while
        // the calculator click still has trusted user activation. Metadata is
        // preloaded into RAM before that click, so there is no IndexedDB await
        // between the gesture and WebAuthn.
        root.unlockWithWebAuthnPrf = async function trustedGestureBiometricUnlock() {
            this._requireCrypto();
            this._requireWebAuthn();
            const record = this.__dmashBiometricRecordCache;
            const wraps = biometricWraps(record);
            if (!record || !wraps.length) {
                throw new global.DeviceRootError("WEBAUTHN_METADATA_NOT_READY", "Биометрические данные ещё не готовы. Повторите нажатие через секунду.");
            }
            const salt = unb64(wraps[0].prfSalt);
            if (salt.length !== PRF_BYTES) throw new global.DeviceRootError("STORAGE_CORRUPT", "Biometric PRF metadata is invalid.");
            const allowCredentials = wraps.map(wrap => ({ type: "public-key", id: unb64(wrap.credentialId) }));

            let assertionPromise;
            try {
                assertionPromise = this._credentials().get({ publicKey: {
                    challenge: this._webauthnChallenge(),
                    rpId: global.location?.hostname || undefined,
                    timeout: 60000,
                    userVerification: "required",
                    allowCredentials,
                    extensions: { prf: { eval: { first: salt } } }
                } });
            } catch (error) {
                throw new global.DeviceRootError("WEBAUTHN_ASSERTION_FAILED", error?.message || "WebAuthn could not start.");
            }

            let assertion;
            try { assertion = await assertionPromise; }
            catch (_) { throw new global.DeviceRootError("WEBAUTHN_ASSERTION_FAILED", "Биометрическая проверка отменена или не прошла."); }

            const selectedId = new Uint8Array(assertion.rawId);
            const selected = wraps.find(wrap => {
                const id = unb64(wrap.credentialId);
                return id.length === selectedId.length && id.every((v, i) => v === selectedId[i]);
            });
            if (!selected) throw new global.DeviceRootError("WEBAUTHN_UNKNOWN_CREDENTIAL", "Этот биометрический ключ не привязан к устройству.");

            let output;
            try {
                output = prfResult(assertion);
                const key = await this._prfWrapKey(output);
                const plaintext = await this._crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: unb64(selected.iv), additionalData: DEVICE_PRF_AAD },
                    key,
                    unb64(selected.wrappedRoot)
                );
                const unlockedRoot = new Uint8Array(plaintext);
                if (unlockedRoot.length !== ROOT_BYTES) throw new Error("invalid DeviceRoot length");
                const identity = await this.deviceIdentity(unlockedRoot);
                this.state = { root: unlockedRoot, identity, created: false, record };
                return this.state;
            } catch (error) {
                if (error instanceof global.DeviceRootError) throw error;
                throw new global.DeviceRootError("WEBAUTHN_UNLOCK_FAILED", "Биометрический ключ не смог открыть DeviceRoot.");
            } finally { output?.fill?.(0); }
        };

        // If an older broken biometric build already dropped the master-wrap
        // fields, an unlocked biometric session can repair them without changing
        // DeviceRoot. The current calculator master code is still verified
        // against sys_m before the in-memory root is rewrapped.
        root.rewrapMasterPin = async function repairableMasterRewrap(currentMasterPin, nextMasterPin) {
            const store = this._store();
            const stored = await store.get();
            if (validRootRecord(stored)) {
                const result = await previousRewrap(currentMasterPin, nextMasterPin);
                await this.refreshBiometricRecordCache();
                return result;
            }
            if (!this.state?.root) {
                throw new global.DeviceRootError("STORAGE_CORRUPT", "DeviceRoot master-wrap повреждён. Сначала разблокируйте устройство привязанной биометрией.");
            }
            if (await sha256Hex(currentMasterPin) !== localStorage.getItem("sys_m")) {
                throw new global.DeviceRootError("UNLOCK_FAILED", "Текущий Master-код неверен.");
            }
            const salt = this._crypto.getRandomValues(new Uint8Array(16));
            const wrapped = await this._encryptRoot(this.state.root, nextMasterPin, salt);
            const stateRecord = this.state.record && typeof this.state.record === "object" ? this.state.record : {};
            const source = stored && typeof stored === "object" ? stored : {};
            const updated = {
                ...stateRecord,
                ...source,
                id: "root",
                version: 1,
                wrapSalt: b64(salt),
                materials: source.materials || stateRecord.materials || {},
                ...wrapped
            };
            await store.put(updated);
            this.state.record = updated;
            this.__dmashBiometricRecordCache = updated;
            return Object.freeze({ rewrapped: true, repaired: true });
        };

        Object.defineProperty(root, PATCH, { value: true });
        return true;
    }

    async function verifyAccountPassphrase(identity, passphrase, expectedAccountId) {
        const result = await global.argon2.hash({
            pass: passphrase,
            salt: identity + "D_MASH_GAMMA_V1_STABLE",
            time: 3,
            mem: 65536,
            hashLen: 128,
            type: global.argon2.argon2id
        });
        const full = result.hash instanceof Uint8Array ? result.hash : new Uint8Array(result.hash || []);
        if (full.length !== 128) return false;
        const signing = global.nacl.sign.keyPair.fromSeed(full.slice(64, 96));
        const actual = hex(signing.publicKey);
        full.fill(0);
        signing.secretKey.fill(0);
        return actual === expectedAccountId;
    }

    function accountAad(identity) { return utf8(`dmash/account-biometric/v1|${identity}`); }

    function patchCore(core) {
        if (!core || core[PATCH]) return false;

        // Never auto-wipe an installation because a confirmed calculator code
        // failed to decrypt DeviceRoot. A storage/authentication fault must fail
        // closed and preserve the existing identity.
        core.recoverDeviceAfterConfirmedMaster = async function noAutomaticDeviceReplacement() {
            throw new global.DeviceRootError("RECOVERY_REQUIRED", "DeviceRoot не будет автоматически заменён. Используйте привязанную биометрию или явный wipe/recovery.");
        };

        // The retired passwordless Account path stays disabled and is removed
        // from UI. Account biometric login below is a separate WebAuthn binding.
        core.setupLazyLogin = function retiredLazyLogin() {
            this.customAlert("ОТКЛЮЧЕНО", "Беспарольный вход удалён. Используйте отдельную биометрию аккаунта.");
        };
        core.lazyLogin = async function retiredLazyLoginRuntime() { return false; };

        core._accountBiometricCache = new Map();
        core._pendingAccountBiometric = null;

        core.setupAccountBiometrics = function setupAccountBiometrics() {
            if (!this.activeIdentity || !this.keys?.server_id) return this.customAlert("БИОМЕТРИЯ АККАУНТА", "Сначала войдите в аккаунт.");
            this.openModal("БИОМЕТРИЯ АККАУНТА", `
                <div class="dmash-settings-note">Это отдельная биометрия Account. Она не разблокирует DeviceRoot и не заменяет Master-код устройства.</div>
                <input id="dmash-account-bio-pass" class="gate-input" type="password" autocomplete="current-password" placeholder="КЛЮЧ АККАУНТА">
                <button class="dmash-settings-action" onclick="Core.verifyAccountBiometricSecret()">ПРОВЕРИТЬ КЛЮЧ</button>
                <button class="dmash-settings-action primary" onclick="Core.closeModal()">ОТМЕНА</button>`);
        };

        core.verifyAccountBiometricSecret = async function verifyAccountBiometricSecret() {
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
                    <div class="dmash-settings-note">Ключ проверен. Следующее нажатие сразу откроет WebAuthn. Привязка относится только к этому Account.</div>
                    <button class="dmash-settings-action" onclick="Core.finishAccountBiometricEnrollment()">СОЗДАТЬ БИОМЕТРИЮ ACCOUNT</button>
                    <button class="dmash-settings-action primary" onclick="Core.closeModal()">ОТМЕНА</button>`);
            } catch (error) { this.customAlert("БИОМЕТРИЯ АККАУНТА", error.message); }
        };

        core.finishAccountBiometricEnrollment = async function finishAccountBiometricEnrollment() {
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
            let createPromise;
            try {
                createPromise = navigator.credentials.create({ publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rp: { name: "D-MASH Account", id: global.location.hostname },
                    user: { id: userId, name: `account-${Date.now()}`, displayName: "D-MASH Account" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "required" },
                    attestation: "none",
                    extensions: { prf: { eval: { first: prfSalt } } }
                } });
            } catch (error) {
                return this.customAlert("БИОМЕТРИЯ АККАУНТА", error?.message || "WebAuthn не запустился.");
            }
            try {
                const credential = await createPromise;
                const output = prfResult(credential);
                const key = await crypto.subtle.importKey("raw", output, "AES-GCM", false, ["encrypt", "decrypt"]);
                const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
                const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: accountAad(pending.identity) }, key, pending.secretBytes);
                const credentialId = new Uint8Array(credential.rawId);
                const binding = {
                    version: ACCOUNT_BIO_VERSION,
                    wrap: ACCOUNT_BIO_WRAP,
                    credentialId: b64(credentialId),
                    prfSalt: b64(prfSalt),
                    iv: b64(iv),
                    ciphertext: b64(new Uint8Array(encrypted)),
                    addedAt: Date.now()
                };
                await global.Storage.updateAccountAuth(pending.identity, { accountBiometric: binding, bio: true, lazy: false, lazy_key: null });
                this._accountBiometricCache.set(pending.identity, binding);
                pending.secretBytes.fill(0);
                this._pendingAccountBiometric = null;
                this.customAlert("ГОТОВО", "Биометрия привязана только к текущему аккаунту.");
            } catch (error) {
                this.customAlert("БИОМЕТРИЯ АККАУНТА", error?.message || "PRF недоступен на этой платформе.");
            }
        };

        // Called directly from an Account selector button. The registry metadata
        // is cached while rendering so navigator.credentials.get is invoked
        // before any await and retains trusted user activation.
        core.accountBiometricLogin = async function accountBiometricLogin(identity) {
            const binding = this._accountBiometricCache.get(identity);
            if (!binding || binding.version !== ACCOUNT_BIO_VERSION || binding.wrap !== ACCOUNT_BIO_WRAP) {
                return this.customAlert("БИОМЕТРИЯ АККАУНТА", "Для этого аккаунта биометрия не настроена.");
            }
            let assertionPromise;
            try {
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

        // Registry belongs to Global Settings. Replace the old modal so Back is
        // deterministic and never jumps into Account Settings.
        core.openAccountManager = async function repairedAccountManager() {
            const accounts = await global.Storage.getAllRegistryAccounts();
            const rows = accounts.map(account => {
                const id = encodeURIComponent(account.id);
                return `<div class="dmash-registry-row">
                    <div class="dmash-registry-id">${esc(account.id)}</div>
                    <div class="dmash-registry-state">${account.accountBiometric ? "ACCOUNT BIOMETRIC · " : ""}${account.id === this.activeIdentity ? "ACTIVE" : "LOCAL"}</div>
                    ${account.id !== this.activeIdentity ? `<button class="gate-btn danger" onclick="Core.removeAccountFlow(decodeURIComponent('${id}'))">УДАЛИТЬ</button>` : ""}
                </div>`;
            }).join("") || '<div class="dmash-settings-note">Реестр аккаунтов пуст.</div>';
            this.openModal("РЕЕСТР АККАУНТОВ", `
                <div class="dmash-registry-list">${rows}</div>
                <button class="dmash-settings-action primary" onclick="Core.closeModal()">НАЗАД</button>`);
        };

        Object.defineProperty(core, PATCH, { value: true });
        return true;
    }

    function patchUi(ui) {
        if (!ui || ui[PATCH]) return false;

        // Account selector now exposes a distinct biometric action only for
        // accounts that have an Account WebAuthn binding.
        ui.renderAccountSelector = async function stabilityAccountSelector(accounts) {
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return;
            if (global.Core?._accountBiometricCache) {
                global.Core._accountBiometricCache.clear();
                for (const account of accounts) if (account?.accountBiometric) global.Core._accountBiometricCache.set(account.id, account.accountBiometric);
            }
            const rows = accounts.map(account => {
                const id = encodeURIComponent(account.id);
                return `<div class="dmash-account-select-row">
                    <button class="gate-btn dmash-account-select-main" onclick="ui.renderLoginForm(decodeURIComponent('${id}'))">${esc(account.id)}</button>
                    ${account.accountBiometric ? `<button class="gate-btn dmash-account-bio-button" onclick="Core.accountBiometricLogin(decodeURIComponent('${id}'))">BIOMETRIC</button>` : ""}
                </div>`;
            }).join("");
            gateBox.innerHTML = `
                <div class="dmash-selector-head"><div id="gate-status-text">КТО ЗАХОДИТ?</div><button id="global-settings-button" class="gate-btn" onclick="ui.renderGlobalSettings()">⚙</button></div>
                <div class="acc-list-scroll">${rows}</div>
                <button class="gate-btn" onclick="ui.renderLoginForm()">+ НОВЫЙ ВХОД</button>`;
        };

        // Device biometric trigger is a tap target after it has been enrolled.
        // The enrollment itself still requires the deliberate 3-second hold.
        if (!ui.__dmashBiometricTapInstalled) {
            const keypad = document.getElementById("keypad");
            keypad?.addEventListener("click", event => {
                const token = event.target?.closest?.("[data-calc-token]")?.dataset?.calcToken;
                const configured = ui.configuredBiometricTrigger?.();
                if (!token || token !== configured || ui.mode !== 0 || global.DeviceRoot?.state?.root) return;
                event.preventDefault();
                event.stopImmediatePropagation();
                void (async () => {
                    try {
                        const ok = await global.Core?.unlockDeviceWithBiometrics?.();
                        if (!ok) return;
                        ui.resetCalculator?.();
                        await ui.show_gate?.();
                    } catch (_) { ui.resetCalculator?.(); }
                })();
            }, true);
            Object.defineProperty(ui, "__dmashBiometricTapInstalled", { value: true });
        }

        // Make the public-node request use the same direct socket path as a WSS
        // entry. Render immediately; AUTH_OK/node-state events update the card.
        ui.requestGlobalNode = async function fastPublicNodeRequest() {
            if (!global.DeviceRoot?.state?.root) return global.Core?.customAlert?.("NODE", "Сначала разблокируйте устройство.");
            const manager = global.NodeManager;
            try {
                if (!manager.originNodes?.length) await manager.loadOriginList("nodes.json");
                if (!manager.originNodes?.length) throw new Error("Публичные Node не найдены.");
                const selected = manager.originNodes[Math.floor(Math.random() * manager.originNodes.length)];
                const endpoint = manager.add(selected.url, selected.label, { public: true, autoConnect: true });
                manager.select(endpoint.url);
                void manager.connect(endpoint.url).catch(error => manager.showMessage?.(error, true));
                await this.renderGlobalNodes();
            } catch (error) { global.Core?.customAlert?.("NODE", error.message); }
        };

        Object.defineProperty(ui, PATCH, { value: true });
        return true;
    }

    function patchAccountSettings(core) {
        if (!core || core.__dmashAccountSettingsV3) return false;
        core.openSettings = function accountSettingsWithBiometric() {
            if (!this.activeIdentity) return global.ui?.renderGlobalSettings?.();
            const accountId = this.keys?.server_id || this.keys?.pub_hex || this.activeIdentity;
            const html = `
                <div class="dmash-settings-title">НАСТРОЙКИ АККАУНТА</div>
                <div class="dmash-settings-note">Только текущий Account. DeviceRoot, Nodes и Public Routes находятся в общих настройках.</div>
                <div class="dmash-settings-list">
                    <div class="dmash-account-identity">${esc(accountId)}</div>
                    <button class="dmash-settings-action" onclick="Core.copyMyId()">КОПИРОВАТЬ ID АККАУНТА</button>
                    <button class="dmash-settings-action" onclick="Core.setupAccountBiometrics()">БИОМЕТРИЯ АККАУНТА</button>
                    <button class="dmash-settings-action" onclick="Core.showMyQR()">PUBLIC / PRIVATE QR</button>
                    <button class="dmash-settings-action primary" onclick="Core.closeModal()">ЗАКРЫТЬ</button>
                </div>`;
            this.openModal("АККАУНТ", html);
        };
        Object.defineProperty(core, "__dmashAccountSettingsV3", { value: true });
        return true;
    }

    function warmColdStartBiometrics() {
        if (!localStorage.getItem("cfg_biometric_trigger")) return;
        if (global.__dmashBiometricWarmupStarted) return;
        if (!global.sys?.loadAllLibs) return;
        global.__dmashBiometricWarmupStarted = true;
        // Invisible crypto/runtime preload. It does not unlock DeviceRoot or an
        // Account; it only ensures the configured calculator trigger can invoke
        // WebAuthn immediately on a later trusted tap.
        void global.sys.loadAllLibs().catch(() => { global.__dmashBiometricWarmupStarted = false; });
    }

    function install() {
        warmColdStartBiometrics();
        const rootOk = patchDeviceRoot(global.DeviceRoot);
        const coreOk = patchCore(global.Core);
        const uiOk = patchUi(global.ui);
        patchAccountSettings(global.Core);
        return rootOk && coreOk && uiOk;
    }

    // Keep biometric metadata current after Device unlock/enrollment and update
    // the Node screen without adding any polling to routing itself.
    global.addEventListener?.("dmash-node-state", () => {
        const title = document.querySelector(".gate-container .dmash-settings-title");
        if (title?.textContent === "НОДЫ") void global.ui?.renderGlobalNodes?.();
    });

    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        try {
            warmColdStartBiometrics();
            if (global.DeviceRoot) void global.DeviceRoot.refreshBiometricRecordCache?.();
            if (install()) clearInterval(timer);
        } catch (error) { console.error("D-MASH stability fixes failed", error); }
        if (attempts > 2400) clearInterval(timer);
    }, 50);
    queueMicrotask(() => {
        try { install(); }
        catch (error) { console.error("D-MASH stability fixes failed", error); }
    });
})(window);
