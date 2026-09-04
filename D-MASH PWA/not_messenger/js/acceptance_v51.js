"use strict";

/*
 * D-MASH browser acceptance fixes v51.
 * Final runtime layer for the real-device issues found after v50:
 * - device unlock never waits for Node sockets or route probes;
 * - Account registry is encrypted at rest under DeviceRoot material and the
 *   legacy plaintext IndexedDB registry is migrated+cleared;
 * - calculator arithmetic is a calculator again;
 * - Global Settings exposes explicit full local recovery wipe;
 * - stale WebAuthn credentials can be removed locally and signalled to the OS;
 * - pending-contact modal has exactly one Back action;
 * - slow optional Kyber/QR initialization is moved off the calculator unlock.
 */
(function installAcceptanceV51(global) {
    const PATCH = "__dmashAcceptanceV51";
    const UI_PATCH = "__dmashAcceptanceV51Ui";
    const SYS_PATCH = "__dmashAcceptanceV51Sys";
    const NODE_PATCH = "__dmashAcceptanceV51Node";
    const STORAGE_PATCH = "__dmashSecureRegistryV1";

    const SECURE_DB = "dm_registry_secure_v1";
    const LEGACY_DB = "dm_registry_v1";
    const SECURE_VERSION = 1;
    const ACCOUNTS_STORE = "accounts";
    const META_STORE = "meta";
    const REGISTRY_MATERIAL = "account-registry-v1";
    const REGISTRY_AAD = new TextEncoder().encode("dmash/account-registry/v1");

    const enc = value => new TextEncoder().encode(String(value));
    const dec = bytes => new TextDecoder().decode(bytes);
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
    const toB64url = value => String(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const esc = value => global.Core?.escapeHtml
        ? global.Core.escapeHtml(String(value ?? ""))
        : String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

    function appUi() {
        try { if (typeof ui !== "undefined" && ui) return ui; } catch (_) {}
        return global.ui || null;
    }
    function appSys() {
        try { if (typeof sys !== "undefined" && sys) return sys; } catch (_) {}
        return global.DMashSys || null;
    }
    function appStorage() {
        try { if (typeof Storage !== "undefined" && Storage?.getAllRegistryAccounts) return Storage; } catch (_) {}
        return global.DMashStorage || null;
    }

    function idbRequest(request) {
        return new Promise((resolve, reject) => {
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error || new Error("IndexedDB request failed"));
        });
    }
    function txDone(tx) {
        return new Promise((resolve, reject) => {
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error || new Error("IndexedDB transaction failed"));
            tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
        });
    }

    /* ---------------- SECURE ACCOUNT REGISTRY ---------------- */
    function patchStorage(storage) {
        if (!storage || storage[STORAGE_PATCH]) return false;

        let dbPromise = null;
        let keysPromise = null;
        let migrationPromise = null;

        async function openSecure() {
            if (dbPromise) return dbPromise;
            dbPromise = new Promise((resolve, reject) => {
                const request = indexedDB.open(SECURE_DB, SECURE_VERSION);
                request.onupgradeneeded = () => {
                    const db = request.result;
                    if (!db.objectStoreNames.contains(ACCOUNTS_STORE)) db.createObjectStore(ACCOUNTS_STORE, { keyPath: "alias" });
                    if (!db.objectStoreNames.contains(META_STORE)) db.createObjectStore(META_STORE, { keyPath: "key" });
                };
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error || new Error("Secure registry open failed"));
            });
            return dbPromise;
        }

        async function registryKeys() {
            if (keysPromise) return keysPromise;
            keysPromise = (async () => {
                if (!global.DeviceRoot?.state?.root || !global.DeviceRoot?.deviceMaterial) {
                    throw new Error("DeviceRoot must be unlocked before reading the Account registry.");
                }
                const raw = await global.DeviceRoot.deviceMaterial(REGISTRY_MATERIAL, () => crypto.getRandomValues(new Uint8Array(32)));
                if (!(raw instanceof Uint8Array) || raw.length !== 32) throw new Error("Account registry key material is invalid.");
                try {
                    const aes = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
                    const hmac = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
                    return { aes, hmac };
                } finally { raw.fill(0); }
            })();
            return keysPromise;
        }

        async function aliasFor(id) {
            const { hmac } = await registryKeys();
            return b64(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, enc(id))));
        }

        async function seal(record) {
            const { aes } = await registryKeys();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv, additionalData: REGISTRY_AAD }, aes, enc(JSON.stringify(record))
            );
            return b64(new Uint8Array([...iv, ...new Uint8Array(ciphertext)]));
        }

        async function openBlob(blob) {
            const { aes } = await registryKeys();
            const packed = unb64(blob);
            if (packed.length <= 12) throw new Error("Secure Account registry record is corrupt.");
            const clear = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: packed.slice(0, 12), additionalData: REGISTRY_AAD }, aes, packed.slice(12)
            );
            return JSON.parse(dec(new Uint8Array(clear)));
        }

        async function readAndEraseLegacy() {
            let databases = null;
            try { databases = await indexedDB.databases?.(); } catch (_) {}
            if (Array.isArray(databases) && !databases.some(item => item?.name === LEGACY_DB)) return [];

            return new Promise(resolve => {
                const request = indexedDB.open(LEGACY_DB);
                request.onerror = () => resolve([]);
                request.onupgradeneeded = () => {};
                request.onsuccess = async () => {
                    const db = request.result;
                    try {
                        if (!db.objectStoreNames.contains("accounts")) { db.close(); return resolve([]); }
                        const readTx = db.transaction("accounts", "readonly");
                        const rows = await idbRequest(readTx.objectStore("accounts").getAll()).catch(() => []);
                        await txDone(readTx).catch(() => {});
                        const clearTx = db.transaction("accounts", "readwrite");
                        clearTx.objectStore("accounts").clear();
                        await txDone(clearTx).catch(() => {});
                        db.close();
                        try { indexedDB.deleteDatabase(LEGACY_DB); } catch (_) {}
                        resolve(Array.isArray(rows) ? rows : []);
                    } catch (_) { try { db.close(); } catch (_) {} resolve([]); }
                };
            });
        }

        async function ensureMigrated() {
            if (migrationPromise) return migrationPromise;
            migrationPromise = (async () => {
                const db = await openSecure();
                const metaTx = db.transaction(META_STORE, "readonly");
                const marker = await idbRequest(metaTx.objectStore(META_STORE).get("legacy-migrated")).catch(() => null);
                await txDone(metaTx).catch(() => {});
                if (marker?.done) return;

                const legacy = await readAndEraseLegacy();
                if (legacy.length) {
                    const writeTx = db.transaction(ACCOUNTS_STORE, "readwrite");
                    const store = writeTx.objectStore(ACCOUNTS_STORE);
                    for (const record of legacy) {
                        if (!record?.id) continue;
                        store.put({ alias: await aliasFor(record.id), blob: await seal(record) });
                    }
                    await txDone(writeTx);
                }
                const markTx = db.transaction(META_STORE, "readwrite");
                markTx.objectStore(META_STORE).put({ key: "legacy-migrated", done: true, at: Date.now() });
                await txDone(markTx);
                try { storage.registry_instance?.close?.(); } catch (_) {}
                storage.registry_instance = null;
            })();
            return migrationPromise;
        }

        storage.openRegistry = async function secureRegistryOpen() {
            await ensureMigrated();
            return openSecure();
        };
        storage.getAllRegistryAccounts = async function secureRegistryList() {
            await ensureMigrated();
            const db = await openSecure();
            const tx = db.transaction(ACCOUNTS_STORE, "readonly");
            const rows = await idbRequest(tx.objectStore(ACCOUNTS_STORE).getAll());
            await txDone(tx).catch(() => {});
            const out = [];
            for (const row of rows || []) {
                try { out.push(await openBlob(row.blob)); } catch (_) {}
            }
            return out;
        };
        storage.getRegistryAccount = async function secureRegistryGet(id) {
            await ensureMigrated();
            const db = await openSecure();
            const tx = db.transaction(ACCOUNTS_STORE, "readonly");
            const row = await idbRequest(tx.objectStore(ACCOUNTS_STORE).get(await aliasFor(id)));
            await txDone(tx).catch(() => {});
            return row?.blob ? openBlob(row.blob) : undefined;
        };
        storage.registerAccount = async function secureRegistryRegister(identity, pubHex) {
            const current = await this.getRegistryAccount(identity) || { id: identity, notified: false };
            current.id = identity;
            current.pk = pubHex;
            const db = await openSecure();
            const tx = db.transaction(ACCOUNTS_STORE, "readwrite");
            tx.objectStore(ACCOUNTS_STORE).put({ alias: await aliasFor(identity), blob: await seal(current) });
            await txDone(tx);
        };
        storage.updateAccountAuth = async function secureRegistryUpdate(id, params) {
            const current = await this.getRegistryAccount(id) || { id };
            Object.assign(current, params || {});
            const db = await openSecure();
            const tx = db.transaction(ACCOUNTS_STORE, "readwrite");
            tx.objectStore(ACCOUNTS_STORE).put({ alias: await aliasFor(id), blob: await seal(current) });
            await txDone(tx);
        };
        storage.removeAccountFromRegistry = async function secureRegistryRemove(id) {
            await ensureMigrated();
            const db = await openSecure();
            const tx = db.transaction(ACCOUNTS_STORE, "readwrite");
            tx.objectStore(ACCOUNTS_STORE).delete(await aliasFor(id));
            await txDone(tx);
        };

        storage.REGISTRY_DB = SECURE_DB;
        global.DMashStorage = storage;
        Object.defineProperty(storage, STORAGE_PATCH, { value: true });
        return true;
    }

    /* ---------------- ASYNC NODE STARTUP ---------------- */
    function patchNodeManager(manager) {
        if (!manager || manager[NODE_PATCH] || typeof manager.onDeviceUnlocked !== "function") return false;
        const original = manager.onDeviceUnlocked.bind(manager);
        manager.onDeviceUnlocked = function detachedDeviceUnlockNetwork(...args) {
            Promise.resolve().then(() => original(...args)).catch(error => {
                console.warn("[D-MASH] asynchronous Node startup deferred:", error?.message || error);
            });
            return Promise.resolve({ scheduled: true });
        };
        Object.defineProperty(manager, NODE_PATCH, { value: true });
        return true;
    }

    /* ---------------- FAST CALCULATOR BOOT ---------------- */
    function patchSystem(system) {
        if (!system || system[SYS_PATCH] || typeof system.loadScript !== "function") return false;
        const loadScript = system.loadScript.bind(system);
        system.loadAllLibs = async function fastFoundationLoad() {
            try {
                const ver = global.DMASH_RELEASE?.id || "v51";
                global.Module = { wasmBinaryFile: "js/vendor/argon2.wasm" };
                global.KyberModule = global.KyberModule || {
                    locateFile: path => path.endsWith(".wasm") ? "js/vendor/kyber768.wasm" : path
                };

                // Start optional heavy assets immediately, but never keep the
                // calculator waiting for them. Account boot awaits Kyber later.
                const kyberReady = Promise.all([
                    loadScript(`js/vendor/kyber768.js?v=${ver}`)
                ]).then(async () => {
                    for (let i = 0; i < 100 && !global.KyberModule?.HEAPU8; i++) await new Promise(r => setTimeout(r, 50));
                    if (!global.KyberModule?.HEAPU8) throw new Error("Kyber WASM did not initialize");
                    return true;
                });
                global.__dmashAccountCryptoReady = kyberReady;
                void Promise.all([
                    loadScript(`js/vendor/html5-qrcode.min.js?v=${ver}`),
                    loadScript(`js/vendor/qrcode.min.js?v=${ver}`),
                    loadScript(`js/vendor/nacl-util.min.js?v=${ver}`)
                ]).catch(() => {});

                await Promise.all([
                    loadScript(`js/vendor/argon2-bundled.min.js?v=${ver}`),
                    loadScript(`js/device_root.js?v=${ver}`),
                    loadScript(`js/storage.js?v=${ver}`),
                    loadScript(`js/node_manager.js?v=${ver}`),
                    loadScript(`js/core_engine.js?v=${ver}`),
                    loadScript(`js/vendor/nacl-fast.min.js?v=${ver}`)
                ]);

                patchStorage(appStorage());
                patchNodeManager(global.NodeManager);
                patchCore(global.Core);
                void global.NodeManager?.loadOriginList?.("nodes.json").catch(() => {});
                return true;
            } catch (error) {
                console.error("[D-MASH] foundation load failed", error);
                return false;
            }
        };
        global.DMashSys = system;
        Object.defineProperty(system, SYS_PATCH, { value: true });
        return true;
    }

    /* ---------------- WEBAUTHN CREDENTIAL CLEANUP ---------------- */
    async function signalUnknownCredential(credentialIdB64) {
        const fn = global.PublicKeyCredential?.signalUnknownCredential;
        if (typeof fn !== "function") return false;
        try {
            await fn.call(global.PublicKeyCredential, {
                rpId: global.location.hostname,
                credentialId: toB64url(credentialIdB64)
            });
            return true;
        } catch (_) { return false; }
    }

    async function deleteDatabase(name) {
        if (!name) return;
        await new Promise(resolve => {
            const request = indexedDB.deleteDatabase(name);
            request.onsuccess = request.onerror = request.onblocked = () => resolve();
        });
    }

    async function totalRecoveryWipe() {
        try { global.DMashStorage?.db?.close?.(); } catch (_) {}
        try { global.DMashStorage?.registry_instance?.close?.(); } catch (_) {}
        try { global.DeviceRoot?.lock?.(); } catch (_) {}

        const names = new Set(["dm_gamma_vault", LEGACY_DB, SECURE_DB, "dmash_device_root_v1"]);
        try {
            for (const item of await indexedDB.databases?.() || []) if (item?.name) names.add(item.name);
        } catch (_) {}
        await Promise.all(Array.from(names, deleteDatabase));

        try { localStorage.clear(); } catch (_) {}
        try { sessionStorage.clear(); } catch (_) {}
        try { for (const key of await caches.keys()) await caches.delete(key); } catch (_) {}
        try { for (const reg of await navigator.serviceWorker?.getRegistrations?.() || []) await reg.unregister(); } catch (_) {}
        global.location.reload();
    }

    /* ---------------- CORE/UI ACCEPTANCE ---------------- */
    function patchCore(core) {
        if (!core || core[PATCH]) return false;
        const storage = appStorage();
        if (storage) patchStorage(storage);
        patchNodeManager(global.NodeManager);

        // Account boot, unlike Device unlock, actually needs ML-KEM. If it is
        // still preloading, wait here rather than on the calculator screen.
        if (typeof core.boot === "function" && !core.__dmashV51BootCryptoGate) {
            const originalBoot = core.boot.bind(core);
            core.boot = async function accountBootAfterBackgroundCrypto(...args) {
                if (global.__dmashAccountCryptoReady) await global.__dmashAccountCryptoReady;
                return originalBoot(...args);
            };
            Object.defineProperty(core, "__dmashV51BootCryptoGate", { value: true });
        }

        // v50 wrapped a modal that already had Back, producing two buttons.
        if (typeof core.openPendingContacts === "function") {
            const originalPending = core.openPendingContacts.bind(core);
            core.openPendingContacts = async function singleBackPendingContacts(...args) {
                const result = await originalPending(...args);
                const box = document.querySelector("#sys-modal .sys-modal-box");
                if (box) {
                    const backs = Array.from(box.querySelectorAll("button")).filter(button => button.textContent.trim().toUpperCase() === "НАЗАД");
                    backs.slice(1).forEach(button => button.remove());
                }
                return result;
            };
        }

        core.openDeviceBiometricManager = async function deviceBiometricManagerV51() {
            try {
                const record = await global.DeviceRoot?._store?.().get();
                const wraps = Array.isArray(record?.biometricWraps) && record.biometricWraps.length
                    ? record.biometricWraps : (record?.biometricWrap ? [record.biometricWrap] : []);
                const rows = wraps.map((wrap, index) => `
                    <div class="dmash-registry-row">
                        <div class="dmash-registry-id">DEVICE KEY ${index + 1} · ${esc(new Date(wrap.addedAt || 0).toLocaleString())}</div>
                        <div class="dmash-registry-state">${esc(String(wrap.credentialId || "").slice(0, 18))}…</div>
                        <button class="gate-btn danger" onclick="Core.removeDeviceBiometric(${index})">УДАЛИТЬ КЛЮЧ</button>
                    </div>`).join("") || '<div class="dmash-settings-note">Биометрических ключей устройства нет.</div>';
                this.openModal("БИОМЕТРИЯ УСТРОЙСТВА", `
                    <div class="dmash-settings-note">Удаление всегда убирает ключ из D-MASH. Если ОС поддерживает WebAuthn credential signals, ей также передаётся сигнал удалить устаревший credential.</div>
                    <div class="dmash-registry-list">${rows}</div>
                    <button class="dmash-settings-action" onclick="Core.closeModal(); ui.beginBiometricTriggerSetup()">ДОБАВИТЬ КЛЮЧ</button>
                    <button class="dmash-settings-action primary" onclick="Core.closeModal()">НАЗАД</button>`);
            } catch (error) { this.customAlert("БИОМЕТРИЯ УСТРОЙСТВА", error.message); }
        };

        core.removeDeviceBiometric = async function removeDeviceBiometricV51(index) {
            const store = global.DeviceRoot?._store?.();
            if (!store) return;
            const record = await store.get();
            const wraps = Array.isArray(record?.biometricWraps) && record.biometricWraps.length
                ? [...record.biometricWraps] : (record?.biometricWrap ? [record.biometricWrap] : []);
            if (!wraps[index]) return;
            const [removed] = wraps.splice(index, 1);
            const next = { ...record };
            if (wraps.length) {
                next.biometricWraps = wraps;
                next.biometricWrap = wraps[0];
            } else {
                delete next.biometricWraps;
                delete next.biometricWrap;
                try { localStorage.removeItem("cfg_biometric_trigger"); } catch (_) {}
            }
            await store.put(next);
            if (global.DeviceRoot.state) global.DeviceRoot.state.record = next;
            await signalUnknownCredential(removed.credentialId);
            global.location.reload();
        };

        core.removeAccountBiometric = async function removeAccountBiometricV51(id) {
            const account = await storage?.getRegistryAccount?.(id);
            const binding = account?.accountBiometric;
            if (!binding) return;
            await storage.updateAccountAuth(id, { accountBiometric: null, bio: false, lazy: false, lazy_key: null });
            this._accountBiometricCache?.delete?.(id);
            await signalUnknownCredential(binding.credentialId);
            global.location.reload();
        };

        // Extend the registry manager with Account-biometric removal.
        core.openAccountManager = async function secureAccountManagerV51() {
            try {
                const accounts = await storage.getAllRegistryAccounts();
                const rows = accounts.map(account => {
                    const id = encodeURIComponent(account.id);
                    return `<div class="dmash-registry-row">
                        <div class="dmash-registry-id">${esc(account.id)}</div>
                        <div class="dmash-registry-state">${account.accountBiometric ? "BIOMETRIC · " : ""}${account.id === this.activeIdentity ? "ACTIVE" : "LOCAL"}</div>
                        ${account.accountBiometric ? `<button class="gate-btn" onclick="Core.removeAccountBiometric(decodeURIComponent('${id}'))">УДАЛИТЬ БИОМЕТРИЮ</button>` : ""}
                        ${account.id !== this.activeIdentity ? `<button class="gate-btn danger" onclick="Core.removeAccountFlow(decodeURIComponent('${id}'))">УДАЛИТЬ АККАУНТ</button>` : ""}
                    </div>`;
                }).join("") || '<div class="dmash-settings-note">Реестр аккаунтов пуст.</div>';
                this.openModal("РЕЕСТР АККАУНТОВ", `<div class="dmash-registry-list">${rows}</div><button class="dmash-settings-action primary" onclick="Core.closeModal()">НАЗАД</button>`);
            } catch (error) { this.customAlert("РЕЕСТР АККАУНТОВ", error.message); }
        };

        core.totalRecoveryWipe = async function totalRecoveryWipeV51() {
            if (!global.confirm("Удалить ВСЕ локальные данные D-MASH на этом устройстве? Аккаунты, DeviceRoot, Routes, чаты, Node-настройки и биометрические привязки будут удалены.")) return;
            const phrase = global.prompt("Для полного recovery wipe введите: УДАЛИТЬ ВСЁ");
            if (phrase !== "УДАЛИТЬ ВСЁ") return;
            await totalRecoveryWipe();
        };

        Object.defineProperty(core, PATCH, { value: true });
        return true;
    }

    function patchUi(uiObject) {
        if (!uiObject || uiObject[UI_PATCH]) return false;

        // Calculator output and secret input have different bounds. Arithmetic
        // results may be longer than a PIN and are formatted instead of treated
        // as a KDF/resource error.
        uiObject.setCalculatorValue = function calculatorValueV51(value) {
            if (!Number.isFinite(value)) {
                this.curr = "0";
                this.hist = Number.isNaN(value) ? "ОШИБКА ВЫЧИСЛЕНИЯ" : "ОШИБКА ДЕЛЕНИЯ НА НОЛЬ";
                this.op = null; this.leftOperand = null;
                return false;
            }
            let next = String(value);
            if (next.length > 16) {
                next = Math.abs(value) >= 1e15 || (Math.abs(value) > 0 && Math.abs(value) < 1e-9)
                    ? value.toExponential(8)
                    : Number(value.toPrecision(12)).toString();
            }
            this.curr = next;
            return true;
        };
        if (typeof uiObject.eval === "function") {
            const originalEval = uiObject.eval.bind(uiObject);
            uiObject.eval = async function calculatorEvalPaintV51(...args) {
                const hadOperator = !!this.op;
                const beforeMode = this.mode;
                const result = await originalEval(...args);
                if (beforeMode === 0 && hadOperator) this.update();
                return result;
            };
        }

        // Add recovery + credential management without replacing the existing
        // device-scoped Global Settings layout.
        if (typeof uiObject.renderGlobalSettings === "function") {
            const originalGlobal = uiObject.renderGlobalSettings.bind(uiObject);
            uiObject.renderGlobalSettings = function globalSettingsV51(...args) {
                const result = originalGlobal(...args);
                const list = document.querySelector(".gate-container .dmash-settings-list") || document.querySelector(".gate-container div[style*='display:grid']");
                if (list && !document.getElementById("dmash-biometric-manager-button")) {
                    const bio = document.createElement("button");
                    bio.id = "dmash-biometric-manager-button";
                    bio.className = "dmash-settings-card";
                    bio.innerHTML = "<b>УПРАВЛЕНИЕ БИОМЕТРИЕЙ</b><small>Удаление старых Device credentials и синхронизация с ОС</small>";
                    bio.onclick = () => global.Core?.openDeviceBiometricManager?.();
                    list.appendChild(bio);

                    const wipe = document.createElement("button");
                    wipe.id = "dmash-total-recovery-wipe";
                    wipe.className = "dmash-settings-card dmash-danger-card";
                    wipe.innerHTML = "<b>ПОЛНОЕ УДАЛЕНИЕ ДАННЫХ</b><small>Recovery wipe: DeviceRoot, аккаунты, Routes, чаты, Nodes, кэши</small>";
                    wipe.onclick = () => global.Core?.totalRecoveryWipe?.();
                    list.appendChild(wipe);
                }
                return result;
            };
        }

        Object.defineProperty(uiObject, UI_PATCH, { value: true });
        return true;
    }

    function install() {
        const system = appSys();
        if (system) patchSystem(system);
        const storage = appStorage();
        if (storage && global.DeviceRoot?.state?.root) patchStorage(storage);
        patchNodeManager(global.NodeManager);
        patchCore(global.Core);
        patchUi(appUi());
    }

    install();
    const timer = setInterval(() => {
        install();
        if (appSys()?.[SYS_PATCH] && appUi()?.[UI_PATCH] && global.Core?.[PATCH] && global.NodeManager?.[NODE_PATCH]) clearInterval(timer);
    }, 40);
    setTimeout(() => clearInterval(timer), 30000);
})(window);
