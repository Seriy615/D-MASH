"use strict";

/*
 * D-MASH browser acceptance fixes v52.
 *
 * Canonical fix for the installation-scoped Account registry:
 * - the registry key lives only as DeviceRoot-protected device material;
 * - IndexedDB stores only HMAC aliases + AES-GCM ciphertext;
 * - no crypto await occurs inside a live IndexedDB transaction;
 * - legacy plaintext rows are deleted only AFTER encrypted commit succeeds;
 * - Global Settings remains reachable even when the registry is empty.
 */
(function installAcceptanceV52(global) {
    const PATCH = "__dmashSecureRegistryV2";
    const V51_STORAGE_PATCH = "__dmashSecureRegistryV1";
    const UI_PATCH = "__dmashAcceptanceV52Ui";

    const SECURE_DB = "dm_registry_secure_v1";
    const LEGACY_DB = "dm_registry_v1";
    const DB_VERSION = 1;
    const ACCOUNTS = "accounts";
    const META = "meta";
    const MATERIAL_NAME = "account-registry-v1";
    const AAD = new TextEncoder().encode("dmash/account-registry/v1");

    const utf8 = value => new TextEncoder().encode(String(value));
    const decode = bytes => new TextDecoder().decode(bytes);
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const unb64 = value => Uint8Array.from(atob(String(value)), ch => ch.charCodeAt(0));

    function appStorage() {
        try {
            if (typeof Storage !== "undefined" && Storage && typeof Storage.getAllRegistryAccounts === "function") return Storage;
        } catch (_) {}
        return global.DMashStorage || null;
    }

    function appUi() {
        try { if (typeof ui !== "undefined" && ui) return ui; } catch (_) {}
        return global.ui || null;
    }

    function requestResult(request) {
        return new Promise((resolve, reject) => {
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error || new Error("IndexedDB request failed"));
        });
    }

    function transactionDone(tx) {
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error || new Error("IndexedDB transaction failed"));
            tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
        });
    }

    let secureDbPromise = null;
    let registryKeysPromise = null;
    let migrationPromise = null;

    async function openSecureDb() {
        if (secureDbPromise) return secureDbPromise;
        secureDbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(SECURE_DB, DB_VERSION);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains(ACCOUNTS)) db.createObjectStore(ACCOUNTS, { keyPath: "alias" });
                if (!db.objectStoreNames.contains(META)) db.createObjectStore(META, { keyPath: "key" });
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error || new Error("Secure Account registry could not be opened"));
        });
        return secureDbPromise;
    }

    async function registryKeys() {
        if (registryKeysPromise) return registryKeysPromise;
        registryKeysPromise = (async () => {
            if (!global.DeviceRoot?.state?.root || typeof global.DeviceRoot.deviceMaterial !== "function") {
                throw new Error("DeviceRoot must be unlocked before Account registry access.");
            }
            const raw = await global.DeviceRoot.deviceMaterial(
                MATERIAL_NAME,
                () => crypto.getRandomValues(new Uint8Array(32))
            );
            if (!(raw instanceof Uint8Array) || raw.length !== 32) throw new Error("Account registry key material is invalid.");
            try {
                const aes = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
                const hmac = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
                return { aes, hmac };
            } finally {
                raw.fill(0);
            }
        })();
        try { return await registryKeysPromise; }
        catch (error) { registryKeysPromise = null; throw error; }
    }

    async function aliasFor(id) {
        const { hmac } = await registryKeys();
        return b64(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, utf8(id))));
    }

    async function sealRecord(record) {
        const { aes } = await registryKeys();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: AAD },
            aes,
            utf8(JSON.stringify(record))
        ));
        const packed = new Uint8Array(iv.length + ciphertext.length);
        packed.set(iv, 0);
        packed.set(ciphertext, iv.length);
        return b64(packed);
    }

    async function openRecord(blob) {
        const { aes } = await registryKeys();
        const packed = unb64(blob);
        if (packed.length <= 28) throw new Error("Encrypted Account registry record is corrupt.");
        const clear = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: packed.slice(0, 12), additionalData: AAD },
            aes,
            packed.slice(12)
        );
        const record = JSON.parse(decode(new Uint8Array(clear)));
        if (!record || typeof record !== "object" || typeof record.id !== "string" || !record.id) {
            throw new Error("Encrypted Account registry record is invalid.");
        }
        return record;
    }

    async function databaseExists(name) {
        try {
            if (typeof indexedDB.databases !== "function") return true;
            const dbs = await indexedDB.databases();
            return dbs.some(db => db?.name === name);
        } catch (_) {
            return true;
        }
    }

    async function readLegacyRows(storage) {
        try { storage.registry_instance?.close?.(); } catch (_) {}
        storage.registry_instance = null;
        if (!(await databaseExists(LEGACY_DB))) return [];

        return new Promise(resolve => {
            const open = indexedDB.open(LEGACY_DB);
            open.onerror = () => resolve([]);
            open.onupgradeneeded = () => {};
            open.onsuccess = async () => {
                const db = open.result;
                try {
                    if (!db.objectStoreNames.contains(ACCOUNTS)) {
                        db.close();
                        return resolve([]);
                    }
                    const tx = db.transaction(ACCOUNTS, "readonly");
                    const rows = await requestResult(tx.objectStore(ACCOUNTS).getAll()).catch(() => []);
                    await transactionDone(tx).catch(() => {});
                    db.close();
                    resolve(Array.isArray(rows) ? rows : []);
                } catch (_) {
                    try { db.close(); } catch (_) {}
                    resolve([]);
                }
            };
        });
    }

    async function purgeLegacy(storage) {
        try { storage.registry_instance?.close?.(); } catch (_) {}
        storage.registry_instance = null;
        if (!(await databaseExists(LEGACY_DB))) return;

        await new Promise(resolve => {
            const open = indexedDB.open(LEGACY_DB);
            open.onerror = () => resolve();
            open.onupgradeneeded = () => {};
            open.onsuccess = async () => {
                const db = open.result;
                try {
                    if (db.objectStoreNames.contains(ACCOUNTS)) {
                        const tx = db.transaction(ACCOUNTS, "readwrite");
                        tx.objectStore(ACCOUNTS).clear();
                        await transactionDone(tx).catch(() => {});
                    }
                } finally {
                    try { db.close(); } catch (_) {}
                    resolve();
                }
            };
        });

        await new Promise(resolve => {
            const del = indexedDB.deleteDatabase(LEGACY_DB);
            del.onsuccess = del.onerror = del.onblocked = () => resolve();
        });
    }

    async function readMeta(key) {
        const db = await openSecureDb();
        const tx = db.transaction(META, "readonly");
        const result = await requestResult(tx.objectStore(META).get(key));
        await transactionDone(tx).catch(() => {});
        return result;
    }

    async function writeMeta(value) {
        const db = await openSecureDb();
        const tx = db.transaction(META, "readwrite");
        tx.objectStore(META).put(value);
        await transactionDone(tx);
    }

    async function ensureMigrated(storage) {
        if (migrationPromise) return migrationPromise;
        migrationPromise = (async () => {
            await registryKeys();
            await openSecureDb();

            const marker = await readMeta("legacy-migrated").catch(() => null);
            if (marker?.done) {
                // Retry plaintext cleanup on every open in case an old tab had
                // previously blocked deleteDatabase().
                await purgeLegacy(storage).catch(() => {});
                return;
            }

            const legacy = await readLegacyRows(storage);

            // IMPORTANT: all HMAC/AES work finishes BEFORE a write transaction
            // is created. IndexedDB may auto-commit while JS awaits WebCrypto.
            const encryptedRows = [];
            for (const record of legacy) {
                if (!record?.id) continue;
                encryptedRows.push({
                    alias: await aliasFor(record.id),
                    blob: await sealRecord(record)
                });
            }

            if (encryptedRows.length) {
                const db = await openSecureDb();
                const tx = db.transaction(ACCOUNTS, "readwrite");
                const store = tx.objectStore(ACCOUNTS);
                for (const row of encryptedRows) store.put(row);
                await transactionDone(tx);

                // Verify the encrypted commit before touching plaintext.
                const verifyTx = db.transaction(ACCOUNTS, "readonly");
                const persisted = await requestResult(verifyTx.objectStore(ACCOUNTS).getAll());
                await transactionDone(verifyTx).catch(() => {});
                const aliases = new Set((persisted || []).map(row => row?.alias));
                if (!encryptedRows.every(row => aliases.has(row.alias))) {
                    throw new Error("Encrypted Account registry migration verification failed.");
                }
            }

            await writeMeta({ key: "legacy-migrated", done: true, at: Date.now() });

            // Only now is the old plaintext registry eligible for deletion.
            await purgeLegacy(storage).catch(() => {});
        })();
        try { return await migrationPromise; }
        catch (error) { migrationPromise = null; throw error; }
    }

    async function putEncryptedRecord(record) {
        const alias = await aliasFor(record.id);
        const blob = await sealRecord(record);
        const db = await openSecureDb();
        const tx = db.transaction(ACCOUNTS, "readwrite");
        tx.objectStore(ACCOUNTS).put({ alias, blob });
        await transactionDone(tx);
    }

    function patchStorage(storage) {
        if (!storage) return false;
        if (storage.getAllRegistryAccounts?.__dmashV52 === true) return true;

        // Prevent v51's old migration implementation from being installed later
        // if this patch wins the lazy-load race.
        if (!storage[V51_STORAGE_PATCH]) {
            try { Object.defineProperty(storage, V51_STORAGE_PATCH, { value: true }); } catch (_) {}
        }

        storage.openRegistry = async function encryptedRegistryOpenV52() {
            await ensureMigrated(storage);
            return openSecureDb();
        };

        storage.getAllRegistryAccounts = async function encryptedRegistryListV52() {
            await ensureMigrated(storage);
            const db = await openSecureDb();
            const tx = db.transaction(ACCOUNTS, "readonly");
            const rows = await requestResult(tx.objectStore(ACCOUNTS).getAll());
            await transactionDone(tx).catch(() => {});
            const records = [];
            for (const row of rows || []) {
                try { records.push(await openRecord(row.blob)); }
                catch (error) { console.warn("[D-MASH] encrypted registry row skipped:", error?.message || error); }
            }
            return records;
        };
        storage.getAllRegistryAccounts.__dmashV52 = true;

        storage.getRegistryAccount = async function encryptedRegistryGetV52(id) {
            await ensureMigrated(storage);
            const alias = await aliasFor(id);
            const db = await openSecureDb();
            const tx = db.transaction(ACCOUNTS, "readonly");
            const row = await requestResult(tx.objectStore(ACCOUNTS).get(alias));
            await transactionDone(tx).catch(() => {});
            return row?.blob ? openRecord(row.blob) : undefined;
        };

        storage.registerAccount = async function encryptedRegistryRegisterV52(identity, pubHex) {
            await ensureMigrated(storage);
            const current = await storage.getRegistryAccount(identity) || { id: identity, notified: false };
            current.id = identity;
            current.pk = pubHex;
            await putEncryptedRecord(current);
        };

        storage.updateAccountAuth = async function encryptedRegistryUpdateV52(id, params) {
            await ensureMigrated(storage);
            const current = await storage.getRegistryAccount(id) || { id };
            Object.assign(current, params || {});
            await putEncryptedRecord(current);
        };

        storage.removeAccountFromRegistry = async function encryptedRegistryRemoveV52(id) {
            await ensureMigrated(storage);
            const alias = await aliasFor(id);
            const db = await openSecureDb();
            const tx = db.transaction(ACCOUNTS, "readwrite");
            tx.objectStore(ACCOUNTS).delete(alias);
            await transactionDone(tx);
        };

        storage.REGISTRY_DB = SECURE_DB;
        try { storage.registry_instance?.close?.(); } catch (_) {}
        storage.registry_instance = null;
        global.DMashStorage = storage;
        try { Object.defineProperty(storage, PATCH, { value: true }); }
        catch (_) { storage[PATCH] = true; }
        return true;
    }

    function patchUi(uiObject) {
        if (!uiObject || uiObject[UI_PATCH]) return false;
        const originalLogin = typeof uiObject.renderLoginForm === "function"
            ? uiObject.renderLoginForm.bind(uiObject)
            : null;

        if (originalLogin) {
            uiObject.renderLoginForm = function loginWithGlobalSettingsV52(...args) {
                const result = originalLogin(...args);
                const box = document.querySelector(".gate-container");
                if (box && global.DeviceRoot?.state?.root && !document.getElementById("global-settings-button")) {
                    const row = document.createElement("div");
                    row.className = "dmash-selector-head";
                    row.style.marginBottom = "10px";
                    row.innerHTML = '<div style="font-size:.68rem;color:#888">DEVICE UNLOCKED</div><button id="global-settings-button" class="gate-btn" type="button" style="width:auto;min-width:0;margin:0;padding:5px 9px" onclick="ui.renderGlobalSettings()">⚙</button>';
                    box.prepend(row);
                }
                return result;
            };
        }

        try { Object.defineProperty(uiObject, UI_PATCH, { value: true }); }
        catch (_) { uiObject[UI_PATCH] = true; }
        return true;
    }

    function install() {
        patchStorage(appStorage());
        patchUi(appUi());
    }

    install();
    // v51 also has a lazy installer. Keep v52 alive slightly longer so the
    // secure implementation always wins regardless of which timer observes
    // storage.js first during calculator unlock.
    const timer = setInterval(install, 25);
    setTimeout(() => clearInterval(timer), 35000);
})(window);
