"use strict";

/*
 * DeviceRoot is a local installation secret, distinct from Accounts and their
 * vaults.  It is created with Web Crypto CSPRNG, persisted only encrypted under
 * a master-PIN-hardened wrapping key, and never serialised into network data.
 *
 * KDF encoding (v1):
 *   info = u32be(version) || u32be(len(domain UTF-8)) || domain UTF-8
 *          || u32be(len(context UTF-8)) || context UTF-8
 *   HKDF-SHA-256(ikm=DeviceRoot, salt=32 zero octets, info=above, L=32)
 */
(function (global) {
    const DB_NAME = "dmash_device_root_v1";
    const STORE = "device_root";
    const RECORD_KEY = "root";
    const VERSION = 1;
    const ROOT_BYTES = 32;
    const WRAP_SALT_BYTES = 16;
    const AAD = new TextEncoder().encode("dmash/device-root-wrap/v1");
    const ZERO_SALT = new Uint8Array(32);

    const utf8 = (value) => new TextEncoder().encode(value);
    const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
    const unb64 = (value) => new Uint8Array(atob(value).split("").map((char) => char.charCodeAt(0)));
    const u32 = (value) => {
        const bytes = new Uint8Array(4);
        new DataView(bytes.buffer).setUint32(0, value, false);
        return bytes;
    };
    const join = (...parts) => {
        const length = parts.reduce((total, part) => total + part.length, 0);
        const result = new Uint8Array(length);
        let offset = 0;
        for (const part of parts) { result.set(part, offset); offset += part.length; }
        return result;
    };

    class DeviceRootError extends Error {
        constructor(code, message) { super(message); this.name = "DeviceRootError"; this.code = code; }
    }

    class IndexedDbDeviceRootStore {
        constructor(indexedDb = global.indexedDB) { this.indexedDb = indexedDb; this.db = null; }
        async open() {
            if (this.db) return this.db;
            if (!this.indexedDb) throw new DeviceRootError("STORAGE_UNAVAILABLE", "Device identity storage is unavailable; recovery is required.");
            this.db = await new Promise((resolve, reject) => {
                const request = this.indexedDb.open(DB_NAME, VERSION);
                request.onupgradeneeded = () => {
                    const db = request.result;
                    if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "id" });
                };
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(new DeviceRootError("STORAGE_UNAVAILABLE", "Device identity storage could not be opened."));
                request.onblocked = () => reject(new DeviceRootError("STORAGE_BLOCKED", "Device identity storage is blocked by another session."));
            });
            return this.db;
        }
        async get() {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const request = db.transaction(STORE, "readonly").objectStore(STORE).get(RECORD_KEY);
                request.onsuccess = () => resolve(request.result || null);
                request.onerror = () => reject(new DeviceRootError("STORAGE_CORRUPT", "Device identity storage cannot be read."));
            });
        }
        async put(record) {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const tx = db.transaction(STORE, "readwrite");
                tx.objectStore(STORE).put(record);
                tx.oncomplete = resolve;
                tx.onerror = () => reject(new DeviceRootError("STORAGE_WRITE_FAILED", "Device identity storage could not be saved."));
                tx.onabort = () => reject(new DeviceRootError("STORAGE_WRITE_FAILED", "Device identity storage write was aborted."));
            });
        }
    }

    const DeviceRoot = {
        VERSION,
        domains: Object.freeze({
            identityEd25519: "dmash/device-identity-ed25519",
            identityX25519: "dmash/device-identity-x25519",
            storage: "dmash/device-storage",
            pairing: "dmash/device-pairing",
            routing: "dmash/device-routing",
            transportAuth: "dmash/device-transport-auth",
            mlKemSeedRoot: "dmash/device-mlkem-seed-root"
        }),
        store: null,
        state: null,
        _crypto: global.crypto,

        setStoreForTests(store) { this.store = store; },
        resetForTests() { this.store = null; this.state = null; },
        _store() { return this.store || (this.store = new IndexedDbDeviceRootStore()); },
        _requireCrypto() {
            if (!this._crypto?.getRandomValues || !this._crypto?.subtle) throw new DeviceRootError("CRYPTO_UNAVAILABLE", "Web Crypto is required for device identity.");
        },
        canonicalInfo(domain, version = VERSION, context = "") {
            if (typeof domain !== "string" || !domain || typeof context !== "string" || !Number.isInteger(version) || version < 1) {
                throw new DeviceRootError("INVALID_KDF_INPUT", "Invalid DeviceRoot KDF domain, version, or context.");
            }
            const domainBytes = utf8(domain);
            const contextBytes = utf8(context);
            return join(u32(version), u32(domainBytes.length), domainBytes, u32(contextBytes.length), contextBytes);
        },
        async derive(root, domain, version = VERSION, context = "") {
            this._requireCrypto();
            const bytes = root instanceof Uint8Array ? root : new Uint8Array(root);
            if (bytes.length !== ROOT_BYTES) throw new DeviceRootError("INVALID_ROOT", "DeviceRoot must contain exactly 256 bits.");
            const base = await this._crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveBits"]);
            const bits = await this._crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info: this.canonicalInfo(domain, version, context) }, base, 256);
            return new Uint8Array(bits);
        },
        async _wrapKey(masterPin, salt) {
            if (typeof masterPin !== "string" || !masterPin) throw new DeviceRootError("MASTER_PIN_REQUIRED", "A calculator master PIN is required to unlock this device.");
            if (!global.argon2?.hash) throw new DeviceRootError("ARGON2_UNAVAILABLE", "Password hardening is unavailable; device identity was not changed.");
            const result = await global.argon2.hash({
                pass: masterPin,
                salt: b64(salt),
                time: 3,
                mem: 65536,
                hashLen: 32,
                type: global.argon2.argon2id
            });
            return this._crypto.subtle.importKey("raw", result.hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        },
        async _encryptRoot(root, masterPin, salt) {
            const iv = this._crypto.getRandomValues(new Uint8Array(12));
            const key = await this._wrapKey(masterPin, salt);
            const ciphertext = await this._crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, root);
            return { iv: b64(iv), wrappedRoot: b64(new Uint8Array(ciphertext)) };
        },
        async _decryptRoot(record, masterPin) {
            try {
                const salt = unb64(record.wrapSalt);
                const key = await this._wrapKey(masterPin, salt);
                const plaintext = await this._crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(record.iv), additionalData: AAD }, key, unb64(record.wrappedRoot));
                const root = new Uint8Array(plaintext);
                if (root.length !== ROOT_BYTES) throw new Error("invalid root length");
                return root;
            } catch (error) {
                if (error instanceof DeviceRootError) throw error;
                throw new DeviceRootError("UNLOCK_FAILED", "Device identity could not be unlocked. It was not replaced.");
            }
        },
        async deviceIdentity(root) {
            const edSeed = await this.derive(root, this.domains.identityEd25519, VERSION, "");
            const xSeed = await this.derive(root, this.domains.identityX25519, VERSION, "");
            if (!global.nacl?.sign?.keyPair?.fromSeed || !global.nacl?.box?.keyPair?.fromSecretKey) {
                throw new DeviceRootError("NACL_UNAVAILABLE", "Device identity primitives are unavailable.");
            }
            const signing = global.nacl.sign.keyPair.fromSeed(edSeed);
            const agreement = global.nacl.box.keyPair.fromSecretKey(xSeed);
            const idDigest = new Uint8Array(await this._crypto.subtle.digest("SHA-256", join(utf8("dmash/device-id/v1"), signing.publicKey, agreement.publicKey)));
            return Object.freeze({
                // DeviceID is public/pseudonymous: SHA-256 over public keys and a
                // protocol label, never a hash of DeviceRoot.
                deviceId: "d1_" + b64(idDigest).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""),
                signing,
                agreement,
                fingerprints: Object.freeze({ signing: b64(signing.publicKey), agreement: b64(agreement.publicKey) })
            });
        },
        async _legacyVaultExists() {
            // A missing DeviceRoot must not silently overwrite an established
            // Gamma installation.  `databases()` is the only non-mutating
            // IndexedDB inventory API; without it, migration is deliberately
            // blocked rather than guessing from a newly-created database.
            if (typeof this._store().indexedDb?.databases !== "function") {
                throw new DeviceRootError("MIGRATION_DETECTION_UNAVAILABLE", "Cannot safely detect a legacy vault; device migration is required.");
            }
            const databases = await this._store().indexedDb.databases();
            return databases.some((database) => database.name === "dm_gamma_vault");
        },
        async deviceMaterial(name, create) {
            if (!this.state?.root || typeof name !== "string" || !name || typeof create !== "function") {
                throw new DeviceRootError("DEVICE_LOCKED", "Device identity must be unlocked before accessing device key material.");
            }
            const materials = this.state.record.materials || {};
            const domainRoot = await this.derive(this.state.root, this.domains.mlKemSeedRoot, VERSION, name);
            const key = await this._crypto.subtle.importKey("raw", domainRoot, "AES-GCM", false, ["encrypt", "decrypt"]);
            const materialAad = utf8("dmash/device-material/v1|" + name);
            if (materials[name]) {
                try {
                    const plaintext = await this._crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(materials[name].iv), additionalData: materialAad }, key, unb64(materials[name].ciphertext));
                    return new Uint8Array(plaintext);
                } catch (_) {
                    throw new DeviceRootError("STORAGE_CORRUPT", "Device key material is corrupt. It was not regenerated.");
                }
            }
            const created = await create();
            const bytes = created instanceof Uint8Array ? created : new Uint8Array(created);
            const iv = this._crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await this._crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: materialAad }, key, bytes);
            this.state.record.materials = { ...materials, [name]: { iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) } };
            await this._store().put(this.state.record);
            return bytes;
        },
        async unlock(masterPin) {
            this._requireCrypto();
            const store = this._store();
            let record;
            try { record = await store.get(); }
            catch (error) { throw error instanceof DeviceRootError ? error : new DeviceRootError("STORAGE_UNAVAILABLE", "Device identity storage cannot be read; recovery is required."); }
            let root;
            let created = false;
            if (record) {
                if (record.version !== VERSION || !record.wrapSalt || !record.iv || !record.wrappedRoot) {
                    throw new DeviceRootError("STORAGE_CORRUPT", "Device identity record is corrupt or unsupported. It was not replaced.");
                }
                root = await this._decryptRoot(record, masterPin);
            } else {
                if (await this._legacyVaultExists()) {
                    throw new DeviceRootError("LEGACY_MIGRATION_REQUIRED", "A legacy Account-derived vault exists. DeviceRoot was not created; migrate explicitly before changing identity.");
                }
                root = this._crypto.getRandomValues(new Uint8Array(ROOT_BYTES));
                const wrapSalt = this._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
                const wrapped = await this._encryptRoot(root, masterPin, wrapSalt);
                record = { id: RECORD_KEY, version: VERSION, wrapSalt: b64(wrapSalt), materials: {}, ...wrapped };
                try { await store.put(record); }
                catch (error) { root.fill(0); throw error instanceof DeviceRootError ? error : new DeviceRootError("STORAGE_WRITE_FAILED", "Device identity was not persisted and was discarded."); }
                created = true;
            }
            const identity = await this.deviceIdentity(root);
            this.state = { root, identity, created, record };
            return this.state;
        },
        async bootstrap(masterPin) {
            try {
                return await this.unlock(masterPin);
            } catch (error) {
                if (error instanceof DeviceRootError && error.code === "LEGACY_MIGRATION_REQUIRED") {
                    // Legacy Account identities remain usable until an explicit
                    // cryptographic migration/recovery flow is specified.
                    return Object.freeze({ legacy: true, migrationRequired: true, created: false, identity: null });
                }
                throw error;
            }
        },
        lock() {
            if (this.state?.root) this.state.root.fill(0);
            this.state = null;
        }
    };

    global.DeviceRoot = DeviceRoot;
    global.DeviceRootError = DeviceRootError;
    global.IndexedDbDeviceRootStore = IndexedDbDeviceRootStore;
    if (typeof module !== "undefined") module.exports = { DeviceRoot, DeviceRootError, IndexedDbDeviceRootStore };
})(typeof window !== "undefined" ? window : globalThis);
