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
    const WRAP_KEY_BYTES = 32;
    const WRAP_IV_BYTES = 12;
    const GCM_TAG_BYTES = 16;
    const AAD = new TextEncoder().encode("dmash/device-root-wrap/v1");
    const WRAP_V2 = "argon2id-aes-256-gcm-v2";
    const WRAP_PROFILE = Object.freeze({ algorithm: "argon2id", version: 19, type: 2, time: 3, mem: 65536, parallelism: 1, hashLen: 32, saltEncoding: "base64-utf8" });
    const AAD_V2 = new TextEncoder().encode("dmash/device-root-wrap/v2");
    const credentialProof = record => { validateCredentialRecord(record); return record ? JSON.stringify([record.credentialRevision ?? 0, record.wrap || null, record.wrapKdf || null, record.wrapSalt, record.iv, record.wrappedRoot, record.credentials || null]) : null; };
    const stale = () => new DeviceRootError("CREDENTIAL_CONFLICT", "Local credentials changed; retry with the current credential.");
    const preparedRoots = new WeakMap();
    const erasePrepared = value => {
        for (const bytes of [value?.root, value?.identity?.signing?.secretKey, value?.identity?.agreement?.secretKey]) bytes?.fill(0);
        if (value) value.disposed = true;
    };
    const makePrepared = (owner, value) => {
        const handle = Object.freeze({ identity: Object.freeze({ deviceId: value.identity.deviceId }), dispose: () => { erasePrepared(value); owner._prepared.delete(value); } });
        preparedRoots.set(handle, value); owner._prepared.add(value); return handle;
    };
    const preparedValue = (owner, handle) => {
        const value = preparedRoots.get(handle);
        if (!value || value.disposed || value.epoch !== owner._epoch || value.store !== owner._store() || value.signal?.aborted) {
            erasePrepared(value); throw new DeviceRootError("DEVICE_LOCKED", "Prepared credential operation is no longer current.");
        }
        return value;
    };
    const PRF_WRAP = "webauthn-prf-aes-256-gcm-v1";
    const PRF_AAD = new TextEncoder().encode("dmash/device-root-webauthn-prf-wrap/v1");
    const PRF_SALT_BYTES = 32;
    const PRF_OUTPUT_BYTES = 32;
    const ZERO_SALT = new Uint8Array(32);

    const utf8 = (value) => new TextEncoder().encode(value);
    const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
    const unb64 = (value) => new Uint8Array(atob(value).split("").map((char) => char.charCodeAt(0)));
    const decodeB64 = (value, length) => {
        if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("invalid base64");
        const bytes = unb64(value);
        // Reject non-canonical encodings so persisted cryptographic fields have
        // one representation and malformed records cannot be interpreted leniently.
        if (b64(bytes) !== value || (length !== undefined && bytes.length !== length)) throw new Error("invalid encoded length");
        return bytes;
    };
    const validateCredentialRecord = record => {
        if (!record) return;
        const revision = record.credentialRevision;
        if (revision !== undefined && (!Number.isSafeInteger(revision) || revision < 0)) throw new DeviceRootError("STORAGE_CORRUPT", "Invalid credential revision.");
        const c = record.credentials;
        if (c === undefined) return; // Explicit legacy absence, not an unknown profile.
        if (!c || typeof c !== "object" || Array.isArray(c) || c.version !== 1 || !["ready", "pending-wipe"].includes(c.state) || !["required", "complete"].includes(c.legacyCleanup) || !Number.isSafeInteger(revision) || revision < 1 || Object.keys(c).some(key => !["version", "state", "legacyCleanup", "wipe", "wipeDisabledReason"].includes(key))) throw new DeviceRootError("STORAGE_CORRUPT", "Unsupported local credential structure.");
        if (c.state === "pending-wipe") {
            if (c.wipe !== undefined || c.legacyCleanup !== "complete" || c.wipeDisabledReason !== undefined) throw new DeviceRootError("STORAGE_CORRUPT", "Invalid pending setup structure.");
            return;
        }
        if (!Object.prototype.hasOwnProperty.call(c, "wipe")) throw new DeviceRootError("STORAGE_CORRUPT", "Missing wipe policy.");
        if (c.wipe === null) {
            if (!["legacy-collision", "not-configured"].includes(c.wipeDisabledReason)) throw new DeviceRootError("STORAGE_CORRUPT", "Missing disabled-wipe reason.");
        } else {
            const w = c.wipe;
            if (!w || w.profile !== "sha256-prehash-argon2id-v1" || Object.keys(w).some(key => !["profile", "salt", "digest"].includes(key)) || (c.wipeDisabledReason !== undefined && c.wipeDisabledReason !== null)) throw new DeviceRootError("STORAGE_CORRUPT", "Unsupported wipe credential structure.");
            try { decodeB64(w.salt, 16); decodeB64(w.digest, 32); } catch (_) { throw new DeviceRootError("STORAGE_CORRUPT", "Invalid wipe credential encoding."); }
        }
    };
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
        constructor(indexedDb = global.indexedDB) { this.indexedDb = indexedDb; this.db = null; this.invalidated = false; this.onInvalidated = null; }
        async open() {
            if (this.invalidated) throw new DeviceRootError("ROOT_STORE_INVALIDATED", "Installation storage was deleted or changed in another context; reload is required.");
            if (this.db) return this.db;
            if (!this.indexedDb) throw new DeviceRootError("STORAGE_UNAVAILABLE", "Device identity storage is unavailable; recovery is required.");
            this.db = await new Promise((resolve, reject) => {
                const request = this.indexedDb.open(DB_NAME, VERSION);
                request.onupgradeneeded = () => {
                    const db = request.result;
                    if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "id" });
                };
                request.onsuccess = () => { const db = request.result; db.onversionchange = () => { this.invalidated = true; db.close(); if (this.db === db) this.db = null; this.onInvalidated?.(); }; resolve(db); };
                request.onerror = () => reject(new DeviceRootError("STORAGE_UNAVAILABLE", "Device identity storage could not be opened."));
                request.onblocked = () => reject(new DeviceRootError("STORAGE_BLOCKED", "Device identity storage is blocked by another session."));
            });
            return this.db;
        }
        async get(id = RECORD_KEY) {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const request = db.transaction(STORE, "readonly").objectStore(STORE).get(id);
                request.onsuccess = () => resolve(request.result || null);
                request.onerror = () => reject(new DeviceRootError("STORAGE_CORRUPT", "Device identity storage cannot be read."));
            });
        }
        async _write(update, { assertCurrent = () => {}, signal } = {}) {
            assertCurrent(); const db = await this.open(); assertCurrent();
            if (signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled.");
            return new Promise((resolve, reject) => {
                const tx = db.transaction(STORE, "readwrite"); let result, failure;
                const cancel = () => { try { tx.abort(); } catch (_) {} };
                const cleanup = () => signal?.removeEventListener("abort", cancel);
                signal?.addEventListener("abort", cancel, { once: true });
                tx.oncomplete = () => { cleanup(); resolve(result); };
                tx.onerror = tx.onabort = () => { cleanup(); reject(failure || new DeviceRootError(signal?.aborted ? "DEVICE_LOCKED" : "STORAGE_WRITE_FAILED", "Device identity storage write did not complete.")); };
                try {
                    const request = tx.objectStore(STORE).get(update.id || RECORD_KEY);
                    request.onsuccess = () => {
                        try { assertCurrent(); if (signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled."); result = update(request.result || null); tx.objectStore(STORE).put(result); }
                        catch (error) { failure = error; cancel(); }
                    };
                } catch (error) { failure = error; cancel(); }
            });
        }
        async put(record, options = {}) {
            const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
            const expected = options.expected;
            const update = current => {
                if (record.id !== RECORD_KEY) return record;
                validateCredentialRecord(record); validateCredentialRecord(current); validateCredentialRecord(expected);
                if (!current) { if (expected) throw stale(); return record; }
                if (!expected) { if (equal(current, record)) return current; throw stale(); }
                if (credentialProof(current) !== credentialProof(expected) || credentialProof(record) !== credentialProof(expected)) throw stale();
                const result = { ...current, materials: { ...current.materials } };
                // Compare only slots this writer changed; unrelated concurrent
                // metadata additions survive. Conflicting random identity or
                // biometric writes must retry, never overwrite the winner.
                for (const key of new Set([...Object.keys(expected), ...Object.keys(record)])) {
                    if (key === "materials" || equal(expected[key], record[key])) continue;
                    if (!equal(current[key], expected[key])) throw stale();
                    if (Object.prototype.hasOwnProperty.call(record, key)) result[key] = record[key]; else delete result[key];
                }
                for (const key of new Set([...Object.keys(expected.materials || {}), ...Object.keys(record.materials || {})])) {
                    if (equal(expected.materials?.[key], record.materials?.[key])) continue;
                    if (!equal(current.materials?.[key], expected.materials?.[key])) throw stale();
                    if (!Object.prototype.hasOwnProperty.call(record.materials || {}, key)) throw new DeviceRootError("INVALID_MATERIAL_DELETE", "Material deletion requires explicit wipe.");
                    result.materials[key] = record.materials[key];
                }
                return result;
            };
            update.id = record.id;
            await this._write(update, options);
        }
        async compareAndSwap(expected, patch, options = {}) {
            // Read, compare and merge in ONE native IDB transaction. Never use
            // an await between the read callback and its write.
            return this._write(current => {
                if (credentialProof(current) !== credentialProof(expected)) throw stale();
                if (options.biometricBinding) {
                    const wraps = Array.isArray(current?.biometricWraps) && current.biometricWraps.length ? current.biometricWraps : (current?.biometricWrap ? [current.biometricWrap] : []);
                    if (!wraps.some(wrap => JSON.stringify(wrap) === options.biometricBinding)) throw stale();
                }
                const revision = current?.credentialRevision ?? 0;
                if (revision >= Number.MAX_SAFE_INTEGER || !Number.isSafeInteger(patch.credentialRevision) || patch.credentialRevision !== revision + 1) throw stale();
                const allowed = ["wrap", "wrapKdf", "wrapSalt", "iv", "wrappedRoot", "credentials", "credentialRevision", "migration"];
                if (Object.keys(patch).some(key => !allowed.includes(key))) throw new DeviceRootError("INVALID_CREDENTIAL_PATCH", "Credential transaction contains unrelated fields.");
                const updated = { ...(current || { id: RECORD_KEY, version: VERSION, materials: {} }), ...patch };
                validateCredentialRecord(updated); return updated;
            }, options);
        }
        close() {
            try { this.db?.close(); } catch (_) {}
            this.db = null;
        }
    }

    // Preparation may be expensive (Node PoW); only complete record commits
    // share this queue. A rejected write cannot poison the next writer.
    const recordWrites = new WeakMap(), materialJobs = new WeakMap(), materialSecrets = new WeakMap();
    const queueRecordWrite = (store, run) => {
        const operation = (recordWrites.get(store) || Promise.resolve()).then(run);
        recordWrites.set(store, operation.catch(() => {}));
        return operation;
    };
    const putCurrentRecord = async (root, store, record, current, expected = root.state?.record) => {
        current(); const abort = new AbortController(), off = root.onLock(() => abort.abort());
        try { current(); await store.put(record, { assertCurrent: current, signal: abort.signal, expected }); current(); }
        finally { off(); }
    };
    const sessionGuard = (root, session, store, unlocked = true) => {
        const epoch = root._epoch;
        return () => {
            if (root._epoch !== epoch || root.state !== session || root._store() !== store || (unlocked && !session?.root) || (session && !session.root)) {
                throw new DeviceRootError("DEVICE_LOCKED", "Device identity session changed during key material access.");
            }
        };
    };
    const trackSecret = (session, bytes) => {
        let secrets = materialSecrets.get(session);
        if (!secrets) materialSecrets.set(session, secrets = new Set());
        secrets.add(bytes); return bytes;
    };
    const wipeSecret = (session, bytes) => { bytes?.fill(0); materialSecrets.get(session)?.delete(bytes); };
    const hasMaterial = (record, name) => Object.prototype.hasOwnProperty.call(record.materials || {}, name);
    async function rewriteRootWrap(root, oldSecret, nextSecret, migration = false) {
        root._requireCrypto();
        const session = root.state, store = root._store(), current = sessionGuard(root, session, store, false);
        current(); const record = await store.get(); current();
        if (!record || record.version !== VERSION || !record.wrapSalt || !record.iv || !record.wrappedRoot) {
            throw new DeviceRootError("STORAGE_CORRUPT", "Device identity record is corrupt or unsupported. It was not changed.");
        }
        let bytes;
        try {
            bytes = await root._decryptRoot(record, oldSecret);
            if (session) trackSecret(session, bytes);
            current();
            const wrapSalt = root._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
            const wrapped = await root._encryptRoot(bytes, nextSecret, wrapSalt); current();
            await queueRecordWrite(store, async () => {
                current(); const latest = await store.get(); current();
                // Do not let a concurrent credential change replace the proof
                // used above. Material/biometric updates may safely be merged.
                if (!latest || ['iv', 'wrapSalt', 'wrappedRoot'].some(name => latest[name] !== record[name])) {
                    throw new DeviceRootError("DEVICE_LOCKED", "Device wrapping changed during credential update.");
                }
                const updated = { ...latest, wrapSalt: b64(wrapSalt), ...wrapped };
                if (migration) updated.migration = { ...(latest.migration || {}), credentialDomain: "calculator-master-v1", migratedAt: Date.now() };
                if (store.compareAndSwap) {
                    const patch = { ...wrapped, wrapSalt: b64(wrapSalt), credentialRevision: (record.credentialRevision || 0) + 1 };
                    if (migration) patch.migration = updated.migration;
                    const abort = new AbortController(), off = root.onLock(() => abort.abort());
                    try { current(); const committed = await store.compareAndSwap(record, patch, { assertCurrent: current, signal: abort.signal }); current(); if (session) session.record = committed; }
                    finally { off(); }
                } else {
                    // Legacy injected test adapters only; the shipped IDB store
                    // always takes the native transaction CAS path above.
                    await putCurrentRecord(root, store, updated, current);
                    if (session) session.record = updated;
                }
            });
            return Object.freeze(migration ? { migrated: true } : { rewrapped: true });
        } finally { if (session) wipeSecret(session, bytes); else bytes?.fill(0); }
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
            notificationBeacon: "dmash/device-notification-beacon",
            mlKemSeedRoot: "dmash/device-mlkem-seed-root"
        }),
        store: null,
        state: null,
        _epoch: 0,
        _prepared: new Set(),
        credentialProfile: WRAP_PROFILE,
        _lockObservers: new Set(),
        _unlockObservers: new Set(),
        _crypto: global.crypto,

        invalidateStore() { const store = this._store(); store.invalidated = true; store.close?.(); this.lock(); },
        setStoreForTests(store) { this.store = store; if (store instanceof IndexedDbDeviceRootStore) store.onInvalidated = () => this.lock(); },
        resetForTests() { this.store = null; this.state = null; },
        _store() { if (!this.store) { this.store = new IndexedDbDeviceRootStore(); this.store.onInvalidated = () => this.lock(); } return this.store; },
        _requireCrypto() {
            if (!this._crypto?.getRandomValues || !this._crypto?.subtle) throw new DeviceRootError("CRYPTO_UNAVAILABLE", "Web Crypto is required for device identity.");
        },
        _credentials() { return global.navigator?.credentials; },
        _requireWebAuthn() {
            if (global.isSecureContext !== true || typeof this._credentials()?.create !== "function" || typeof this._credentials()?.get !== "function") {
                throw new DeviceRootError("WEBAUTHN_UNAVAILABLE", "Platform WebAuthn PRF is unavailable; use the calculator master secret.");
            }
        },
        _webauthnChallenge() { return this._crypto.getRandomValues(new Uint8Array(32)); },
        _prfResult(credential) {
            const result = credential?.getClientExtensionResults?.()?.prf?.results?.first;
            const bytes = result instanceof ArrayBuffer ? new Uint8Array(result) :
                (ArrayBuffer.isView(result) ? new Uint8Array(result.buffer, result.byteOffset, result.byteLength) : null);
            if (!bytes || bytes.length !== PRF_OUTPUT_BYTES) throw new DeviceRootError("WEBAUTHN_PRF_UNAVAILABLE", "The platform credential did not provide a WebAuthn PRF result.");
            return new Uint8Array(bytes);
        },
        _credentialId(credential) {
            const rawId = credential?.rawId;
            const bytes = rawId instanceof ArrayBuffer ? new Uint8Array(rawId) :
                (ArrayBuffer.isView(rawId) ? new Uint8Array(rawId.buffer, rawId.byteOffset, rawId.byteLength) : null);
            if (!bytes?.length || bytes.length > 1024) throw new DeviceRootError("WEBAUTHN_ENROLLMENT_FAILED", "Platform WebAuthn did not return a valid credential.");
            return b64(bytes);
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
        async _wrapKey(masterPin, salt, type = 2, { signal } = {}) {
            if (typeof masterPin !== "string" || !masterPin) throw new DeviceRootError("MASTER_PIN_REQUIRED", "A calculator master PIN is required to unlock this device.");
            const port = this.credentialKdf || global.LocalCredentialKdf;
            if (!port?.derive && !global.argon2?.hash) throw new DeviceRootError("ARGON2_UNAVAILABLE", "Password hardening is unavailable; device identity was not changed.");
            if (!(salt instanceof Uint8Array) || salt.length !== WRAP_SALT_BYTES) throw new DeviceRootError("STORAGE_CORRUPT", "Device identity wrapping parameters are invalid.");
            let hash;
            try {
                if (signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled.");
                if (port?.derive) {
                    hash = await port.derive({ pass: masterPin, salt: b64(salt), type, time: 3, mem: 65536, hashLen: WRAP_KEY_BYTES, parallelism: 1, version: 19 }, { signal });
                } else {
                    const result = await global.argon2.hash({ pass: masterPin, salt: b64(salt), time: 3, mem: 65536, hashLen: WRAP_KEY_BYTES, type, parallelism: 1 });
                    hash = result?.hash instanceof Uint8Array ? result.hash : new Uint8Array(result?.hash || []);
                }
                if (signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled.");
                if (!(hash instanceof Uint8Array) || hash.length !== WRAP_KEY_BYTES) throw new Error("invalid Argon2 output");
                return await this._crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
            } catch (error) {
                if (error instanceof DeviceRootError) throw error;
                throw new DeviceRootError("ARGON2_FAILED", "Password hardening failed; device identity was not changed.");
            } finally {
                hash?.fill(0);
            }
        },
        async _encryptRoot(root, masterPin, salt, options = {}) {
            const epoch = this._epoch;
            const current = () => { if (epoch !== this._epoch || options.signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Wrapping was cancelled before persistence."); };
            current(); const iv = this._crypto.getRandomValues(new Uint8Array(12));
            const key = await this._wrapKey(masterPin, salt, 2, options); current();
            const ciphertext = await this._crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD_V2 }, key, root); current();
            const wrapped = { wrap: WRAP_V2, wrapKdf: { ...WRAP_PROFILE }, iv: b64(iv), wrappedRoot: b64(new Uint8Array(ciphertext)) };
            let reopened;
            try {
                // Re-derive through the actual configured KDF port, authenticate
                // the complete new wrap and compare the same root BEFORE any
                // canonical replacement. A valid-length unstable KDF must not
                // strand an installation or complete pending setup.
                reopened = await this._decryptRoot({ ...wrapped, wrapSalt: b64(salt) }, masterPin, options); current();
                let difference = reopened.length ^ root.length;
                for (let i = 0; i < root.length; i++) difference |= root[i] ^ reopened[i];
                if (difference) throw new DeviceRootError("WRAP_VERIFY_FAILED", "Prepared root wrap did not reopen the same identity.");
                return wrapped;
            } finally { reopened?.fill(0); }
        },
        async _decryptRoot(record, masterPin, options = {}) {
            const modern = record.wrap === WRAP_V2;
            if (modern && (Object.keys(record.wrapKdf || {}).length !== Object.keys(WRAP_PROFILE).length || Object.entries(WRAP_PROFILE).some(([key, value]) => record.wrapKdf?.[key] !== value))) {
                throw new DeviceRootError("STORAGE_CORRUPT", "Unsupported credential KDF profile; identity was not changed.");
            }
            if (!modern && record.wrap && record.wrap !== "argon2id-aes-256-gcm-v1") throw new DeviceRootError("STORAGE_CORRUPT", "Unsupported root wrapping scheme.");
            try {
                const salt = decodeB64(record.wrapSalt, WRAP_SALT_BYTES), iv = decodeB64(record.iv, WRAP_IV_BYTES);
                const wrappedRoot = decodeB64(record.wrappedRoot, ROOT_BYTES + GCM_TAG_BYTES);
                // Legacy deployed v1 used the vendor default Argon2d. Some
                // explicit-id ports used the same label: bounded fallback is
                // accepted ONLY after authenticating the complete GCM tag.
                for (const type of modern ? [2] : [0, 2]) {
                    const key = await this._wrapKey(masterPin, salt, type, options);
                    try {
                        const plaintext = await this._crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: modern ? AAD_V2 : AAD }, key, wrappedRoot);
                        const root = new Uint8Array(plaintext);
                        if (root.length !== ROOT_BYTES) { root.fill(0); throw new Error("invalid root length"); }
                        return root;
                    } catch (error) { if (type === 2) throw error; }
                }
            } catch (error) {
                if (error instanceof DeviceRootError) throw error;
                throw new DeviceRootError("UNLOCK_FAILED", "Device identity could not be unlocked. It was not replaced.");
            }
        },
        async _prfWrapKey(prfOutput) {
            if (!(prfOutput instanceof Uint8Array) || prfOutput.length !== PRF_OUTPUT_BYTES) {
                throw new DeviceRootError("WEBAUTHN_PRF_UNAVAILABLE", "The platform credential did not provide a WebAuthn PRF result.");
            }
            try {
                return await this._crypto.subtle.importKey("raw", prfOutput, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
            } catch (_) {
                throw new DeviceRootError("WEBAUTHN_PRF_FAILED", "The WebAuthn PRF wrapping key could not be used.");
            }
        },
        async _getPrfAssertion(credentialId, prfSalt) {
            this._requireWebAuthn();
            let assertion;
            try {
                assertion = await this._credentials().get({ publicKey: {
                    challenge: this._webauthnChallenge(),
                    rpId: global.location?.hostname || undefined,
                    allowCredentials: [{ type: "public-key", id: credentialId }],
                    userVerification: "required",
                    extensions: { prf: { eval: { first: prfSalt } } }
                } });
            } catch (_) {
                throw new DeviceRootError("WEBAUTHN_ASSERTION_FAILED", "Device biometric authentication did not unlock this device.");
            }
            return this._prfResult(assertion);
        },
        // Enrolls a platform, user-verified credential as an additional wrapping
        // path for the already-unlocked DeviceRoot. It never replaces Argon2id.
        async enrollWebAuthnPrf() {
            this._requireCrypto(); this._requireWebAuthn();
            const session = this.state, store = this._store(), current = sessionGuard(this, session, store);
            current(); const record = session.record;
            const wraps = Array.isArray(record.biometricWraps) ? [...record.biometricWraps] : (record.biometricWrap ? [record.biometricWrap] : []);
            if (wraps.length >= 8) throw new DeviceRootError("WEBAUTHN_LIMIT", "Device biometric credential limit reached.");
            const salt = wraps[0]?.prfSalt ? decodeB64(wraps[0].prfSalt, PRF_SALT_BYTES) : this._crypto.getRandomValues(new Uint8Array(PRF_SALT_BYTES));
            let output;
            try {
                const credential = await this._credentials().create({ publicKey: {
                    challenge: this._webauthnChallenge(), rp: { name: "MathPro Security", id: global.location?.hostname },
                    user: { id: this._crypto.getRandomValues(new Uint8Array(16)), name: `device-${wraps.length + 1}-${Date.now()}`, displayName: `D-MASH Device ${wraps.length + 1}` },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "required" }, attestation: "none", extensions: { prf: { eval: { first: salt } } }
                } }); current();
                const id = decodeB64(this._credentialId(credential));
                try { output = this._prfResult(credential); }
                catch (_) { output = await this._getPrfAssertion(id, salt); current(); }
                trackSecret(session, output);
                const key = await this._prfWrapKey(output); current();
                const iv = this._crypto.getRandomValues(new Uint8Array(WRAP_IV_BYTES));
                const ciphertext = await this._crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: PRF_AAD }, key, session.root); current();
                wraps.push({ wrap: PRF_WRAP, credentialId: b64(id), prfSalt: b64(salt), iv: b64(iv), wrappedRoot: b64(new Uint8Array(ciphertext)), addedAt: Date.now() });
                await queueRecordWrite(store, async () => {
                    current();
                    const next = { ...record, biometricWraps: wraps, biometricWrap: wraps[0] };
                    await putCurrentRecord(this, store, next, current, record); current(); session.record = await store.get(); current();
                });
                return Object.freeze({ enrolled: true, credentialCount: wraps.length });
            } catch (failure) {
                if (failure instanceof DeviceRootError) throw failure;
                throw new DeviceRootError("WEBAUTHN_ENROLLMENT_FAILED", "Platform biometric enrollment was not committed.");
            } finally { wipeSecret(session, output); }
        },
        async unlockWithWebAuthnPrf() {
            const handle = await this.prepareWebAuthnUnlock();
            try { return await this.publishPrepared(handle); } finally { handle.dispose(); }
        },
        async deviceIdentity(root) {
            let edSeed, xSeed, signing, agreement;
            try {
                edSeed = await this.derive(root, this.domains.identityEd25519, VERSION, "");
                xSeed = await this.derive(root, this.domains.identityX25519, VERSION, "");
                if (!global.nacl?.sign?.keyPair?.fromSeed || !global.nacl?.box?.keyPair?.fromSecretKey) {
                    throw new DeviceRootError("NACL_UNAVAILABLE", "Device identity primitives are unavailable.");
                }
                signing = global.nacl.sign.keyPair.fromSeed(edSeed);
                agreement = global.nacl.box.keyPair.fromSecretKey(xSeed);
                const idDigest = new Uint8Array(await this._crypto.subtle.digest("SHA-256", join(utf8("dmash/device-id/v1"), signing.publicKey, agreement.publicKey)));
                return Object.freeze({
                    // DeviceID is public/pseudonymous: SHA-256 over public keys and a
                    // protocol label, never a hash of DeviceRoot.
                    deviceId: "d1_" + b64(idDigest).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""),
                    signing,
                    agreement,
                    fingerprints: Object.freeze({ signing: b64(signing.publicKey), agreement: b64(agreement.publicKey) })
                });
            } catch (error) {
                signing?.secretKey.fill(0); agreement?.secretKey.fill(0);
                throw error;
            } finally { edSeed?.fill(0); xSeed?.fill(0); }
        },
        async transportIdentity(nodeId) {
            if (!this.state?.root || !/^[0-9a-f]{64}$/i.test(nodeId || "")) {
                throw new DeviceRootError("INVALID_NODE_CONTEXT", "A verified Ed25519 NodeID is required for device transport authentication.");
            }
            const context = `DMP-C|2|${nodeId.toLowerCase()}`;
            const seed = await this.derive(this.state.root, this.domains.transportAuth, VERSION, context);
            if (!global.nacl?.sign?.keyPair?.fromSeed) throw new DeviceRootError("NACL_UNAVAILABLE", "Device transport primitives are unavailable.");
            const signing = global.nacl.sign.keyPair.fromSeed(seed);
            return Object.freeze({ mode: "DEVICE_AUTH_V1", nodeId: nodeId.toLowerCase(), signing });
        },
        async notificationBeaconHandle() {
            if (!this.state?.root) throw new DeviceRootError("DEVICE_LOCKED", "Device identity must be unlocked before accessing the notification beacon.");
            const material = await this.derive(this.state.root, this.domains.notificationBeacon, VERSION, "origin-v1");
            const digest = new Uint8Array(await this._crypto.subtle.digest("SHA-256", join(utf8("dmash/notification-beacon/v1"), material)));
            // This is a stable opaque device handle. It is not an Account ID,
            // DeviceRoot, or a routing locator and is never displayed raw.
            return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
        },
        bindingTranscript(binding) {
            const fields = ["D-MASH-DEVICE-BINDING", "1", binding.account_public_key, binding.device_signing_public_key, binding.device_agreement_public_key, String(binding.created_at)];
            if (!fields.every((value) => typeof value === "string" && value.length)) throw new DeviceRootError("INVALID_BINDING", "Device binding fields are invalid.");
            return utf8(fields.join("|"));
        },
        verifyBinding(binding) {
            try {
                if (!binding || binding.version !== 1 || !/^[0-9a-f]{64}$/i.test(binding.account_public_key || "") ||
                    !/^[A-Za-z0-9+/]+={0,2}$/.test(binding.device_signing_public_key || "") ||
                    !/^[A-Za-z0-9+/]+={0,2}$/.test(binding.device_agreement_public_key || "") ||
                    !/^[A-Za-z0-9+/]+={0,2}$/.test(binding.signature || "")) return false;
                return global.nacl.sign.detached.verify(this.bindingTranscript(binding), unb64(binding.signature), new Uint8Array(this.hexToBytes(binding.account_public_key)));
            } catch (_) { return false; }
        },
        hexToBytes(value) { return new Uint8Array(value.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))); },
        async migrateLegacy(masterPin, accountPublicKey, accountSecretKey) {
            this._requireCrypto();
            if (!/^[0-9a-f]{64}$/i.test(accountPublicKey || "") || !(accountSecretKey instanceof Uint8Array) || accountSecretKey.length < 64) {
                throw new DeviceRootError("LEGACY_ACCOUNT_UNVERIFIED", "Legacy Account identity must be unlocked and verified before DeviceRoot migration.");
            }
            const store = this._store();
            let marker = await store.get("migration");
            let record = await store.get();
            if (marker?.state === "complete" && !record) throw new DeviceRootError("MIGRATION_INCONSISTENT", "Migration marker has no DeviceRoot record.");
            if (!record) {
                await store.put({ id: "migration", version: 1, state: "in_progress" });
                const root = this._crypto.getRandomValues(new Uint8Array(ROOT_BYTES));
                const wrapSalt = this._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
                const wrapped = await this._encryptRoot(root, masterPin, wrapSalt);
                record = { id: RECORD_KEY, version: VERSION, wrapSalt: b64(wrapSalt), materials: {}, migration: { version: 1, state: "in_progress" }, ...wrapped };
                await store.put(record);
                root.fill(0);
            }
            const root = await this._decryptRoot(record, masterPin);
            const identity = await this.deviceIdentity(root);
            const existing = record.migration?.binding;
            if (existing && !this.verifyBinding(existing)) throw new DeviceRootError("BINDING_INVALID", "Stored DeviceBinding is invalid and migration cannot continue.");
            const binding = existing || (() => {
                const candidate = {
                    version: 1, account_public_key: accountPublicKey.toLowerCase(),
                    device_signing_public_key: b64(identity.signing.publicKey), device_agreement_public_key: b64(identity.agreement.publicKey),
                    created_at: Date.now()
                };
                candidate.signature = b64(global.nacl.sign.detached(this.bindingTranscript(candidate), accountSecretKey));
                return candidate;
            })();
            if (binding.account_public_key !== accountPublicKey.toLowerCase() || !this.verifyBinding(binding)) {
                root.fill(0); throw new DeviceRootError("BINDING_INVALID", "DeviceBinding did not verify against the unlocked Account identity.");
            }
            // Verify persistence before commit. A restart seeing in_progress
            // reuses this exact root/binding; it never makes a second device.
            const reopened = await this._decryptRoot(record, masterPin);
            reopened.fill(0);
            const expected = structuredClone(record);
            record.migration = { version: 1, state: "complete", binding };
            await store.put(record, { expected });
            await store.put({ id: "migration", version: 1, state: "complete" });
            this._replaceState({ root, identity, created: false, record });
            return this.state;
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
            const session = this.state, store = this._store(), current = sessionGuard(this, session, store);
            current();
            if (typeof name !== "string" || !name || typeof create !== "function") {
                throw new DeviceRootError("INVALID_KDF_INPUT", "Invalid device material request.");
            }
            const materialAad = utf8("dmash/device-material/v1|" + name);
            const materialKey = async () => {
                let domainRoot;
                try {
                    current(); domainRoot = trackSecret(session, await this.derive(session.root, this.domains.mlKemSeedRoot, VERSION, name)); current();
                    const key = await this._crypto.subtle.importKey("raw", domainRoot, "AES-GCM", false, ["encrypt", "decrypt"]); current();
                    return key;
                } finally { wipeSecret(session, domainRoot); }
            };
            if (!hasMaterial(session.record, name)) {
                let jobs = materialJobs.get(session);
                if (!jobs) materialJobs.set(session, jobs = new Map());
                let entry = jobs.get(name);
                if (!entry) {
                    entry = { promise: null };
                    // No plaintext promise result is shared. Each caller will
                    // decrypt its own independent copy after this commit.
                    entry.promise = Promise.resolve().then(async () => {
                        let bytes;
                        try {
                            current(); const created = await create();
                            bytes = trackSecret(session, created instanceof Uint8Array ? created : new Uint8Array(created)); current();
                            const key = await materialKey(); current();
                            const iv = this._crypto.getRandomValues(new Uint8Array(12));
                            const ciphertext = await this._crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: materialAad }, key, bytes); current();
                            const encrypted = { iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) };
                            await queueRecordWrite(store, async () => {
                                current();
                                if (hasMaterial(session.record, name)) return;
                                const record = { ...session.record, materials: { ...session.record.materials, [name]: encrypted } };
                                await putCurrentRecord(this, store, record, current); session.record = record;
                            });
                        } finally {
                            wipeSecret(session, bytes);
                            if (jobs.get(name) === entry) jobs.delete(name);
                        }
                    });
                    jobs.set(name, entry);
                }
                await entry.promise; current();
            }
            // Existing malformed ciphertext is never treated as missing and
            // must never trigger creation of a replacement identity.
            let bytes, returned = false;
            try {
                const key = await materialKey(); current();
                const existing = session.record.materials[name];
                try {
                    bytes = trackSecret(session, new Uint8Array(await this._crypto.subtle.decrypt({ name: "AES-GCM", iv: decodeB64(existing.iv, 12), additionalData: materialAad }, key, decodeB64(existing.ciphertext))));
                } catch (_) {
                    current(); throw new DeviceRootError("STORAGE_CORRUPT", "Device key material is corrupt. It was not regenerated.");
                }
                current(); returned = true; return bytes;
            } finally {
                if (!returned) wipeSecret(session, bytes);
                else materialSecrets.get(session)?.delete(bytes);
            }
        },
        async prepareWebAuthnUnlock({ record = this.__dmashBiometricRecordCache, signal } = {}) {
            this._requireCrypto(); this._requireWebAuthn();
            const store = this._store(), epoch = this._epoch;
            const current = () => { if (epoch !== this._epoch || store !== this._store() || signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Biometric authentication was cancelled."); };
            const wraps = Array.isArray(record?.biometricWraps) && record.biometricWraps.length ? record.biometricWraps : (record?.biometricWrap ? [record.biometricWrap] : []);
            if (wraps.length > 8) throw new DeviceRootError("STORAGE_CORRUPT", "Invalid biometric credential count.");
            if (!record || record.version !== VERSION || !wraps.length) throw new DeviceRootError("WEBAUTHN_METADATA_NOT_READY", "Preload biometric metadata before trusted interaction.");
            const salt = decodeB64(wraps[0].prfSalt, PRF_SALT_BYTES);
            const allowCredentials = wraps.map(wrap => ({ type: "public-key", id: decodeB64(wrap.credentialId) }));
            let output, root, identity;
            try {
                // Start synchronously before the first await so trusted user
                // activation reaches the platform authenticator unchanged.
                current(); const assertionPromise = this._credentials().get({ publicKey: { challenge: this._webauthnChallenge(), rpId: global.location?.hostname || undefined, timeout: 60000, userVerification: "required", allowCredentials, extensions: { prf: { eval: { first: salt } } } }, signal });
                const assertion = await assertionPromise; current();
                const selectedId = this._credentialId(assertion), selected = wraps.find(wrap => wrap.credentialId === selectedId);
                if (!selected || selected.wrap !== PRF_WRAP) throw new DeviceRootError("WEBAUTHN_UNKNOWN_CREDENTIAL", "Platform credential is not bound to this root.");
                output = this._prfResult(assertion);
                const key = await this._prfWrapKey(output); current();
                root = new Uint8Array(await this._crypto.subtle.decrypt({ name: "AES-GCM", iv: decodeB64(selected.iv, WRAP_IV_BYTES), additionalData: PRF_AAD }, key, decodeB64(selected.wrappedRoot, ROOT_BYTES + GCM_TAG_BYTES))); current();
                if (root.length !== ROOT_BYTES) throw new DeviceRootError("STORAGE_CORRUPT", "Invalid biometric root length.");
                identity = await this.deviceIdentity(root); current();
                const latest = await store.get(); current(); validateCredentialRecord(latest);
                const latestWraps = Array.isArray(latest?.biometricWraps) && latest.biometricWraps.length ? latest.biometricWraps : (latest?.biometricWrap ? [latest.biometricWrap] : []);
                if (!latest || !latestWraps.some(wrap => JSON.stringify(wrap) === JSON.stringify(selected))) throw stale();
                return makePrepared(this, { root, identity, record: latest, store, epoch, signal, disposed: false, authentication: "webauthn-prf", authenticatedAt: Date.now(), biometricBinding: JSON.stringify(selected) });
            } catch (failure) {
                erasePrepared({ root, identity });
                if (failure instanceof DeviceRootError) throw failure;
                throw new DeviceRootError("WEBAUTHN_UNLOCK_FAILED", "Fresh platform authentication could not open the existing root.");
            } finally { output?.fill(0); }
        },
        preparedAuthentication(handle) {
            const value = preparedValue(this, handle);
            return Object.freeze({ method: value.authentication || "master", authenticatedAt: value.authenticatedAt || null });
        },
        async prepareSetup(masterPin, { assertEmpty, signal } = {}) {
            if (typeof assertEmpty !== "function") throw new DeviceRootError("SETUP_INVENTORY_REQUIRED", "Explicit empty-installation inventory is required.");
            this._requireCrypto(); const store = this._store(), epoch = this._epoch;
            const current = () => { if (epoch !== this._epoch || store !== this._store() || signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Setup was cancelled."); };
            if (typeof store.compareAndSwap !== "function") throw new DeviceRootError("STORAGE_CAS_UNAVAILABLE", "Atomic credential storage is required.");
            let root, identity;
            try {
                current(); if (await assertEmpty() !== true) throw new DeviceRootError("LEGACY_MIGRATION_REQUIRED", "Installation is not proven empty; explicit recovery is required."); current();
                if (await store.get()) throw stale(); current();
                root = this._crypto.getRandomValues(new Uint8Array(ROOT_BYTES));
                const salt = this._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
                const wrapped = await this._encryptRoot(root, masterPin, salt, { signal }); current();
                identity = await this.deviceIdentity(root); current();
                const record = await store.compareAndSwap(null, { ...wrapped, wrapSalt: b64(salt), credentialRevision: 1, credentials: { version: 1, state: "pending-wipe", legacyCleanup: "complete" } }, { assertCurrent: current, signal }); current();
                return makePrepared(this, { root, identity, record, store, epoch, signal, disposed: false });
            } catch (error) { erasePrepared({ root, identity }); throw error; }
        },
        validateCredentialRecord(record) { validateCredentialRecord(record); },
        preparedRecord(handle) { return structuredClone(preparedValue(this, handle).record); },
        async commitPreparedMetadata(handle, credentials, { signal } = {}) {
            const value = preparedValue(this, handle);
            if (typeof value.store.compareAndSwap !== "function") throw new DeviceRootError("STORAGE_CAS_UNAVAILABLE", "Atomic credential storage is required.");
            const current = () => { preparedValue(this, handle); if (signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled."); };
            current(); const record = await value.store.compareAndSwap(value.record, { credentials, credentialRevision: (value.record.credentialRevision || 0) + 1 }, { assertCurrent: current, signal: signal || value.signal, biometricBinding: value.biometricBinding });
            if (this.state && credentialProof(this.state.record) === credentialProof(value.record)) this.state.record = record;
            value.record = record;
            try { current(); } catch (failure) { failure.committed = true; failure.revision = record.credentialRevision; throw failure; }
            return Object.freeze({ committed: true, revision: record.credentialRevision });
        },
        async prepareUnlock(masterPin, { signal } = {}) {
            this._requireCrypto();
            const epoch = this._epoch, store = this._store(); let root, identity;
            const current = () => { if (epoch !== this._epoch || store !== this._store() || signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled."); };
            try {
                current(); const record = await store.get(); current();
                if (!record) throw new DeviceRootError("ROOT_MISSING", "Existing installation root is missing; explicit setup or recovery is required.");
                validateCredentialRecord(record);
                if (record.version !== VERSION) throw new DeviceRootError("STORAGE_CORRUPT", "Unsupported root identity version.");
                root = await this._decryptRoot(record, masterPin, { signal }); current();
                identity = await this.deviceIdentity(root); current();
                return makePrepared(this, { root, identity, record, store, epoch, signal, disposed: false });
            } catch (error) { erasePrepared({ root, identity }); throw error; }
        },
        async publishPrepared(handle) {
            const value = preparedValue(this, handle), latest = await value.store.get();
            preparedValue(this, handle);
            const latestBiometrics = Array.isArray(latest?.biometricWraps) && latest.biometricWraps.length ? latest.biometricWraps : (latest?.biometricWrap ? [latest.biometricWrap] : []);
            if (credentialProof(latest) !== credentialProof(value.record) || (value.biometricBinding && !latestBiometrics.some(wrap => JSON.stringify(wrap) === value.biometricBinding))) { handle.dispose(); throw stale(); }
            // Reauthentication of the same unlocked root need not revoke Node
            // owners or emit a synthetic lock/cancel cycle. Compare actual root
            // bytes; a different installation cannot replace an unlocked one.
            if (this.state?.root) {
                let difference = this.state.root.length ^ value.root.length;
                for (let i = 0; i < value.root.length; i++) difference |= this.state.root[i] ^ value.root[i];
                if (difference) { handle.dispose(); throw stale(); }
                this.state.record = latest; handle.dispose(); return this.state;
            }
            // There is no await between the final lifecycle check and publish.
            const state = { root: value.root, identity: value.identity, record: latest, created: false };
            this._prepared.delete(value); value.disposed = true;
            value.root = null; value.identity = null;
            this._replaceState(state); return state;
        },
        async commitPreparedCredentials(handle, nextSecret, credentials, { signal } = {}) {
            const value = preparedValue(this, handle);
            const current = () => { preparedValue(this, handle); if (signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled."); };
            if (typeof value.store.compareAndSwap !== "function") throw new DeviceRootError("STORAGE_CAS_UNAVAILABLE", "Atomic credential storage is required.");
            const salt = this._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
            const wrap = await this._encryptRoot(value.root, nextSecret, salt, { signal: signal || value.signal }); current();
            const record = await value.store.compareAndSwap(value.record, { ...wrap, wrapSalt: b64(salt), credentialRevision: (value.record.credentialRevision || 0) + 1, credentials }, { assertCurrent: current, signal: signal || value.signal, biometricBinding: value.biometricBinding });
            // Commit is the linearization point. A later cancellation prevents
            // publication but cannot pretend a committed credential rolled back.
            if (this.state && credentialProof(this.state.record) === credentialProof(value.record)) this.state.record = record;
            value.record = record;
            try { current(); } catch (failure) { failure.committed = true; failure.revision = record.credentialRevision; throw failure; }
            return Object.freeze({ committed: true, revision: record.credentialRevision });
        },
        async unlock(masterPin, options = {}) {
            // Compatibility entry until all callers use explicit service setup.
            // Existing roots ALWAYS use the prepare/publish cancellation path.
            const store = this._store(), epoch = this._epoch;
            const record = await store.get();
            if (epoch !== this._epoch || options.signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled.");
            if (record) {
                const prepared = await this.prepareUnlock(masterPin, options);
                try { return await this.publishPrepared(prepared); } finally { prepared.dispose(); }
            }
            if (await this._legacyVaultExists()) throw new DeviceRootError("LEGACY_MIGRATION_REQUIRED", "A legacy vault exists. DeviceRoot was not created.");
            const root = this._crypto.getRandomValues(new Uint8Array(ROOT_BYTES)); let identity;
            const current = () => { if (epoch !== this._epoch || store !== this._store() || options.signal?.aborted) throw new DeviceRootError("DEVICE_LOCKED", "Credential operation was cancelled."); };
            try {
                current(); const salt = this._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
                const wrapped = await this._encryptRoot(root, masterPin, salt, options); current();
                const next = { id: RECORD_KEY, version: VERSION, wrapSalt: b64(salt), materials: {}, ...wrapped };
                // The legacy compatibility path also forbids concurrent setup
                // from replacing a root installed while the KDF was running.
                if (store.compareAndSwap) await store.compareAndSwap(null, { ...wrapped, wrapSalt: b64(salt), credentialRevision: 1 }, { assertCurrent: current, signal: options.signal });
                else { if (await store.get()) throw stale(); current(); await store.put(next, { assertCurrent: current, signal: options.signal }); }
                current(); identity = await this.deviceIdentity(root); current();
                const persisted = await store.get(); current();
                this._replaceState({ root, identity, created: true, record: persisted }); return this.state;
            } catch (error) { erasePrepared({ root, identity }); throw error; }
        },
        // Changing the calculator master secret must also rotate the local
        // wrapping key.  The DeviceRoot itself (and therefore the public device
        // identity, account separation, and biometric wrap) remains unchanged.
        // Persist only after both the old unwrap and new wrap succeed, so a
        // failed/cancelled change cannot strand or replace an installation.
        async rewrapMasterPin(currentMasterPin, nextMasterPin) {
            this._requireCrypto();
            if (typeof nextMasterPin !== "string" || !nextMasterPin) {
                throw new DeviceRootError("MASTER_PIN_REQUIRED", "A new calculator master PIN is required.");
            }
            return rewriteRootWrap(this, currentMasterPin, nextMasterPin);
        },
        // Compatibility migration for records created before DeviceRoot moved
        // from the Account passphrase to the calculator master secret. The
        // caller must obtain this secret explicitly from the user after a
        // calculator unlock failure. A successful old-wrap decrypt is the
        // cryptographic proof of the legacy credential; the same root is then
        // atomically rewrapped and annotated, never recreated or replaced.
        async migrateLegacyAccountPassphrase(accountPassphrase, calculatorMasterPin) {
            return rewriteRootWrap(this, accountPassphrase, calculatorMasterPin, true);
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
        // Explicit wipe/recovery boundary. This deletes the complete local
        // DeviceRoot database, so the next calculator setup creates a new
        // installation identity. It is never used for an ordinary unlock
        // failure or a wrong master-code attempt.
        async eraseForExplicitWipe() {
            const store = this._store();
            this.lock();
            store.close?.();
            if (!global.indexedDB?.deleteDatabase) {
                throw new DeviceRootError("STORAGE_UNAVAILABLE", "Device identity storage could not be erased.");
            }
            await new Promise((resolve, reject) => {
                const request = global.indexedDB.deleteDatabase(DB_NAME);
                request.onsuccess = () => resolve();
                request.onerror = () => reject(new DeviceRootError("STORAGE_WRITE_FAILED", "Device identity storage could not be erased."));
                request.onblocked = () => reject(new DeviceRootError("STORAGE_BLOCKED", "Close other D-MASH tabs before wiping this device."));
            });
            this.store = null;
        },
        onUnlock(listener) {
            if (typeof listener !== "function") throw new TypeError("Unlock listener must be a function");
            this._unlockObservers.add(listener);
            return () => this._unlockObservers.delete(listener);
        },
        onLock(listener) {
            if (typeof listener !== "function") throw new TypeError("Lock listener must be a function");
            this._lockObservers.add(listener);
            return () => this._lockObservers.delete(listener);
        },
        _replaceState(state) {
            if (this.state) this.lock();
            this.state = state;
            for (const listener of [...this._unlockObservers]) {
                try { listener(); } catch (_) { /* Runtime failure cannot replace persisted root material. */ }
            }
        },
        lock() {
            this._epoch++;
            for (const value of this._prepared) erasePrepared(value);
            this._prepared.clear();
            for (const bytes of materialSecrets.get(this.state) || []) bytes.fill(0);
            for (const key of [this.state?.root, this.state?.identity?.signing?.secretKey, this.state?.identity?.agreement?.secretKey]) {
                if (key instanceof Uint8Array && key.byteLength) key.fill(0);
            }
            this.state = null;
            for (const listener of [...this._lockObservers]) {
                try { listener(); } catch (_) { /* One observer cannot prevent other owners from locking. */ }
            }
        }
    };

    global.DeviceRoot = DeviceRoot;
    global.DeviceRootError = DeviceRootError;
    global.IndexedDbDeviceRootStore = IndexedDbDeviceRootStore;
    if (typeof module !== "undefined") module.exports = { DeviceRoot, DeviceRootError, IndexedDbDeviceRootStore };
})(typeof window !== "undefined" ? window : globalThis);
