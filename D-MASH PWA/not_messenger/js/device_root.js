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
        async get(id = RECORD_KEY) {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const request = db.transaction(STORE, "readonly").objectStore(STORE).get(id);
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
        close() {
            try { this.db?.close(); } catch (_) {}
            this.db = null;
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
            notificationBeacon: "dmash/device-notification-beacon",
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
        async _wrapKey(masterPin, salt) {
            if (typeof masterPin !== "string" || !masterPin) throw new DeviceRootError("MASTER_PIN_REQUIRED", "A calculator master PIN is required to unlock this device.");
            if (!global.argon2?.hash) throw new DeviceRootError("ARGON2_UNAVAILABLE", "Password hardening is unavailable; device identity was not changed.");
            if (!(salt instanceof Uint8Array) || salt.length !== WRAP_SALT_BYTES) throw new DeviceRootError("STORAGE_CORRUPT", "Device identity wrapping parameters are invalid.");
            let hash;
            try {
                const result = await global.argon2.hash({
                    pass: masterPin,
                    salt: b64(salt),
                    time: 3,
                    mem: 65536,
                    hashLen: WRAP_KEY_BYTES,
                    type: global.argon2.argon2id
                });
                hash = result?.hash instanceof Uint8Array ? result.hash : new Uint8Array(result?.hash || []);
                if (hash.length !== WRAP_KEY_BYTES) throw new Error("invalid Argon2 output");
                return await this._crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
            } catch (error) {
                if (error instanceof DeviceRootError) throw error;
                throw new DeviceRootError("ARGON2_FAILED", "Password hardening failed; device identity was not changed.");
            } finally {
                hash?.fill(0);
            }
        },
        async _encryptRoot(root, masterPin, salt) {
            const iv = this._crypto.getRandomValues(new Uint8Array(12));
            const key = await this._wrapKey(masterPin, salt);
            const ciphertext = await this._crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, root);
            return { wrap: "argon2id-aes-256-gcm-v1", iv: b64(iv), wrappedRoot: b64(new Uint8Array(ciphertext)) };
        },
        async _decryptRoot(record, masterPin) {
            try {
                if (record.wrap && record.wrap !== "argon2id-aes-256-gcm-v1") throw new Error("unsupported wrapping scheme");
                const salt = decodeB64(record.wrapSalt, WRAP_SALT_BYTES);
                const key = await this._wrapKey(masterPin, salt);
                const iv = decodeB64(record.iv, WRAP_IV_BYTES);
                const wrappedRoot = decodeB64(record.wrappedRoot, ROOT_BYTES + GCM_TAG_BYTES);
                const plaintext = await this._crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, wrappedRoot);
                const root = new Uint8Array(plaintext);
                if (root.length !== ROOT_BYTES) throw new Error("invalid root length");
                return root;
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
            this._requireCrypto();
            this._requireWebAuthn();
            if (!this.state?.root || !this.state?.record) throw new DeviceRootError("DEVICE_LOCKED", "Unlock the device with the calculator master secret before enrolling biometrics.");
            if (this.state.record.biometricWrap) throw new DeviceRootError("WEBAUTHN_ALREADY_ENROLLED", "Device biometric authentication is already enrolled.");
            let credential;
            try {
                const userId = this._crypto.getRandomValues(new Uint8Array(32));
                credential = await this._credentials().create({ publicKey: {
                    challenge: this._webauthnChallenge(),
                    rp: { name: "D-MASH Device" },
                    user: { id: userId, name: "device", displayName: "D-MASH Device" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
                    attestation: "none",
                    extensions: { prf: {} }
                } });
            } catch (_) {
                throw new DeviceRootError("WEBAUTHN_ENROLLMENT_FAILED", "Platform WebAuthn enrollment did not complete.");
            }
            const credentialId = decodeB64(this._credentialId(credential));
            const prfSalt = this._crypto.getRandomValues(new Uint8Array(PRF_SALT_BYTES));
            let prfOutput;
            try {
                prfOutput = await this._getPrfAssertion(credentialId, prfSalt);
                const key = await this._prfWrapKey(prfOutput);
                const iv = this._crypto.getRandomValues(new Uint8Array(WRAP_IV_BYTES));
                const ciphertext = await this._crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: PRF_AAD }, key, this.state.root);
                const biometricWrap = { wrap: PRF_WRAP, credentialId: b64(credentialId), prfSalt: b64(prfSalt), iv: b64(iv), wrappedRoot: b64(new Uint8Array(ciphertext)) };
                const record = { ...this.state.record, biometricWrap };
                await this._store().put(record);
                this.state.record = record;
                return Object.freeze({ enrolled: true });
            } catch (error) {
                if (error instanceof DeviceRootError) throw error;
                throw new DeviceRootError("WEBAUTHN_ENROLLMENT_FAILED", "Device biometric wrapping was not saved.");
            } finally { prfOutput?.fill(0); }
        },
        // This path is intentionally PRF-only: cancellation, unsupported PRF,
        // malformed metadata, or decrypt failure never fall back to PIN or any
        // locally stored software secret.
        async unlockWithWebAuthnPrf() {
            this._requireCrypto();
            const record = await this._store().get();
            const wrap = record?.biometricWrap;
            let prfOutput;
            try {
                if (!record || record.version !== VERSION || !wrap || wrap.wrap !== PRF_WRAP) throw new Error("no supported biometric wrap");
                const credentialId = decodeB64(wrap.credentialId);
                const prfSalt = decodeB64(wrap.prfSalt, PRF_SALT_BYTES);
                const iv = decodeB64(wrap.iv, WRAP_IV_BYTES);
                const wrappedRoot = decodeB64(wrap.wrappedRoot, ROOT_BYTES + GCM_TAG_BYTES);
                prfOutput = await this._getPrfAssertion(credentialId, prfSalt);
                const key = await this._prfWrapKey(prfOutput);
                const plaintext = await this._crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: PRF_AAD }, key, wrappedRoot);
                const root = new Uint8Array(plaintext);
                if (root.length !== ROOT_BYTES) throw new Error("invalid root length");
                const identity = await this.deviceIdentity(root);
                this.state = { root, identity, created: false, record };
                return this.state;
            } catch (error) {
                if (this.state?.root) this.lock();
                if (error instanceof DeviceRootError && error.code === "WEBAUTHN_UNAVAILABLE") throw error;
                throw new DeviceRootError("WEBAUTHN_UNLOCK_FAILED", "Device biometric authentication could not unlock this device.");
            } finally { prfOutput?.fill(0); }
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
            record.migration = { version: 1, state: "complete", binding };
            await store.put(record);
            await store.put({ id: "migration", version: 1, state: "complete" });
            this.state = { root, identity, created: false, record };
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
            const store = this._store();
            const record = await store.get();
            if (!record || record.version !== VERSION || !record.wrapSalt || !record.iv || !record.wrappedRoot) {
                throw new DeviceRootError("STORAGE_CORRUPT", "Device identity record is corrupt or unsupported. It was not changed.");
            }
            const root = await this._decryptRoot(record, currentMasterPin);
            try {
                const wrapSalt = this._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
                const wrapped = await this._encryptRoot(root, nextMasterPin, wrapSalt);
                const updated = { ...record, wrapSalt: b64(wrapSalt), ...wrapped };
                await store.put(updated);
                if (this.state?.root) this.state.record = updated;
                return Object.freeze({ rewrapped: true });
            } finally {
                root.fill(0);
            }
        },
        // Compatibility migration for records created before DeviceRoot moved
        // from the Account passphrase to the calculator master secret. The
        // caller must obtain this secret explicitly from the user after a
        // calculator unlock failure. A successful old-wrap decrypt is the
        // cryptographic proof of the legacy credential; the same root is then
        // atomically rewrapped and annotated, never recreated or replaced.
        async migrateLegacyAccountPassphrase(accountPassphrase, calculatorMasterPin) {
            this._requireCrypto();
            const store = this._store();
            const record = await store.get();
            if (!record || record.version !== VERSION || !record.wrapSalt || !record.iv || !record.wrappedRoot) {
                throw new DeviceRootError("STORAGE_CORRUPT", "Device identity record is corrupt or unsupported. It was not changed.");
            }
            const root = await this._decryptRoot(record, accountPassphrase);
            try {
                const wrapSalt = this._crypto.getRandomValues(new Uint8Array(WRAP_SALT_BYTES));
                const wrapped = await this._encryptRoot(root, calculatorMasterPin, wrapSalt);
                const migration = { ...(record.migration || {}), credentialDomain: "calculator-master-v1", migratedAt: Date.now() };
                const updated = { ...record, wrapSalt: b64(wrapSalt), ...wrapped, migration };
                await store.put(updated);
                if (this.state?.root) this.state.record = updated;
                return Object.freeze({ migrated: true });
            } finally {
                root.fill(0);
            }
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
