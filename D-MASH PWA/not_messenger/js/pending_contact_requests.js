// D-MASH // PENDING CONTACT REQUEST STORE // v1
// Device-root-protected local inbox. It deliberately has no Account dependency.
"use strict";
(function (global) {
    const VERSION = 1;
    const MATERIAL_NAME = "pending-contact-requests/v1";
    const STORAGE_KEY = "dmash.pending-contact-requests.v1";
    const AAD = new TextEncoder().encode("dmash/pending-contact-requests/v1");
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const STATUSES = Object.freeze({ PENDING: "pending", ACCEPTED: "accepted", REJECTED: "rejected" });
    const IDENTITY_KEYS = new Set(["account", "accountid", "account_id", "accountpublickey", "account_public_key"]);

    class PendingContactRequestError extends Error {
        constructor(code, message) { super(message); this.name = "PendingContactRequestError"; this.code = code; }
    }

    const clone = (value) => JSON.parse(JSON.stringify(value));
    const b64 = (bytes) => {
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return global.btoa(binary);
    };
    const unb64 = (value) => Uint8Array.from(global.atob(value), (char) => char.charCodeAt(0));
    const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

    class PendingContactRequestStore {
        constructor({ deviceRoot = global.DeviceRoot, storage = global.localStorage, crypto = global.crypto, now = () => Date.now(), idFactory } = {}) {
            this.deviceRoot = deviceRoot;
            this.storage = storage;
            this.crypto = crypto;
            this.now = now;
            this.idFactory = idFactory || (() => {
                const bytes = this.crypto.getRandomValues(new Uint8Array(16));
                return "pcr_" + Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
            });
            this.state = null;
        }

        static normalizeText(value, field, maxLength, required = true) {
            if ((value === undefined || value === null) && !required) return null;
            if (typeof value !== "string") throw new PendingContactRequestError("INVALID_" + field.toUpperCase(), field + " must be text.");
            const normalized = value.normalize("NFKC").trim();
            if ((required && !normalized) || normalized.length > maxLength || /[\u0000-\u001f\u007f]/.test(normalized)) {
                throw new PendingContactRequestError("INVALID_" + field.toUpperCase(), field + " is invalid.");
            }
            return normalized;
        }

        static normalizeDisplayName(value) {
            const normalized = PendingContactRequestStore.normalizeText(value, "display name", 128);
            return normalized.replace(/\s+/g, " ");
        }

        static normalizeBootstrap(value) {
            if (!isPlainObject(value)) throw new PendingContactRequestError("INVALID_BOOTSTRAP", "Bootstrap fields must be an object.");
            let serialized;
            try { serialized = JSON.stringify(value); } catch (_) { throw new PendingContactRequestError("INVALID_BOOTSTRAP", "Bootstrap fields must be serializable."); }
            if (serialized.length > 16384) throw new PendingContactRequestError("INVALID_BOOTSTRAP", "Bootstrap fields are too large.");
            const copy = JSON.parse(serialized);
            const inspect = (item) => {
                if (Array.isArray(item)) return item.forEach(inspect);
                if (!isPlainObject(item)) {
                    if (typeof item !== "string" && typeof item !== "number" && typeof item !== "boolean" && item !== null) throw new PendingContactRequestError("INVALID_BOOTSTRAP", "Bootstrap fields contain an invalid value.");
                    return;
                }
                for (const [key, child] of Object.entries(item)) {
                    if (IDENTITY_KEYS.has(key.toLowerCase())) throw new PendingContactRequestError("ACCOUNT_IDENTITY_FORBIDDEN", "Account identity must not be stored with a pending request.");
                    inspect(child);
                }
            };
            inspect(copy);
            return copy;
        }

        async _key() {
            if (!this.crypto?.subtle || !this.crypto?.getRandomValues || !this.deviceRoot?.deviceMaterial) {
                throw new PendingContactRequestError("CRYPTO_UNAVAILABLE", "Device-bound encryption is unavailable.");
            }
            const material = await this.deviceRoot.deviceMaterial(MATERIAL_NAME, () => this.crypto.getRandomValues(new Uint8Array(32)));
            if (!(material instanceof Uint8Array) || material.length !== 32) throw new PendingContactRequestError("INVALID_KEY", "Device key material is invalid.");
            return this.crypto.subtle.importKey("raw", material, "AES-GCM", false, ["encrypt", "decrypt"]);
        }

        _empty() { return { version: VERSION, requests: [] }; }
        _assertState(state) {
            if (!state || state.version !== VERSION || !Array.isArray(state.requests)) throw new PendingContactRequestError("STORAGE_CORRUPT", "Pending contact request storage is corrupt or unsupported.");
            const ids = new Set();
            for (const request of state.requests) {
                if (!isPlainObject(request) || typeof request.id !== "string" || !request.id || ids.has(request.id) || !Number.isFinite(request.receivedAt) || !Number.isFinite(request.updatedAt) || !Object.values(STATUSES).includes(request.status)) {
                    throw new PendingContactRequestError("STORAGE_CORRUPT", "Pending contact request storage is corrupt.");
                }
                PendingContactRequestStore.normalizeDisplayName(request.displayName);
                PendingContactRequestStore.normalizeText(request.intro, "intro", 2048, false);
                PendingContactRequestStore.normalizeText(request.replyRoute, "reply route", 4096);
                PendingContactRequestStore.normalizeText(request.receivedRoute, "received route", 4096);
                PendingContactRequestStore.normalizeBootstrap(request.bootstrap);
                ids.add(request.id);
            }
        }

        async load() {
            if (this.state) return clone(this.state);
            const stored = this.storage?.getItem(STORAGE_KEY);
            if (!stored) { this.state = this._empty(); return clone(this.state); }
            let envelope;
            try { envelope = JSON.parse(stored); } catch (_) { throw new PendingContactRequestError("STORAGE_CORRUPT", "Pending contact request storage cannot be decoded."); }
            if (!envelope || envelope.version !== VERSION || typeof envelope.iv !== "string" || typeof envelope.ciphertext !== "string") throw new PendingContactRequestError("STORAGE_CORRUPT", "Pending contact request storage is corrupt or unsupported.");
            try {
                const plaintext = await this.crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(envelope.iv), additionalData: AAD }, await this._key(), unb64(envelope.ciphertext));
                this.state = JSON.parse(decoder.decode(plaintext)); this._assertState(this.state);
                return clone(this.state);
            } catch (error) {
                if (error instanceof PendingContactRequestError) throw error;
                throw new PendingContactRequestError("STORAGE_CORRUPT", "Pending contact request storage could not be authenticated.");
            }
        }

        async _save() {
            this._assertState(this.state);
            const iv = this.crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await this.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, await this._key(), encoder.encode(JSON.stringify(this.state)));
            try { this.storage.setItem(STORAGE_KEY, JSON.stringify({ version: VERSION, iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) })); }
            catch (_) { throw new PendingContactRequestError("STORAGE_WRITE_FAILED", "Pending contact request storage could not be saved."); }
        }

        async add({ displayName, intro = null, replyRoute, bootstrap, receivedRoute, receivedAt = this.now() } = {}) {
            await this.load();
            displayName = PendingContactRequestStore.normalizeDisplayName(displayName);
            intro = PendingContactRequestStore.normalizeText(intro, "intro", 2048, false);
            replyRoute = PendingContactRequestStore.normalizeText(replyRoute, "reply route", 4096);
            receivedRoute = PendingContactRequestStore.normalizeText(receivedRoute, "received route", 4096);
            bootstrap = PendingContactRequestStore.normalizeBootstrap(bootstrap);
            if (!Number.isFinite(receivedAt) || receivedAt < 0) throw new PendingContactRequestError("INVALID_RECEIVED_AT", "Received time is invalid.");
            const id = this.idFactory();
            if (typeof id !== "string" || !id || this.state.requests.some(request => request.id === id)) throw new PendingContactRequestError("INVALID_ID", "Pending contact request identifier is invalid.");
            const request = { id, displayName, intro, replyRoute, bootstrap, receivedRoute, status: STATUSES.PENDING, receivedAt, updatedAt: this.now() };
            this.state.requests.push(request); await this._save(); return clone(request);
        }
        async list() { await this.load(); return clone(this.state.requests); }
        async read(id) { await this.load(); const request = this.state.requests.find(item => item.id === id); return request ? clone(request) : null; }
        async _setStatus(id, status) {
            await this.load(); const request = this.state.requests.find(item => item.id === id);
            if (!request) throw new PendingContactRequestError("NOT_FOUND", "Pending contact request was not found.");
            if (request.status !== STATUSES.PENDING) throw new PendingContactRequestError("ALREADY_RESOLVED", "Pending contact request is already resolved.");
            request.status = status; request.updatedAt = this.now(); await this._save(); return clone(request);
        }
        async reject(id) { return this._setStatus(id, STATUSES.REJECTED); }
        async accept(id) { return this._setStatus(id, STATUSES.ACCEPTED); }
    }

    global.PendingContactRequestStore = PendingContactRequestStore;
    global.PendingContactRequestError = PendingContactRequestError;
    if (typeof module !== "undefined") module.exports = { PendingContactRequestStore, PendingContactRequestError, MATERIAL_NAME, STORAGE_KEY, STATUSES };
})(typeof window !== "undefined" ? window : globalThis);
