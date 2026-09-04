// D-MASH // QUICK NAME REGISTRY // v1
// Isolated, device-bound encrypted registry.  This file intentionally has no
// dependency on the legacy Storage module or application UI.
"use strict";
(function (global) {
    const VERSION = 1;
    const MATERIAL_NAME = "quick-name-registry/v1";
    const STORAGE_KEY = "dmash.quick-name-registry.v1";
    const AAD = new TextEncoder().encode("dmash/quick-name-registry/v1");
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    class QuickNameRegistryError extends Error {
        constructor(code, message) { super(message); this.name = "QuickNameRegistryError"; this.code = code; }
    }

    const clone = (value) => JSON.parse(JSON.stringify(value));
    const b64 = (bytes) => {
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return global.btoa(binary);
    };
    const unb64 = (value) => Uint8Array.from(global.atob(value), (char) => char.charCodeAt(0));

    class QuickNameRegistry {
        constructor({ deviceRoot = global.DeviceRoot, storage = global.localStorage, crypto = global.crypto, now = () => Date.now(), idFactory } = {}) {
            this.deviceRoot = deviceRoot;
            this.storage = storage;
            this.crypto = crypto;
            this.now = now;
            this.idFactory = idFactory || (() => {
                const bytes = this.crypto.getRandomValues(new Uint8Array(16));
                return "qn_" + Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
            });
            this.state = null;
        }

        static normalizeName(name) {
            if (typeof name !== "string") throw new QuickNameRegistryError("INVALID_NAME", "Quick Name must be text.");
            const normalized = name.normalize("NFKC").trim().replace(/\s+/g, " ");
            if (!normalized || normalized.length > 64 || /[\u0000-\u001f\u007f]/.test(normalized)) {
                throw new QuickNameRegistryError("INVALID_NAME", "Quick Name must contain 1 to 64 printable characters.");
            }
            return normalized;
        }

        static normalizeValue(value) {
            if (typeof value !== "string") throw new QuickNameRegistryError("INVALID_VALUE", "Quick Name value must be text.");
            const normalized = value.trim();
            if (!normalized || normalized.length > 512 || /[\u0000-\u001f\u007f]/.test(normalized)) {
                throw new QuickNameRegistryError("INVALID_VALUE", "Quick Name value must contain 1 to 512 printable characters.");
            }
            return normalized;
        }

        async _key() {
            if (!this.crypto?.subtle || !this.crypto?.getRandomValues || !this.deviceRoot?.deviceMaterial) {
                throw new QuickNameRegistryError("CRYPTO_UNAVAILABLE", "Device-bound encryption is unavailable.");
            }
            const material = await this.deviceRoot.deviceMaterial(MATERIAL_NAME, () => this.crypto.getRandomValues(new Uint8Array(32)));
            if (!(material instanceof Uint8Array) || material.length !== 32) throw new QuickNameRegistryError("INVALID_KEY", "Device key material is invalid.");
            return this.crypto.subtle.importKey("raw", material, "AES-GCM", false, ["encrypt", "decrypt"]);
        }

        _empty() { return { version: VERSION, entries: [], defaultId: null }; }
        _assertState(state) {
            if (!state || state.version !== VERSION || !Array.isArray(state.entries) || (state.defaultId !== null && typeof state.defaultId !== "string")) {
                throw new QuickNameRegistryError("STORAGE_CORRUPT", "Quick Name registry is corrupt or unsupported.");
            }
            const ids = new Set(), names = new Set();
            for (const entry of state.entries) {
                if (!entry || typeof entry.id !== "string" || ids.has(entry.id)) throw new QuickNameRegistryError("STORAGE_CORRUPT", "Quick Name registry contains duplicate identifiers.");
                const name = QuickNameRegistry.normalizeName(entry.name);
                QuickNameRegistry.normalizeValue(entry.value);
                const key = name.toLocaleLowerCase();
                if (names.has(key)) throw new QuickNameRegistryError("STORAGE_CORRUPT", "Quick Name registry contains duplicate names.");
                ids.add(entry.id); names.add(key);
            }
            if (state.defaultId !== null && !ids.has(state.defaultId)) throw new QuickNameRegistryError("STORAGE_CORRUPT", "Quick Name registry default is missing.");
        }

        async load() {
            if (this.state) return clone(this.state);
            const stored = this.storage?.getItem(STORAGE_KEY);
            if (!stored) { this.state = this._empty(); return clone(this.state); }
            let envelope;
            try { envelope = JSON.parse(stored); } catch (_) { throw new QuickNameRegistryError("STORAGE_CORRUPT", "Quick Name registry cannot be decoded."); }
            if (!envelope || envelope.version !== VERSION || typeof envelope.iv !== "string" || typeof envelope.ciphertext !== "string") {
                throw new QuickNameRegistryError("STORAGE_CORRUPT", "Quick Name registry is corrupt or unsupported.");
            }
            try {
                const plaintext = await this.crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(envelope.iv), additionalData: AAD }, await this._key(), unb64(envelope.ciphertext));
                this.state = JSON.parse(decoder.decode(plaintext));
                this._assertState(this.state);
                return clone(this.state);
            } catch (error) {
                if (error instanceof QuickNameRegistryError) throw error;
                throw new QuickNameRegistryError("STORAGE_CORRUPT", "Quick Name registry could not be authenticated.");
            }
        }

        async _save() {
            this._assertState(this.state);
            const iv = this.crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await this.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, await this._key(), encoder.encode(JSON.stringify(this.state)));
            try { this.storage.setItem(STORAGE_KEY, JSON.stringify({ version: VERSION, iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) })); }
            catch (_) { throw new QuickNameRegistryError("STORAGE_WRITE_FAILED", "Quick Name registry could not be saved."); }
        }

        async list() { await this.load(); return clone(this.state.entries); }
        async getDefault() { await this.load(); const entry = this.state.entries.find(item => item.id === this.state.defaultId); return entry ? clone(entry) : null; }
        _find(id) { const entry = this.state.entries.find(item => item.id === id); if (!entry) throw new QuickNameRegistryError("NOT_FOUND", "Quick Name was not found."); return entry; }
        _ensureUnique(name, exceptId = null) {
            if (this.state.entries.some(entry => entry.id !== exceptId && entry.name.toLocaleLowerCase() === name.toLocaleLowerCase())) throw new QuickNameRegistryError("DUPLICATE_NAME", "A Quick Name with this name already exists.");
        }

        async add({ name, value, makeDefault = false } = {}) {
            await this.load(); name = QuickNameRegistry.normalizeName(name); value = QuickNameRegistry.normalizeValue(value); this._ensureUnique(name);
            const timestamp = this.now(); const entry = { id: this.idFactory(), name, value, createdAt: timestamp, updatedAt: timestamp, lastUsedAt: null };
            if (!entry.id || this.state.entries.some(item => item.id === entry.id)) throw new QuickNameRegistryError("INVALID_ID", "Quick Name identifier is invalid.");
            this.state.entries.push(entry); if (makeDefault || this.state.defaultId === null) this.state.defaultId = entry.id;
            await this._save(); return clone(entry);
        }
        async edit(id, { name, value } = {}) {
            await this.load(); const entry = this._find(id);
            if (name !== undefined) { name = QuickNameRegistry.normalizeName(name); this._ensureUnique(name, id); entry.name = name; }
            if (value !== undefined) entry.value = QuickNameRegistry.normalizeValue(value);
            if (name === undefined && value === undefined) throw new QuickNameRegistryError("NO_CHANGES", "Quick Name edit has no changes.");
            entry.updatedAt = this.now(); await this._save(); return clone(entry);
        }
        async remove(id) {
            await this.load(); const index = this.state.entries.findIndex(entry => entry.id === id); if (index < 0) throw new QuickNameRegistryError("NOT_FOUND", "Quick Name was not found.");
            const [removed] = this.state.entries.splice(index, 1);
            if (this.state.defaultId === id) this.state.defaultId = this.state.entries[0]?.id || null;
            await this._save(); return clone(removed);
        }
        async move(id, index) {
            await this.load(); if (!Number.isInteger(index) || index < 0 || index >= this.state.entries.length) throw new QuickNameRegistryError("INVALID_ORDER", "Quick Name order is invalid.");
            const old = this.state.entries.findIndex(entry => entry.id === id); if (old < 0) throw new QuickNameRegistryError("NOT_FOUND", "Quick Name was not found.");
            const [entry] = this.state.entries.splice(old, 1); this.state.entries.splice(index, 0, entry); await this._save(); return clone(this.state.entries);
        }
        async markRecent(id) { await this.load(); const entry = this._find(id); entry.lastUsedAt = this.now(); await this._save(); return clone(entry); }
        async recent(limit = 5) { await this.load(); if (!Number.isInteger(limit) || limit < 0) throw new QuickNameRegistryError("INVALID_LIMIT", "Recent limit is invalid."); return clone(this.state.entries.filter(entry => entry.lastUsedAt !== null).sort((a, b) => b.lastUsedAt - a.lastUsedAt).slice(0, limit)); }
        async setDefault(id) { await this.load(); this._find(id); this.state.defaultId = id; await this._save(); return this.getDefault(); }
    }

    global.QuickNameRegistry = QuickNameRegistry;
    global.QuickNameRegistryError = QuickNameRegistryError;
    if (typeof module !== "undefined") module.exports = { QuickNameRegistry, QuickNameRegistryError, MATERIAL_NAME, STORAGE_KEY };
})(typeof window !== "undefined" ? window : globalThis);
