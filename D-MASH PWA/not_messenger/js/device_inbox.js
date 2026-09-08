"use strict";

(function (global) {
    const MAX_BYTES = 32 * 1024 * 1024;
    const MAX_RECORDS = 16384;
    const text = value => new TextEncoder().encode(value);
    const codec = () => global.DmashSecureSession;

    class DeviceRecordStore {
        constructor(indexedDb = global.indexedDB) { this.indexedDb = indexedDb; this.db = null; this.opening = null; }
        async open() {
            if (this.db) return this.db;
            if (!this.opening) this.opening = new Promise((resolve, reject) => {
                const request = this.indexedDb.open('dmash_device_inbox_v1', 1);
                request.onupgradeneeded = () => request.result.createObjectStore('records', { keyPath: 'key' });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    this.db = request.result;
                    this.db.onversionchange = () => { this.db.close(); this.db = null; this.opening = null; };
                    resolve(this.db);
                };
            });
            return this.opening;
        }
        async all() {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const tx = db.transaction('records', 'readonly');
                const request = tx.objectStore('records').getAll();
                tx.oncomplete = () => resolve(request.result);
                tx.onabort = () => reject(tx.error);
            });
        }
        async get(key) {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const tx = db.transaction('records', 'readonly');
                const request = tx.objectStore('records').get(key);
                tx.oncomplete = () => resolve(request.result || null);
                tx.onabort = () => reject(tx.error);
            });
        }
        async write(record, onlyIfAbsent = false) {
            const db = await this.open();
            return new Promise((resolve, reject) => {
                const tx = db.transaction('records', 'readwrite'), store = tx.objectStore('records');
                let inserted = false, failure = null;
                const request = store.getAll();
                request.onsuccess = () => {
                    const now = Date.now(), rows = [];
                    for (const row of request.result) {
                        if (row.retireAt && row.retireAt <= now) store.delete(row.key);
                        else rows.push(row);
                    }
                    const previous = rows.find(row => row.key === record.key);
                    if (previous && onlyIfAbsent) return;
                    const size = rows.reduce((sum, row) => sum + row.size, 0) - (previous?.size || 0) + record.size;
                    if (size > MAX_BYTES || (!previous && rows.length >= MAX_RECORDS)) {
                        failure = new Error('Device Inbox quota reached'); tx.abort(); return;
                    }
                    store.put(record); inserted = true;
                };
                tx.oncomplete = () => resolve(inserted);
                tx.onabort = () => reject(failure || tx.error);
            });
        }
        close() { this.db?.close(); this.db = null; this.opening = null; }
    }

    class DeviceInbox {
        constructor({ store = new DeviceRecordStore(), getRoot, getActiveAccount = () => null,
                      onAccount = async () => false, onDevice = async () => false } = {}) {
            this.store = store; this.getRoot = getRoot; this.getActiveAccount = getActiveAccount;
            this.onAccount = onAccount; this.onDevice = onDevice;
            this.serial = Promise.resolve();
        }
        _root() {
            const root = this.getRoot?.();
            if (!(root instanceof Uint8Array) || root.length !== 32) throw new Error('Device locked');
            return root;
        }
        _check(root) { if (this.getRoot?.() !== root) throw new Error('Device locked or changed'); }
        async _material(root, domain) {
            const bytes = await codec().hkdf(root, new Uint8Array(32), text('D-MASH|DEVICE-INBOX|V1|' + domain), 32);
            this._check(root);
            return bytes;
        }
        async _alias(root, label) {
            const bytes = await this._material(root, 'ALIAS');
            try {
                const key = await global.crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
                const hash = new Uint8Array(await global.crypto.subtle.sign('HMAC', key, text(label)));
                this._check(root);
                return codec().b64(hash);
            } finally { bytes.fill(0); }
        }
        async _key(root, usage) {
            const bytes = await this._material(root, 'STORAGE');
            try { return await global.crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, [usage]); }
            finally { bytes.fill(0); }
        }
        async _write(label, value, onlyIfAbsent = false, retireAt = 0) {
            const root = this._root(), alias = await this._alias(root, label);
            const key = await this._key(root, 'encrypt');
            const iv = global.crypto.getRandomValues(new Uint8Array(12));
            const plaintext = text(codec().canonical(value));
            let ciphertext;
            try { ciphertext = new Uint8Array(await global.crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: text(alias) }, key, plaintext)); }
            finally { plaintext.fill(0); }
            this._check(root);
            return this.store.write({ key: alias, iv: codec().b64(iv), ciphertext: codec().b64(ciphertext),
                size: ciphertext.length + 128, retireAt }, onlyIfAbsent);
        }
        async _open(record) {
            const root = this._root(), key = await this._key(root, 'decrypt');
            const plaintext = new Uint8Array(await global.crypto.subtle.decrypt({ name: 'AES-GCM', iv: codec().unb64(record.iv, 12), additionalData: text(record.key) }, key, codec().unb64(record.ciphertext)));
            try {
                this._check(root);
                return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
            } finally { plaintext.fill(0); }
        }
        async _get(label) {
            const root = this._root(), alias = await this._alias(root, label);
            const record = await this.store.get(alias);
            this._check(root);
            return record ? this._open(record) : null;
        }
        async registerRoute(routeId, { scope, accountSlot = null } = {}) {
            if (typeof routeId !== 'string' || !routeId || routeId.length > 256 ||
                !['DEVICE', 'ACCOUNT'].includes(scope) ||
                (scope === 'ACCOUNT' && (typeof accountSlot !== 'string' || !accountSlot || accountSlot.length > 512))) throw new Error('Invalid Device route policy');
            await this._write('route:' + routeId, { record: 'route', routeId, scope, accountSlot });
        }
        async _dispatch(envelope, policy) {
            if (policy.scope === 'DEVICE') return await this.onDevice(envelope) === true;
            if (this.getActiveAccount() !== policy.accountSlot) return false;
            return await this.onAccount(envelope, policy.accountSlot) === true;
        }
        async _process(envelope, policy) {
            if (!policy) return 'DEVICE_STORED';
            if (await this._dispatch(envelope, policy)) {
                await this._write('packet:' + envelope.packet_id, { record: 'seen', packetId: envelope.packet_id }, false, Date.now() + 30 * 86400000);
                return 'PROCESSED';
            }
            return 'DEVICE_STORED';
        }
        _exclusive(callback) {
            const run = () => global.navigator?.locks?.request
                ? global.navigator.locks.request('dmash-device-inbox-v1', callback) : callback();
            const result = this.serial.then(run);
            this.serial = result.catch(() => {});
            return result;
        }
        receive(ciphertext, recipientSecretKey) {
            return this._exclusive(async () => {
                this._root();
                const envelope = global.DeviceEnvelope.open(recipientSecretKey, ciphertext);
                const policy = await this._get('route:' + envelope.route_id);
                const inserted = await this._write('packet:' + envelope.packet_id,
                    { record: 'pending', envelope, policy }, true);
                if (!inserted) return 'DUPLICATE';
                // Persist before calling any Account or Device handler. A
                // callback failure leaves the opaque payload for retry.
                return this._process(envelope, policy);
            });
        }
        drain(accountSlot = null) {
            return this._exclusive(async () => {
                const root = this._root(), results = [];
                for (const row of await this.store.all()) {
                    const record = await this._open(row);
                    this._check(root);
                    if (record.record !== 'pending') continue;
                    // A route may be restored after the Node already drained
                    // its mailbox. Keep unknown-route payloads encrypted until
                    // local authority is available; never infer an Account.
                    const policy = record.policy || await this._get('route:' + record.envelope.route_id);
                    if (!policy) continue;
                    if (accountSlot !== null && (policy.scope !== 'ACCOUNT' || policy.accountSlot !== accountSlot)) continue;
                    results.push(await this._process(record.envelope, policy));
                }
                return results;
            });
        }
        async canPull() {
            this._root();
            const rows = await this.store.all();
            return rows.length + 256 <= MAX_RECORDS && rows.reduce((n, row) => n + row.size, 0) + 1024 * 1024 <= MAX_BYTES;
        }
        stageTransport(nodeId, entries) {
            return this._exclusive(async () => {
                for (const entry of entries) {
                    if (typeof entry.delivery_id !== 'string' || typeof entry.ciphertext !== 'string' || entry.ciphertext.length > 65536) throw new Error('Invalid mailbox entry');
                    const label = 'transport:' + nodeId + ':' + entry.delivery_id;
                    await this._write(label, {record: 'transport', label, ciphertext: entry.ciphertext}, true);
                }
            });
        }
        async drainTransport(receiver) {
            const results = [];
            for (const row of await this.store.all()) {
                const record = await this._open(row);
                if (record.record !== 'transport') continue;
                try {
                    const result = await receiver(record.ciphertext);
                    await this._write(record.label, {record: 'transport_seen'}, false, Date.now() + 86400000);
                    results.push(result);
                } catch (_) {
                    // Keep even unknown/temporarily undecryptable Device boxes.
                    // A bad entry must not prevent the rest of a drain.
                    results.push('DEVICE_STORED');
                }
            }
            return results;
        }
    }
    global.DeviceRecordStore = DeviceRecordStore;
    global.DeviceInbox = DeviceInbox;
    if (typeof module !== 'undefined') module.exports = { DeviceInbox, DeviceRecordStore };
})(typeof window !== 'undefined' ? window : globalThis);
