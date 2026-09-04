// D-MASH GAMMA-1 // STORAGE MODULE // V100.0 // SHADOW ARCHITECTURE
"use strict";

const Storage = {
    db: null,
    registry_instance: null,
    masterKey: null, // AES-GCM ключ (32 байта из Argon2)
    REGISTRY_DB: 'dm_registry_v1',
    REG_VER: 23,

    /**
     * ИНИЦИАЛИЗАЦИЯ СЛЕПОГО СЕЙФА (Gamma-1)
     */
    initGamma: function(keyBytes) {
        return new Promise(async (resolve, reject) => {
            try {
                // Импортируем MasterKey для шифрования боксов на диске
                this.masterKey = await window.crypto.subtle.importKey(
                    "raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
                );

                // Открываем теневое хранилище
                const request = indexedDB.open("dm_gamma_vault", this.REG_VER);

                request.onupgradeneeded = (e) => {
                    const db = e.target.result;
                    // L1: Список кентов (Алиасы L1)
                    if (!db.objectStoreNames.contains('blind_peers')) {
                        db.createObjectStore('blind_peers', { keyPath: 'alias' });
                    }
                    // L2: Секреты переписки (Алиасы L2)
                    if (!db.objectStoreNames.contains('blind_secrets')) {
                        db.createObjectStore('blind_secrets', { keyPath: 'alias' });
                    }
                    // L3: Сами малявы (Алиасы L3)
                    if (!db.objectStoreNames.contains('blind_messages')) {
                        db.createObjectStore('blind_messages', { keyPath: 'alias' });
                    }
                    if (!db.objectStoreNames.contains('pairing_material')) {
                        db.createObjectStore('pairing_material', { keyPath: 'alias' });
                    }
                    // Outbound content waits encrypted at rest until a Mesh
                    // route becomes usable; it never goes into localStorage.
                    if (!db.objectStoreNames.contains('blind_outbox')) {
                        db.createObjectStore('blind_outbox', { keyPath: 'alias' });
                    }
                };

                request.onsuccess = (e) => {
                    this.db = e.target.result;
                    resolve();
                };

                request.onerror = (e) => reject(e);
            } catch (e) { reject(e); }
        });
    },

    /**
     * ГЕНЕРАЦИЯ СЛЕПОГО АЛИАСА (L1, L2, L3)
     * Использует RAM-only SecretSalt из Core
     */
    getAlias: async function(base, level = "L1") {
        const msg = new TextEncoder().encode(base + level);
        const combined = new Uint8Array(msg.length + Core.blindSalt.length);
        combined.set(msg);
        combined.set(Core.blindSalt, msg.length);
        // Дергаем быстрый хеш из Core
        return await Core.fastHash(combined);
    },

    /**
     * СОХРАНЕНИЕ МАЛЯВЫ (Gamma-1: Blind Pagination)
     */
// В storage.js измени saveMessageGamma:
    saveMessageGamma: async function(peerID, text, inbound, isRead, transportState = null, wireId = null) {
        const aliasL1 = await this.getAlias(peerID, "L1");

        let secrets = await this.getBox('blind_secrets', aliasL1);
        if (!secrets) {
            secrets = { msgCount: 0, psk: this.uint8ToHex(window.nacl.randomBytes(32)), epochShift: 0, staticShared: null };
        }

        const seqNum = (secrets.msgCount || 0) + 1;
        secrets.msgCount = seqNum;
        await this.putBox('blind_secrets', { alias: aliasL1, data: secrets });

        const aliasL3 = await this.getAlias(aliasL1 + seqNum, "L3");
        await this.putBox('blind_messages', {
            alias: aliasL3,
            // Outgoing data has only entered local transport at this point.
            // Do not claim DELIVERED or READ without authenticated receipts.
            data: { text, ts: Date.now(), inbound, transportState: inbound ? null : (transportState || 'SENT'), wireId }
        });

        const peerInfo = await this.getBox('blind_peers', aliasL1) || { id: peerID, name: `Peer-${peerID.substring(0,4)}` };
        peerInfo.last_ts = Date.now();
        // An outgoing message or a read inbound message must not erase a
        // previously pending unread marker; only opening the chat clears it.
        if (inbound && !isRead) peerInfo.unread = true;
        await this.putBox('blind_peers', { alias: aliasL1, data: peerInfo });

        // ФИКС: Возвращаем SeqNum
        return seqNum;
    },

    hasMessageWireId: async function(peerID, wireId) {
        if (!wireId) return false;
        const aliasL1 = await this.getAlias(peerID, 'L1');
        const secrets = await this.getBox('blind_secrets', aliasL1);
        for (let seq = secrets?.msgCount || 0; seq >= 1; seq--) {
            const alias = await this.getAlias(aliasL1 + seq, 'L3');
            const message = await this.getBox('blind_messages', alias);
            if (message?.wireId === wireId) return true;
        }
        return false;
    },

    // Receipt references are opaque random message IDs carried only inside the
    // end-to-end encrypted payload.  Search is bounded by this peer's local
    // message count; no identity or message metadata is exposed to a node.
    updateMessageTransportState: async function(peerID, wireId, transportState) {
        if (!wireId || !['DELIVERED', 'READ'].includes(transportState)) return false;
        const aliasL1 = await this.getAlias(peerID, 'L1');
        const secrets = await this.getBox('blind_secrets', aliasL1);
        for (let seq = secrets?.msgCount || 0; seq >= 1; seq--) {
            const alias = await this.getAlias(aliasL1 + seq, 'L3');
            const message = await this.getBox('blind_messages', alias);
            if (!message || message.inbound || message.wireId !== wireId) continue;
            const rank = { SENT: 0, DELIVERED: 1, READ: 2 };
            if ((rank[message.transportState] || 0) >= rank[transportState]) return true;
            message.transportState = transportState;
            await this.putBox('blind_messages', { alias, data: message });
            return true;
        }
        return false;
    },

    markInboundMessagesRead: async function(peerID) {
        const aliasL1 = await this.getAlias(peerID, 'L1');
        const secrets = await this.getBox('blind_secrets', aliasL1);
        const newlyReadWireIds = [];
        for (let seq = 1; seq <= (secrets?.msgCount || 0); seq++) {
            const alias = await this.getAlias(aliasL1 + seq, 'L3');
            const message = await this.getBox('blind_messages', alias);
            if (!message?.inbound || message.readAt) continue;
            message.readAt = Date.now();
            if (message.wireId) newlyReadWireIds.push(message.wireId);
            await this.putBox('blind_messages', { alias, data: message });
        }
        return newlyReadWireIds;
    },

/**
     * ЗАГРУЗКА ЧАТА (Хронологический порядок)
     */
    loadMessagesGamma: async function(peerID, limit, offset) {
        const aliasL1 = await this.getAlias(peerID, "L1");
        const secrets = await this.getBox('blind_secrets', aliasL1);
        if (!secrets) return [];

        const total = secrets.msgCount || 0;
        // Pages are returned in chronological order. The caller atomically
        // paints the initial page, preventing progressive early-message paint.
        const end = Math.max(1, total - offset);
        const start = Math.max(1, end - limit + 1);

        const messages = [];
        for (let i = start; i <= end; i++) {
            const aliasL3 = await this.getAlias(aliasL1 + i, "L3");
            const msg = await this.getBox('blind_messages', aliasL3);
            if (msg) messages.push({ ...msg, id: i });
        }
        return messages; // [Старое, ..., Новое]
    },

    /**
     * СОХРАНЕНИЕ КОНТАКТА (L1)
     */
savePeerGamma: async function(id, name) {
        const aliasL1 = await this.getAlias(id, "L1");
        const peerInfo = await this.getBox('blind_peers', aliasL1) || { id, name, securityAlert: false };
        peerInfo.name = name;
        // Сохраняем, не трогая флаг securityAlert если он уже там был
        await this.putBox('blind_peers', { alias: aliasL1, data: peerInfo });
    },

    /**
     * ЗАГРУЗКА СПИСКА КОНТАКТОВ
     */
    loadPeersGamma: function() {
        return new Promise((res) => {
            const tx = this.db.transaction('blind_peers', 'readonly');
            tx.objectStore('blind_peers').getAll().onsuccess = async (e) => {
                const rawRecords = e.target.result || [];
                const decryptedPeers = [];
                for (let r of rawRecords) {
                    const dec = await this.decryptBox(r.blob);
                    if (dec) decryptedPeers.push({ ...dec, alias: r.alias });
                }
                decryptedPeers.sort((a, b) => (b.last_ts || 0) - (a.last_ts || 0));
                res(decryptedPeers);
            };
        });
    },
deleteMessageGamma: async function(peerID, msgId) {
        const aliasL1 = await this.getAlias(peerID, "L1");
        const aliasL3 = await this.getAlias(aliasL1 + msgId, "L3");
        return new Promise((res) => {
            const tx = this.db.transaction('blind_messages', 'readwrite');
            tx.objectStore('blind_messages').delete(aliasL3);
            tx.oncomplete = () => {
                console.log(`[Storage] Малява ${msgId} для ${peerID.substring(0,8)} зачищена.`);
                res();
            };
        });
    },
    /**
     * УДАЛЕНИЕ ЧАТА (Снос всех уровней)
     */
    deleteChatGamma: async function(peerID) {
        const aliasL1 = await this.getAlias(peerID, "L1");
        const secrets = await this.getBox('blind_secrets', aliasL1);

        if (secrets && secrets.msgCount) {
            const messageAliases = [];
            for (let i = 1; i <= secrets.msgCount; i++) {
                messageAliases.push(await this.getAlias(aliasL1 + i, "L3"));
            }
            const tx = this.db.transaction('blind_messages', 'readwrite');
            const store = tx.objectStore('blind_messages');
            messageAliases.forEach(aliasL3 => store.delete(aliasL3));
            await new Promise((resolve, reject) => {
                tx.oncomplete = resolve;
                tx.onerror = () => reject(tx.error || new Error('message deletion failed'));
                tx.onabort = () => reject(tx.error || new Error('message deletion aborted'));
            });
        }

        await new Promise((resolve, reject) => {
            const tx2 = this.db.transaction(['blind_peers', 'blind_secrets'], 'readwrite');
            tx2.objectStore('blind_peers').delete(aliasL1);
            tx2.objectStore('blind_secrets').delete(aliasL1);
            tx2.oncomplete = resolve;
            tx2.onerror = () => reject(tx2.error || new Error('peer deletion failed'));
            tx2.onabort = () => reject(tx2.error || new Error('peer deletion aborted'));
        });
        const queued = await this.getAllBoxes('blind_outbox');
        await Promise.all(queued.filter(item => item?.peerID === peerID).map(item => this.deleteBox('blind_outbox', item.alias)));
    },

    async getAllBoxes(storeName) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(storeName, 'readonly');
            const request = tx.objectStore(storeName).getAll();
            request.onerror = () => reject(request.error || new Error('vault read failed'));
            request.onsuccess = async () => {
                try {
                    const values = await Promise.all((request.result || []).map(async item => ({ ...(await this.decryptBox(item.blob)), alias: item.alias })));
                    resolve(values.filter(Boolean));
                } catch (error) { reject(error); }
            };
        });
    },
    deleteBox(storeName, alias) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction(storeName, 'readwrite');
            tx.objectStore(storeName).delete(alias);
            tx.oncomplete = resolve; tx.onerror = () => reject(tx.error || new Error('vault delete failed'));
        });
    },

    /**
     * РАБОТА С БОКСАМИ (AES-GCM)
     */
    putBox: async function(storeName, { alias, data }) {
        const blob = await this.encryptBox(data);
        return new Promise((res) => {
            const tx = this.db.transaction(storeName, 'readwrite');
            tx.objectStore(storeName).put({ alias, blob });
            tx.oncomplete = () => res();
        });
    },

    getBox: async function(storeName, alias) {
        return new Promise((res) => {
            const tx = this.db.transaction(storeName, 'readonly');
            tx.objectStore(storeName).get(alias).onsuccess = async (e) => {
                if (!e.target.result) return res(null);
                const dec = await this.decryptBox(e.target.result.blob);
                res(dec);
            };
        });
    },

    encryptBox: async function(data) {
        const enc = new TextEncoder().encode(JSON.stringify(data));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const res = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, this.masterKey, enc);
        const packed = new Uint8Array(iv.length + res.byteLength);
        packed.set(iv);
        packed.set(new Uint8Array(res), 12);
        return this.uint8ToBase64(packed);
    },

    decryptBox: async function(b64) {
        try {
            const raw = this.base64ToUint8(b64);
            const iv = raw.slice(0, 12);
            const data = raw.slice(12);
            const dec = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, this.masterKey, data);
            return JSON.parse(new TextDecoder().decode(dec));
        } catch (e) { return null; }
    },

    /**
     * РЕЕСТР АККАУНТОВ (Внешняя полка)
     */
    openRegistry: function() {
        return new Promise((resolve, reject) => {
            if (this.registry_instance) return resolve(this.registry_instance);
            const request = indexedDB.open(this.REGISTRY_DB, this.REG_VER);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('accounts')) db.createObjectStore('accounts', { keyPath: 'id' });
            };
            request.onsuccess = (e) => { this.registry_instance = e.target.result; resolve(this.registry_instance); };
            request.onerror = reject;
        });
    },

    registerAccount: async function(identity, pubHex) {
        const db = await this.openRegistry();
        return new Promise((resolve) => {
            const tx = db.transaction('accounts', 'readwrite');
            const store = tx.objectStore('accounts');
            store.get(identity).onsuccess = (ev) => {
                const data = ev.target.result || { id: identity, pk: pubHex, notified: false };
                data.pk = pubHex;
                store.put(data);
                tx.oncomplete = resolve;
            };
        });
    },

    getAllRegistryAccounts: async function() {
        const db = await this.openRegistry();
        return new Promise((res) => {
            const tx = db.transaction('accounts', 'readonly');
            tx.objectStore('accounts').getAll().onsuccess = (e) => res(e.target.result || []);
        });
    },

    updateAccountAuth: async function(id, params) {
        const db = await this.openRegistry();
        return new Promise((resolve) => {
            const tx = db.transaction('accounts', 'readwrite');
            const store = tx.objectStore('accounts');
            store.get(id).onsuccess = (ev) => {
                const data = ev.target.result || { id: id };
                Object.assign(data, params);
                store.put(data);
                tx.oncomplete = resolve;
            };
        });
    },

    getRegistryAccount: async function(id) {
        const db = await this.openRegistry();
        return new Promise((res) => {
            db.transaction('accounts', 'readonly').objectStore('accounts').get(id).onsuccess = (e) => res(e.target.result);
        });
    },

    removeAccountFromRegistry: async function(id) {
        const db = await this.openRegistry();
        return new Promise((res) => {
            const tx = db.transaction('accounts', 'readwrite');
            tx.objectStore('accounts').delete(id);
            tx.oncomplete = res;
        });
    },

    // --- УТИЛИТЫ (Стрелочные, чтоб не ломать Strict Mode) ---
    uint8ToBase64: (b) => btoa(Array.from(b).map(c => String.fromCharCode(c)).join('')),
    base64ToUint8: (s) => new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0))),
    uint8ToHex: (b) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
};
