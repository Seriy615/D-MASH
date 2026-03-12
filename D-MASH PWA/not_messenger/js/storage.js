// D-MASH GAMMA-1 // STORAGE MODULE // V100.0 // SHADOW ARCHITECTURE
"use strict";

const Storage = {
    db: null,
    registry_instance: null,
    masterKey: null, // AES-GCM ключ (32 байта из Argon2)
    REGISTRY_DB: 'dm_registry_v1',
    REG_VER: 21, 

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
                const request = indexedDB.open("dm_gamma_vault", 1); 
                
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
    saveMessageGamma: async function(peerID, text, inbound, isRead) {
        const aliasL1 = await this.getAlias(peerID, "L1");
        
        let secrets = await this.getBox('blind_secrets', aliasL1);
        if (!secrets) {
            secrets = { msgCount: 0, psk: this.uint8ToHex(window.nacl.randomBytes(32)), epochShift: 0, staticShared: null };
        }
        
        const seqNum = (secrets.msgCount || 0) + 1;
        secrets.msgCount = seqNum;
        await this.putBox('blind_secrets', { alias: aliasL1, data: secrets });

        const aliasL3 = await this.getAlias(aliasL1 + seqNum, "L3");
        await this.putBox('blind_messages', { alias: aliasL3, data: { text, ts: Date.now(), inbound } });

        const peerInfo = await this.getBox('blind_peers', aliasL1) || { id: peerID, name: `Peer-${peerID.substring(0,4)}` };
        peerInfo.last_ts = Date.now();
        peerInfo.unread = (!isRead && inbound);
        await this.putBox('blind_peers', { alias: aliasL1, data: peerInfo });

        // ФИКС: Возвращаем SeqNum
        return seqNum;
    },

/**
     * ЗАГРУЗКА ЧАТА (Хронологический порядок)
     */
    loadMessagesGamma: async function(peerID, limit, offset) {
        const aliasL1 = await this.getAlias(peerID, "L1");
        const secrets = await this.getBox('blind_secrets', aliasL1);
        if (!secrets) return [];

        const total = secrets.msgCount || 0;
        // Считаем границы: от старых к новым
        const end = Math.max(1, total - offset);
        const start = Math.max(1, end - limit + 1);
        
        const messages = [];
        for (let i = start; i <= end; i++) {
            const aliasL3 = await this.getAlias(aliasL1 + i, "L3");
            const msg = await this.getBox('blind_messages', aliasL3);
            if (msg) messages.push({ ...msg, id: i });
        }
        return messages; // Теперь возвращает [Старое, ..., Новое]
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
            const tx = this.db.transaction('blind_messages', 'readwrite');
            const store = tx.objectStore('blind_messages');
            for (let i = 1; i <= secrets.msgCount; i++) {
                const aliasL3 = await this.getAlias(aliasL1 + i, "L3");
                store.delete(aliasL3);
            }
        }
        
        const tx2 = this.db.transaction(['blind_peers', 'blind_secrets'], 'readwrite');
        tx2.objectStore('blind_peers').delete(aliasL1);
        tx2.objectStore('blind_secrets').delete(aliasL1);
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