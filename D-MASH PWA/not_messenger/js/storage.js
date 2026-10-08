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
    initGamma: function(keyBytes, {isCurrent = () => true} = {}) {
        return new Promise(async (resolve, reject) => {
            try {
                // Импортируем MasterKey для шифрования боксов на диске
                const masterKey = await window.crypto.subtle.importKey(
                    "raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
                );

                if (!isCurrent()) throw new Error("Account vault opening cancelled");

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
                    if (!isCurrent()) { e.target.result.close(); reject(new Error("Account vault opening cancelled")); return; }
                    this.masterKey = masterKey;
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
        const db = this.db, masterKey = this.masterKey, salt = Core.blindSalt, account = Core.activeIdentity;
        const check = () => {
            if (this.db !== db || this.masterKey !== masterKey || Core.blindSalt !== salt ||
                Core.activeIdentity !== account || Core._accountTransitioning)
                throw new Error('Account vault changed during message save');
        };
        const read = (table, alias) => new Promise((resolve, reject) => {
            check(); const tx = db.transaction(table, 'readonly'), request = tx.objectStore(table).get(alias);
            request.onsuccess = () => resolve(request.result ?? null);
            request.onerror = () => reject(request.error || Error('Message preflight failed'));
            tx.onabort = () => reject(tx.error || Error('Message preflight aborted'));
        });
        check(); const aliasL1 = await this.getAlias(peerID, 'L1'); check();
        const peerRaw = await read('blind_peers', aliasL1);
        const existingPeer = peerRaw ? await this.decryptBox(peerRaw.blob) : null; check();
        if (peerRaw && (!existingPeer || existingPeer.id !== peerID)) throw Error('Corrupt chat owner; no message saved');
        const secretAlias = window.DmashChatPassword ?
            await window.DmashChatPassword.location(this, aliasL1, 'L2', existingPeer?.chatLock) : aliasL1;
        check(); const secretRaw = await read('blind_secrets', secretAlias);
        const old = secretRaw ? await this.decryptBox(secretRaw.blob) : null; check();
        if (secretRaw && !old) throw Error('Corrupt chat counter; no message saved');
        const count = old?.msgCount ?? 0;
        if (!Number.isSafeInteger(count) || count < 0 || count >= 1000000) throw Error('Invalid chat counter; no message saved');
        const seqNum = count + 1, aliasL3 = await this.getAlias(aliasL1 + seqNum, 'L3'); check();
        const secrets = old ? {...old, msgCount: seqNum} :
            {msgCount: seqNum, psk: this.uint8ToHex(window.nacl.randomBytes(32)), epochShift: 0, staticShared: null};
        const peerInfo = existingPeer ? {...existingPeer} : {id: peerID, name: `Peer-${peerID.substring(0,4)}`};
        const ts = Date.now(); peerInfo.last_ts = ts;
        if (inbound && !isRead) peerInfo.unread = true;
        const protectedText = window.DmashChatPassword ? await window.DmashChatPassword.protect(this, peerID, text) : text;
        check(); const secretBlob = await this.encryptBox(secrets);
        const messageBlob = await this.encryptBox({text: protectedText, ts, inbound,
            transportState: inbound ? null : (transportState || 'SENT'), wireId});
        const peerBlob = await this.encryptBox(peerInfo); check();
        await new Promise((resolve, reject) => {
            const tx = db.transaction(['blind_secrets', 'blind_messages', 'blind_peers'], 'readwrite');
            let problem = null, remaining = 3;
            const fail = error => {problem = error; try {tx.abort();} catch (_) {reject(error);}};
            const actual = {}, lookups = [['blind_secrets', secretAlias], ['blind_messages', aliasL3], ['blind_peers', aliasL1]];
            for (const [table, alias] of lookups) {
                const request = tx.objectStore(table).get(alias);
                request.onsuccess = () => {
                    try {
                        check(); actual[table] = request.result ?? null;
                        if (--remaining) return;
                        if ((actual.blind_secrets?.blob ?? null) !== (secretRaw?.blob ?? null) ||
                            (actual.blind_peers?.blob ?? null) !== (peerRaw?.blob ?? null))
                            throw Error('Chat state changed; retry message save');
                        if (actual.blind_messages) throw Error('Existing message at next sequence; repair counter before sending');
                        tx.objectStore('blind_secrets').put({alias: secretAlias, blob: secretBlob});
                        tx.objectStore('blind_messages').put({alias: aliasL3, blob: messageBlob});
                        tx.objectStore('blind_peers').put({alias: aliasL1, blob: peerBlob});
                    } catch (error) {fail(error);}
                };
            }
            tx.oncomplete = () => {try {check(); resolve();} catch (error) {reject(error);}};
            tx.onabort = () => reject(problem || tx.error || Error('Message save aborted'));
            tx.onerror = () => {};
        });
        return seqNum;
    },

    // A key exchange may replace cryptographic session fields but must never
    // reset the independent, encrypted Gamma history counter. Compare the
    // exact encrypted owner rows inside one transaction; a concurrent message
    // append or chat-lock change makes this attempt retryable, never lossy.
    commitHandshakeSecretsGamma: async function(peerID, fields, {phase, expectedPendingAttempt = null} = {}) {
        if (!['init', 'final'].includes(phase) || !fields || typeof fields !== 'object' ||
            Object.hasOwn(fields, 'msgCount')) throw Error('Invalid handshake state update');
        const db = this.db, masterKey = this.masterKey, salt = Core.blindSalt, account = Core.activeIdentity;
        const check = () => {
            if (this.db !== db || this.masterKey !== masterKey || Core.blindSalt !== salt ||
                Core.activeIdentity !== account || Core._accountTransitioning)
                throw Error('Account vault changed during handshake');
        };
        const read = (table, alias) => new Promise((resolve, reject) => {
            check(); const tx = db.transaction(table, 'readonly'), request = tx.objectStore(table).get(alias);
            request.onsuccess = () => resolve(request.result ?? null);
            request.onerror = () => reject(request.error || Error('Handshake preflight failed'));
            tx.onabort = () => reject(tx.error || Error('Handshake preflight aborted'));
        });
        const aliasL1 = await this.getAlias(peerID, 'L1'); check();
        const peerRaw = await read('blind_peers', aliasL1);
        const peer = peerRaw ? await this.decryptBox(peerRaw.blob) : null; check();
        if (peerRaw && (!peer || peer.id !== peerID)) throw Error('Corrupt chat owner; handshake refused');
        const secretAlias = window.DmashChatPassword ?
            await window.DmashChatPassword.location(this, aliasL1, 'L2', peer?.chatLock) : aliasL1;
        check(); const previousRaw = await read('blind_secrets', secretAlias);
        const previous = previousRaw ? await this.decryptBox(previousRaw.blob) : null; check();
        if (previousRaw && !previous) throw Error('Corrupt chat counter; handshake refused');
        const count = previous?.msgCount ?? 0;
        if (!Number.isSafeInteger(count) || count < 0 || count > 1000000) throw Error('Invalid chat counter; handshake refused');
        if (phase === 'init' && (previous?.staticShared || previous?.pendingKyberInit)) throw Error('Handshake state changed; retry');
        if (phase === 'final' && (previous?.staticShared && !previous.pendingKyberInit ||
            previous?.pendingKyberInit && previous.pendingKyberInit.attempt_id !== expectedPendingAttempt))
            throw Error('Handshake state changed; retry');
        const next = {...previous, ...fields, msgCount: count};
        if (phase === 'init') delete next.kyberFinalReceipt;
        if (phase === 'final') {delete next.pendingKyberInit; delete next.pendingKyberFinal;}
        const blob = await this.encryptBox(next); check();
        await new Promise((resolve, reject) => {
            const tx = db.transaction(['blind_peers', 'blind_secrets'], 'readwrite');
            let problem = null, remaining = 2; const actual = {};
            const fail = error => {problem = error; try {tx.abort();} catch (_) {reject(error);}};
            for (const [table, alias] of [['blind_peers', aliasL1], ['blind_secrets', secretAlias]]) {
                const request = tx.objectStore(table).get(alias);
                request.onsuccess = () => {
                    try {
                        check(); actual[table] = request.result ?? null;
                        if (--remaining) return;
                        if ((actual.blind_peers?.blob ?? null) !== (peerRaw?.blob ?? null) ||
                            (actual.blind_secrets?.blob ?? null) !== (previousRaw?.blob ?? null))
                            throw Error('Handshake state changed; retry');
                        tx.objectStore('blind_secrets').put({alias: secretAlias, blob});
                    } catch (error) {fail(error);}
                };
            }
            tx.oncomplete = () => {try {check(); resolve();} catch (error) {reject(error);}};
            tx.onabort = () => reject(problem || tx.error || Error('Handshake state update aborted'));
            tx.onerror = () => {};
        });
        return next;
    },

    // Explicit recovery only. This deliberately requires a single-peer vault:
    // every raw message row must match the contiguous, authenticated aliases
    // for this peer. It never guesses ownership of a foreign or gapped row.
    _historyCounterProofGamma: async function(peerID, targetCount, expectedCurrentCount) {
        if (!/^[0-9a-f]{64}$/.test(peerID) || !Number.isSafeInteger(targetCount) ||
            targetCount < 1 || targetCount > 1000 || !Number.isSafeInteger(expectedCurrentCount) ||
            expectedCurrentCount < 0 || expectedCurrentCount >= targetCount)
            throw Error('Invalid history repair scope');
        const db = this.db, masterKey = this.masterKey, salt = Core.blindSalt, account = Core.activeIdentity;
        const check = () => {
            if (this.db !== db || this.masterKey !== masterKey || Core.blindSalt !== salt ||
                Core.activeIdentity !== account || Core._accountTransitioning)
                throw Error('Account vault changed during history inspection');
        };
        const read = (table, alias) => new Promise((resolve, reject) => {
            check(); const tx = db.transaction(table, 'readonly'), request = tx.objectStore(table).get(alias);
            request.onsuccess = () => resolve(request.result ?? null);
            request.onerror = () => reject(request.error || Error('History inspection failed'));
            tx.onabort = () => reject(tx.error || Error('History inspection aborted'));
        });
        check(); const aliasL1 = await this.getAlias(peerID, 'L1'); check();
        const peerRaw = await read('blind_peers', aliasL1);
        const peer = peerRaw ? await this.decryptBox(peerRaw.blob) : null; check();
        if (!peer || peer.id !== peerID || peer.chatLock) throw Error('History owner missing, corrupt, or locked');
        const secretRaw = await read('blind_secrets', aliasL1);
        const secrets = secretRaw ? await this.decryptBox(secretRaw.blob) : null; check();
        if (!secrets || secrets.msgCount !== expectedCurrentCount)
            throw Error('History counter changed or corrupt');
        const aliases = [];
        for (let i = 1; i <= targetCount; i++) {aliases.push(await this.getAlias(aliasL1 + i, 'L3')); check();}
        const boundary = await this.getAlias(aliasL1 + (targetCount + 1), 'L3'); check();
        const rawMessages = await new Promise((resolve, reject) => {
            check(); const tx = db.transaction('blind_messages', 'readonly'), request = tx.objectStore('blind_messages').getAll();
            request.onsuccess = () => resolve(request.result || []);
            request.onerror = () => reject(request.error || Error('History scan failed'));
            tx.onabort = () => reject(tx.error || Error('History scan aborted'));
        });
        check(); const found = new Map(rawMessages.map(row => [row.alias, row]));
        if (rawMessages.length !== targetCount || found.size !== targetCount || found.has(boundary) ||
            aliases.some(alias => !found.has(alias)))
            throw Error('History aliases are gapped or include another owner; repair refused');
        for (const alias of aliases) {
            const value = await this.decryptBox(found.get(alias).blob); check();
            if (!value || typeof value !== 'object' || !Object.hasOwn(value, 'text') ||
                !Number.isSafeInteger(value.ts) || typeof value.inbound !== 'boolean')
                throw Error('Corrupt history row; repair refused');
        }
        return {db, masterKey, check, aliasL1, peerRaw, secretRaw, secrets, aliases, rawMessages};
    },
    inspectHistoryCounterGamma: async function(peerID, targetCount, expectedCurrentCount = 0) {
        const proof = await this._historyCounterProofGamma(peerID, targetCount, expectedCurrentCount);
        proof.check();
        return {repairable: true, currentCount: expectedCurrentCount, contiguousCount: targetCount,
            totalMessageRows: proof.rawMessages.length, singlePeerVault: true};
    },
    repairHistoryCounterGamma: async function(peerID, targetCount, expectedCurrentCount = 0) {
        const proof = await this._historyCounterProofGamma(peerID, targetCount, expectedCurrentCount);
        const next = {...proof.secrets, msgCount: targetCount};
        proof.check(); const blob = await this.encryptBox(next); proof.check();
        await new Promise((resolve, reject) => {
            const tx = proof.db.transaction(['blind_peers', 'blind_secrets', 'blind_messages'], 'readwrite');
            let problem = null, remaining = 3; const actual = {};
            const fail = error => {problem = error; try {tx.abort();} catch (_) {reject(error);}};
            const requests = [['blind_peers', 'get', proof.aliasL1],
                ['blind_secrets', 'get', proof.aliasL1], ['blind_messages', 'getAll', null]];
            for (const [table, action, alias] of requests) {
                const request = tx.objectStore(table)[action](...(alias === null ? [] : [alias]));
                request.onsuccess = () => {
                    try {
                        proof.check(); actual[table] = request.result;
                        if (--remaining) return;
                        if ((actual.blind_peers?.blob ?? null) !== proof.peerRaw.blob ||
                            (actual.blind_secrets?.blob ?? null) !== proof.secretRaw.blob)
                            throw Error('History owner or counter changed; repair refused');
                        const before = proof.rawMessages, now = actual.blind_messages || [];
                        if (now.length !== before.length || now.some((row, i) =>
                            row.alias !== before[i].alias || row.blob !== before[i].blob))
                            throw Error('History changed during repair');
                        tx.objectStore('blind_secrets').put({alias: proof.aliasL1, blob});
                    } catch (error) {fail(error);}
                };
            }
            tx.oncomplete = () => {try {proof.check(); resolve();} catch (error) {reject(error);}};
            tx.onabort = () => reject(problem || tx.error || Error('History repair aborted'));
            tx.onerror = () => {};
        });
        return {repaired: true, previousCount: expectedCurrentCount, messageCount: targetCount};
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
    async markMessageSendFailure(peerID,wireId,reason) {
        const aliasL1=await this.getAlias(peerID,'L1'),secrets=await this.getBox('blind_secrets',aliasL1);
        for(let seq=secrets?.msgCount||0;seq>=1;seq--){
            const alias=await this.getAlias(aliasL1+seq,'L3'),message=await this.getBox('blind_messages',alias);
            if(!message||message.inbound||message.wireId!==wireId)continue;
            if(['DELIVERED','READ'].includes(message.transportState))return false;
            message.transportState='FAILED';message.failureReason=String(reason).slice(0,64);
            await this.putBox('blind_messages',{alias,data:message});return true;
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
            if (msg) messages.push({ ...msg, text: window.DmashChatPassword ? await window.DmashChatPassword.reveal(this, peerID, msg.text) : msg.text, id: i });
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
        // Resolve every owner-bound alias and inspect mixed-format rows before
        // deleting anything. New v4 records share pairing_material but use
        // their own authenticated formats; a legacy scan cannot claim them.
        const db = this.db, masterKey = this.masterKey, salt = Core.blindSalt, account = Core.activeIdentity;
        const check = () => {
            if (this.db !== db || this.masterKey !== masterKey || Core.blindSalt !== salt || Core.activeIdentity !== account)
                throw new Error('Account vault changed during chat deletion');
        };
        const readRaw = (storeName, alias) => new Promise((resolve, reject) => {
            check(); const tx = db.transaction(storeName, 'readonly'), request = tx.objectStore(storeName).get(alias);
            request.onsuccess = () => resolve(request.result ?? null);
            request.onerror = () => reject(request.error || new Error('Chat deletion preflight failed'));
            tx.onabort = () => reject(tx.error || new Error('Chat deletion preflight aborted'));
        });
        check();
        const aliasL1 = await this.getAlias(peerID, "L1");
        check();
        const peerRow = await readRaw('blind_peers', aliasL1);
        const peer = peerRow ? await this.decryptBox(peerRow.blob) : null;
        check();
        if (peerRow && !peer) throw new Error('Corrupt chat owner record; no data deleted');
        const secretsAlias = window.DmashChatPassword ? await window.DmashChatPassword.location(this, aliasL1, 'L2', peer?.chatLock) : aliasL1;
        check();
        const secretsRow = await readRaw('blind_secrets', secretsAlias);
        const secrets = secretsRow ? await this.decryptBox(secretsRow.blob) : null;
        check();
        if (secretsRow && !secrets) throw new Error('Corrupt chat owner record; no data deleted');
        if (secrets && (!Number.isSafeInteger(secrets.msgCount || 0) || secrets.msgCount < 0 || secrets.msgCount > 1000000))
            throw new Error('Corrupt chat message count; no data deleted');
        const messageAliases = [];
        for (let i = 1; i <= (secrets?.msgCount || 0); i++) {
            messageAliases.push(await this.getAlias(aliasL1 + i, "L3")); check();
        }
        const queued = await this.getAllBoxes('blind_outbox');
        check();
        const mappings = await this.getAllBoxes('pairing_material');
        check();
        const knownAlias = await this.getAlias('node-peer-v4:' + peerID, 'L2'); check();
        const knownRow = await readRaw('pairing_material', knownAlias);
        if (knownRow) {
            const known = await this.decryptBox(knownRow.blob); check();
            if (!known || typeof known !== 'object' || (known.peerId && known.peerId !== peerID))
                throw new Error('Corrupt Account route owner record; no data deleted');
        }
        const outboxAliases = queued.filter(item => item?.peerID === peerID).map(item => item.alias);
        const mappingAliases = mappings.filter(item => item?.peerId === peerID && !item.schema && !item.kind).map(item => item.alias);
        if (knownRow) mappingAliases.push(knownAlias);
        check();
        await new Promise((resolve, reject) => {
            const tx = db.transaction(['blind_messages', 'blind_peers', 'blind_secrets', 'blind_outbox', 'pairing_material'], 'readwrite');
            try {
                check();
                for (const alias of messageAliases) tx.objectStore('blind_messages').delete(alias);
                tx.objectStore('blind_peers').delete(aliasL1);
                tx.objectStore('blind_secrets').delete(secretsAlias);
                for (const alias of outboxAliases) tx.objectStore('blind_outbox').delete(alias);
                for (const alias of new Set(mappingAliases)) tx.objectStore('pairing_material').delete(alias);
            } catch (error) { try { tx.abort(); } catch (_) {} reject(error); return; }
            tx.oncomplete = () => { try { check(); resolve(); } catch (error) { reject(error); } };
            tx.onerror = () => reject(tx.error || new Error('chat deletion failed'));
            tx.onabort = () => reject(tx.error || new Error('chat deletion aborted'));
        });
        return {unknownPairingRows: mappings.filter(item => !item.peerId && item.alias !== knownAlias).length};
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
        return new Promise((res,rej) => {
            const tx = this.db.transaction(storeName, 'readwrite');
            tx.objectStore(storeName).put({ alias, blob });
            tx.oncomplete = () => res();
            tx.onerror=()=>rej(tx.error||new Error('Vault write failed'));tx.onabort=()=>rej(tx.error||new Error('Vault write aborted'));
        });
    },

    getBox: async function(storeName, alias) {
        return new Promise((res,rej) => {
            const tx = this.db.transaction(storeName, 'readonly');
            tx.objectStore(storeName).get(alias).onsuccess = async (e) => {
                if (!e.target.result) return res(null);
                const dec = await this.decryptBox(e.target.result.blob);
                res(dec);
            };
            tx.onerror=()=>rej(tx.error||new Error('Vault read failed'));tx.onabort=()=>rej(tx.error||new Error('Vault read aborted'));
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

// Keep the classic lexical module usable by separately loaded PWA runtimes.
// Acceptance may replace this with its encrypted registry adapter later.
window.DMashStorage ||= Storage;
