"use strict";
(function (global) {
    const CHUNK = 256 * 1024, MAX = 64 * 1024 * 1024;
    const ACCOUNT_QUOTA = 256 * 1024 * 1024, INBOUND_PEER_QUOTA = 128 * 1024 * 1024;
    const encoder = new TextEncoder(), decoder = new TextDecoder();
    const isId = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
    const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    const currentError = () => Error('Account changed during file operation');
    const request = (db, storeName, alias) => new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const q = tx.objectStore(storeName).get(alias);
        q.onsuccess = () => resolve(q.result || null);
        q.onerror = () => reject(q.error || Error('File vault read failed'));
        tx.onabort = () => reject(tx.error || Error('File vault read aborted'));
    });

    class FileVault {
        constructor(core, storage) { this.core = core; this.storage = storage; }

        capture() {
            const core = this.core, storage = this.storage, keys = core.keys, salt = core.blindSalt;
            const slot = core.activeIdentity, db = storage.db, key = storage.masterKey;
            const root = global.DeviceRoot?.state;
            // pub_hex is the full Account bundle (signing + box + PQ keys),
            // while server_id is the stable 32-byte signing identity.
            const owner = keys?.server_id ||
                (keys?.sign?.publicKey ? core.bytesToHex(keys.sign.publicKey) : null);
            if (!isId(owner) || !salt || !slot || !db || !key || !root || core._accountTransitioning ||
                !db.objectStoreNames.contains('blind_files') || !db.objectStoreNames.contains('blind_file_owners'))
                throw Error('FILE_VAULT_UNAVAILABLE: Откройте аккаунт и повторите передачу.');
            const check = () => {
                if (core.keys !== keys || core.blindSalt !== salt || core.activeIdentity !== slot ||
                    storage.db !== db || storage.masterKey !== key || global.DeviceRoot?.state !== root ||
                    core._accountTransitioning) throw currentError();
            };
            return {owner, db, key, check};
        }

        async alias(session, label, level) {
            session.check();
            const alias = await this.storage.getAlias(label, level);
            session.check();
            return alias;
        }

        ownerAlias(session) { return this.alias(session, 'file-owner-v1:' + session.owner, 'L2'); }
        fileAlias(session, peer, fileId) {
            if (!isId(peer) || !isId(fileId)) throw Error('Invalid file owner');
            return this.alias(session, 'file-v1:' + session.owner + ':' + peer + ':' + fileId, 'L3');
        }

        async seal(session, alias, kind, value) {
            session.check();
            const iv = global.crypto.getRandomValues(new Uint8Array(12));
            const cipher = await global.crypto.subtle.encrypt({name: 'AES-GCM', iv,
                additionalData: encoder.encode(`D-MASH|LOCAL-FILE|1|${kind}|${alias}`)},
            session.key, encoder.encode(JSON.stringify(value)));
            session.check();
            return {iv, cipher};
        }

        async open(session, alias, kind, row) {
            session.check();
            if (!row || row.alias !== alias || !(row.iv instanceof Uint8Array) || row.iv.length !== 12 ||
                !(row.cipher instanceof ArrayBuffer)) throw Error('Corrupt file vault record');
            const plain = await global.crypto.subtle.decrypt({name: 'AES-GCM', iv: row.iv,
                additionalData: encoder.encode(`D-MASH|LOCAL-FILE|1|${kind}|${alias}`)}, session.key, row.cipher);
            session.check();
            return JSON.parse(decoder.decode(plain));
        }

        async owner(session, ownerAlias) {
            const row = await request(session.db, 'blind_file_owners', ownerAlias);
            session.check();
            const value = row ? await this.open(session, ownerAlias, 'owner', row) :
                {schema: 'dmash_file_owner_v1', account: session.owner, entries: []};
            if (value?.schema !== 'dmash_file_owner_v1' || value.account !== session.owner ||
                !Array.isArray(value.entries) || value.entries.length > 4096 ||
                value.entries.some(entry => !isId(entry.peer) || !isId(entry.fileId) || !isId(entry.alias) ||
                    !Number.isSafeInteger(entry.size) || entry.size < 1 || entry.size > MAX ||
                    typeof entry.inbound !== 'boolean' ||
                    !['waiting', 'connecting', 'sending', 'delivered', 'failed', 'cancelled'].includes(entry.status) ||
                    (entry.inbound && entry.status !== 'delivered')) ||
                new Set(value.entries.map(entry => entry.alias)).size !== value.entries.length)
                throw Error('Corrupt file owner inventory');
            return {row, value};
        }

        validMeta(session, peer, fileId, meta) {
            return meta?.schema === 'dmash_file_v1' && meta.account === session.owner &&
                meta.peer === peer && meta.fileId === fileId && isId(meta.sha256) &&
                Number.isSafeInteger(meta.size) && meta.size >= 1 && meta.size <= MAX &&
                typeof meta.name === 'string' && meta.name.length >= 1 && meta.name.length <= 255 &&
                typeof meta.mime === 'string' && meta.mime.length <= 128 &&
                typeof meta.inbound === 'boolean' &&
                ['waiting', 'connecting', 'sending', 'delivered', 'failed', 'cancelled'].includes(meta.status) &&
                (!meta.inbound || meta.status === 'delivered') &&
                Number.isSafeInteger(meta.attempts) && meta.attempts >= 0 &&
                Number.isSafeInteger(meta.nextAttempt) && meta.nextAttempt >= 0 &&
                Number.isSafeInteger(meta.createdAt) && meta.createdAt > 0;
        }

        ensureCapacity(entries, peer, size, inbound) {
            const accountBytes = entries.reduce((total, entry) => total + entry.size, 0);
            if (accountBytes + size > ACCOUNT_QUOTA)
                throw Error('Недостаточно места в защищённом хранилище файлов: лимит аккаунта 256 МиБ. Удалите старые файлы.');
            if (inbound) {
                const peerBytes = entries.filter(entry => entry.inbound && entry.peer === peer)
                    .reduce((total, entry) => total + entry.size, 0);
                if (peerBytes + size > INBOUND_PEER_QUOTA)
                    throw Error('Недостаточно места для файлов от этого контакта: лимит 128 МиБ. Удалите старые файлы.');
            }
        }

        async _encryptBody(session, alias, fileId, size, sha256, blob) {
            const nonce = global.crypto.getRandomValues(new Uint8Array(8));
            const parts = [];
            for (let index = 0; index < Math.ceil(size / CHUNK); index++) {
                session.check();
                const iv = new Uint8Array(12); iv.set(nonce); new DataView(iv.buffer).setUint32(8, index);
                const chunk = await blob.slice(index * CHUNK, Math.min(size, (index + 1) * CHUNK)).arrayBuffer();
                parts.push(await global.crypto.subtle.encrypt({name: 'AES-GCM', iv,
                    additionalData: encoder.encode(`D-MASH|LOCAL-FILE-BODY|1|${alias}|${fileId}|${index}|${size}|${sha256}`)}, session.key, chunk));
                session.check();
            }
            return {nonce, body: new Blob(parts, {type: 'application/octet-stream'})};
        }

        async _decryptBody(session, alias, meta, row) {
            if (!(row.nonce instanceof Uint8Array) || row.nonce.length !== 8 || !(row.body instanceof Blob))
                throw Error('Corrupt encrypted file body');
            const parts = [], count = Math.ceil(meta.size / CHUNK);
            if (row.body.size !== meta.size + count * 16) throw Error('Encrypted file size mismatch');
            let offset = 0;
            for (let index = 0; index < count; index++) {
                session.check();
                const length = Math.min(CHUNK, meta.size - index * CHUNK) + 16;
                const iv = new Uint8Array(12); iv.set(row.nonce); new DataView(iv.buffer).setUint32(8, index);
                const bytes = await row.body.slice(offset, offset + length).arrayBuffer(); offset += length;
                parts.push(await global.crypto.subtle.decrypt({name: 'AES-GCM', iv,
                    additionalData: encoder.encode(`D-MASH|LOCAL-FILE-BODY|1|${alias}|${meta.fileId}|${index}|${meta.size}|${meta.sha256}`)}, session.key, bytes));
                session.check();
            }
            const blob = new Blob(parts, {type: 'application/octet-stream'});
            const digest = hex(new Uint8Array(await global.crypto.subtle.digest('SHA-256', await blob.arrayBuffer())));
            session.check();
            if (digest !== meta.sha256) throw Error('Stored file integrity mismatch');
            return blob;
        }

        async put(peer, fileId, blob, details) {
            const session = this.capture();
            if (!isId(peer) || !isId(fileId) || !(blob instanceof Blob) || blob.size < 1 || blob.size > MAX ||
                !isId(details?.sha256) || !Number.isSafeInteger(details.size) || details.size !== blob.size ||
                typeof details.name !== 'string' || !details.name || details.name.length > 255 ||
                typeof details.mime !== 'string' || details.mime.length > 128 ||
                typeof details.inbound !== 'boolean') throw Error('Invalid local file');
            const alias = await this.fileAlias(session, peer, fileId), ownerAlias = await this.ownerAlias(session);
            const initialOwner = await this.owner(session, ownerAlias);
            const prior = initialOwner.value.entries.find(entry => entry.alias === alias);
            if (prior) {
                if (prior.peer !== peer || prior.fileId !== fileId || prior.size !== blob.size ||
                    prior.inbound !== details.inbound) throw Error('File owner collision');
                const existing = await this.meta(peer, fileId, session);
                if (existing?.sha256 !== details.sha256 || existing.name !== details.name ||
                    existing.mime !== details.mime) throw Error('File identity collision');
                return existing;
            }
            this.ensureCapacity(initialOwner.value.entries, peer, blob.size, details.inbound);
            // The sender computes this digest before queueing; the receiver's
            // FileChannel verifies it before invoking onCommit. Do not hash a
            // 64 MiB buffer a second time on the critical delivery path.
            const digest = details.sha256;
            const meta = {schema: 'dmash_file_v1', account: session.owner, peer, fileId, size: blob.size,
                sha256: digest, name: details.name, mime: details.mime, inbound: details.inbound,
                status: details.inbound ? 'delivered' : 'waiting', attempts: 0, nextAttempt: 0, createdAt: Date.now()};
            const sealedMeta = await this.seal(session, alias, 'meta', meta);
            const encrypted = await this._encryptBody(session, alias, fileId, blob.size, digest, blob);
            for (let attempt = 0; attempt < 3; attempt++) {
                const owner = await this.owner(session, ownerAlias);
                const known = owner.value.entries.find(entry => entry.alias === alias);
                if (known) {
                    if (known.peer !== peer || known.fileId !== fileId || known.size !== blob.size ||
                        known.inbound !== details.inbound) throw Error('File owner collision');
                    const existing = await this.meta(peer, fileId, session);
                    if (existing?.sha256 !== digest || existing.name !== details.name ||
                        existing.mime !== details.mime) throw Error('File identity collision');
                    return existing;
                }
                this.ensureCapacity(owner.value.entries, peer, blob.size, details.inbound);
                const next = {...owner.value, entries: [...owner.value.entries,
                    {alias, peer, fileId, size: blob.size, inbound: details.inbound, status: meta.status}]};
                if (next.entries.length > 4096) throw Error('Локальное хранилище файлов заполнено. Удалите старые файлы.');
                const sealedOwner = await this.seal(session, ownerAlias, 'owner', next);
                try {
                    await new Promise((resolve, reject) => {
                        session.check();
                        const tx = session.db.transaction(['blind_files', 'blind_file_owners'], 'readwrite');
                        const q = tx.objectStore('blind_file_owners').get(ownerAlias);
                        q.onsuccess = () => {
                            try {
                                session.check();
                                const actual = q.result || null;
                                if ((actual?.revision || 0) !== (owner.row?.revision || 0)) throw Error('File inventory changed');
                                tx.objectStore('blind_files').add({alias, ...sealedMeta, ...encrypted, revision: 1});
                                tx.objectStore('blind_file_owners').put({alias: ownerAlias, ...sealedOwner,
                                    revision: (owner.row?.revision || 0) + 1});
                            } catch (error) {try {tx.abort();} catch (_) {} reject(error);}
                        };
                        q.onerror = () => reject(q.error || Error('File inventory read failed'));
                        tx.oncomplete = () => {try {session.check(); resolve();} catch (error) {reject(error);}};
                        tx.onabort = () => reject(tx.error || Error('File vault commit failed'));
                        tx.onerror = () => {};
                    });
                    return meta;
                } catch (error) {
                    if (error.message === 'File inventory changed') continue;
                    if (error.name === 'QuotaExceededError') throw Error('Недостаточно места для сохранения файла. Передача не подтверждена.');
                    throw error;
                }
            }
            throw Error('File inventory changed; retry');
        }

        async meta(peer, fileId, session = this.capture()) {
            const alias = await this.fileAlias(session, peer, fileId);
            const row = await request(session.db, 'blind_files', alias); session.check();
            if (!row) return null;
            const meta = await this.open(session, alias, 'meta', row);
            if (!this.validMeta(session, peer, fileId, meta)) throw Error('Corrupt file owner');
            return meta;
        }

        async get(peer, fileId) {
            const session = this.capture(), alias = await this.fileAlias(session, peer, fileId);
            const row = await request(session.db, 'blind_files', alias); session.check();
            if (!row) return null;
            const meta = await this.open(session, alias, 'meta', row);
            if (!this.validMeta(session, peer, fileId, meta)) throw Error('Corrupt file owner');
            return {meta, blob: await this._decryptBody(session, alias, meta, row)};
        }

        async update(peer, fileId, status, changes = {}) {
            if (!['waiting', 'connecting', 'sending', 'delivered', 'failed', 'cancelled'].includes(status) ||
                Object.keys(changes).some(key => !['attempts', 'nextAttempt'].includes(key)) ||
                (changes.attempts !== undefined && (!Number.isSafeInteger(changes.attempts) || changes.attempts < 0 || changes.attempts > 1000000)) ||
                (changes.nextAttempt !== undefined && (!Number.isSafeInteger(changes.nextAttempt) || changes.nextAttempt < 0)))
                throw Error('Invalid file transfer state');
            const session = this.capture(), alias = await this.fileAlias(session, peer, fileId);
            const ownerAlias = await this.ownerAlias(session);
            for (let attempt = 0; attempt < 3; attempt++) {
                const owner = await this.owner(session, ownerAlias);
                const index = owner.value.entries.findIndex(entry => entry.alias === alias && entry.peer === peer && entry.fileId === fileId);
                if (index < 0) throw Error('File owner missing');
                const row = await request(session.db, 'blind_files', alias); session.check();
                if (!row) throw Error('File body missing');
                const previous = await this.open(session, alias, 'meta', row);
                if (!this.validMeta(session, peer, fileId, previous) ||
                    previous.size !== owner.value.entries[index].size ||
                    previous.status !== owner.value.entries[index].status)
                    throw Error('Corrupt file owner');
                if (previous.inbound && status !== 'delivered') throw Error('Inbound file is committed');
                if ((previous.status === 'delivered' && status !== 'delivered') ||
                    (previous.status === 'cancelled' && status !== 'delivered')) return previous;
                const next = {...previous, status, ...changes};
                const nextOwner = {...owner.value, entries: owner.value.entries.map((entry, i) =>
                    i === index ? {...entry, status} : entry)};
                const sealedMeta = await this.seal(session, alias, 'meta', next);
                const sealedOwner = await this.seal(session, ownerAlias, 'owner', nextOwner);
                try {
                    await new Promise((resolve, reject) => {
                        session.check();
                        const tx = session.db.transaction(['blind_files', 'blind_file_owners'], 'readwrite');
                        const q = tx.objectStore('blind_files').get(alias), o = tx.objectStore('blind_file_owners').get(ownerAlias);
                        let currentFile, currentOwner, received = 0;
                        const write = () => {
                            if (++received !== 2) return;
                            try {
                                session.check();
                                if ((currentFile?.revision || 0) !== (row.revision || 0) ||
                                    (currentOwner?.revision || 0) !== (owner.row?.revision || 0))
                                    throw Error('File inventory changed');
                                tx.objectStore('blind_files').put({...row, ...sealedMeta, revision: (row.revision || 0) + 1});
                                tx.objectStore('blind_file_owners').put({alias: ownerAlias, ...sealedOwner,
                                    revision: (owner.row?.revision || 0) + 1});
                            } catch (error) {try {tx.abort();} catch (_) {} reject(error);}
                        };
                        q.onsuccess = () => {currentFile = q.result; write();};
                        o.onsuccess = () => {currentOwner = o.result; write();};
                        q.onerror = o.onerror = () => reject(Error('File inventory read failed'));
                        tx.oncomplete = () => {try {session.check(); resolve();} catch (error) {reject(error);}};
                        tx.onabort = () => reject(tx.error || Error('File state update failed'));
                        tx.onerror = () => {};
                    });
                    return next;
                } catch (error) {
                    if (error.message === 'File inventory changed') continue;
                    throw error;
                }
            }
            throw Error('File inventory changed; retry');
        }

        async list(peer = null, statuses = null) {
            const session = this.capture(), ownerAlias = await this.ownerAlias(session);
            const {value} = await this.owner(session, ownerAlias);
            const entries = value.entries.filter(entry => (!peer || entry.peer === peer) &&
                (!statuses || statuses.includes(entry.status)));
            const out = [];
            for (const entry of entries) {
                if (entry.alias !== await this.fileAlias(session, entry.peer, entry.fileId))
                    throw Error('Corrupt file owner inventory');
                const meta = await this.meta(entry.peer, entry.fileId, session);
                if (!meta || meta.size !== entry.size || meta.inbound !== entry.inbound ||
                    meta.status !== entry.status) throw Error('Corrupt file inventory');
                out.push(meta);
            }
            return out;
        }

        async prepareDeletePeer(peer) {
            const session = this.capture(), ownerAlias = await this.ownerAlias(session);
            if (!isId(peer)) throw Error('Invalid file peer');
            const owner = await this.owner(session, ownerAlias);
            const entries = owner.value.entries.filter(entry => entry.peer === peer);
            for (const entry of entries) {
                if (entry.alias !== await this.fileAlias(session, peer, entry.fileId))
                    throw Error('Corrupt file owner; chat deletion refused');
                const meta = await this.meta(peer, entry.fileId, session);
                if (!meta || meta.size !== entry.size || meta.inbound !== entry.inbound ||
                    meta.status !== entry.status)
                    throw Error('Corrupt file owner; chat deletion refused');
            }
            const next = {...owner.value, entries: owner.value.entries.filter(entry => entry.peer !== peer)};
            const sealedOwner = entries.length ? await this.seal(session, ownerAlias, 'owner', next) : null;
            session.check();
            return {ownerAlias, revision: owner.row?.revision || 0, aliases: entries.map(entry => entry.alias),
                sealedOwner, check: session.check};
        }
        async prepareDeleteOne(peer, fileId) {
            const session = this.capture(), ownerAlias = await this.ownerAlias(session);
            const alias = await this.fileAlias(session, peer, fileId);
            const owner = await this.owner(session, ownerAlias);
            const entry = owner.value.entries.find(item => item.alias === alias && item.peer === peer && item.fileId === fileId);
            if (!entry) throw Error('File owner missing; message deletion refused');
            const meta = await this.meta(peer, fileId, session);
            if (!meta || meta.size !== entry.size || meta.inbound !== entry.inbound ||
                meta.status !== entry.status)
                throw Error('Corrupt file owner; message deletion refused');
            const next = {...owner.value, entries: owner.value.entries.filter(item => item.alias !== alias)};
            const sealedOwner = await this.seal(session, ownerAlias, 'owner', next);
            session.check();
            return {alias, ownerAlias, revision: owner.row?.revision || 0,
                sealedOwner, check: session.check};
        }
    }
    global.DmashFileVault = FileVault;
})(typeof window !== 'undefined' ? window : globalThis);
