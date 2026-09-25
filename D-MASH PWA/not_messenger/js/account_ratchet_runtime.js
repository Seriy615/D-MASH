// D-MASH ACCOUNT RATCHET RUNTIME
// Packet and control-plane orchestration kept separate from the Core UI engine.
// The module is deliberately late-bound: Core, Storage, the ratchet primitives,
// and the optional ML-KEM runtime may finish loading in any order.
"use strict";

(function (global) {
    const PACKET_DOMAIN = new TextEncoder().encode('D-MASH|ACCOUNT|RATCHET|V1|PACKET\0');

    const peerOperations = new WeakMap();
    function accountGuard(core) {
        const keys = core.keys, sign = keys?.sign, identity = core.activeIdentity, publicKey = keys?.pub_hex;
        return () => {
            if (core.keys !== keys || core.keys?.sign !== sign || core.keys?.pub_hex !== publicKey ||
                core.activeIdentity !== identity || core._accountTransitioning) throw Error('Account session changed');
        };
    }
    function exclusive(core, pid, operation) {
        const check = accountGuard(core);
        let peers = peerOperations.get(core);
        if (!peers) { peers = new Map(); peerOperations.set(core, peers); }
        if (!peers.has(pid) && peers.size >= 1024) return Promise.reject(Error('Ratchet operation quota reached'));
        const previous = peers.get(pid) || Promise.resolve();
        const result = previous.catch(() => {}).then(() => { check(); return operation(); });
        peers.set(pid, result);
        const cleanup = () => { if (peers.get(pid) === result) peers.delete(pid); };
        result.then(cleanup, cleanup);
        return result;
    }
    async function persist(ctx, secrets) {
        ctx.check();
        await ctx.storage.putBox('blind_secrets', {alias: ctx.alias, data: secrets});
        ctx.check();
    }

    function ratchetApi() {
        const api = global.DmashAccountRatchet;
        if (!api) throw new Error('Account ratchet unavailable');
        return api;
    }

    function storageApi() {
        const storage = global.DMashStorage || global.Storage;
        if (storage?.getAlias && storage?.getBox && storage?.putBox) return storage;
        // `Storage` is a global lexical binding in the classic storage.js
        // script. Guard the lookup so the browser's native Storage constructor
        // can never be mistaken for D-MASH storage.
        if (typeof Storage !== 'undefined' && Storage?.getAlias && Storage?.getBox && Storage?.putBox) return Storage;
        throw new Error('D-MASH storage unavailable');
    }

    function direction(core, pid, outbound = true) {
        const self = String(core.keys.pub_hex).toLowerCase();
        const peer = String(pid).toLowerCase();
        // The label describes the canonical sender/recipient ordering. For
        // inbound packets `pid` is the sender, so reverse the comparison.
        return (outbound ? self < peer : peer < self) ? 'A_TO_B' : 'B_TO_A';
    }

    async function encryptPacket(core, data, pid, secrets) {
        const ratchet = ratchetApi();
        const root = core.hexToBytes(secrets.ratchetRoot);
        const id = ratchet.randomMessageId();
        const epoch = secrets.ratchetEpoch;
        const epochBytes = new Uint8Array(8);
        const epochView = new DataView(epochBytes.buffer);
        epochView.setUint32(0, Math.floor(epoch / 0x100000000), false);
        epochView.setUint32(4, epoch >>> 0, false);
        const nonce = global.nacl.randomBytes(24);
        const key = await ratchet.deriveMessageKey(root, direction(core, pid), epoch, id);
        const plaintext = new TextEncoder().encode(typeof data === 'object' ? JSON.stringify(data) : data);
        const cipher = global.nacl.secretbox(plaintext, nonce, key);
        const signed = new Uint8Array(PACKET_DOMAIN.length + epochBytes.length + id.length + nonce.length + cipher.length);
        let offset = 0;
        for (const part of [PACKET_DOMAIN, epochBytes, id, nonce, cipher]) {
            signed.set(part, offset);
            offset += part.length;
        }
        const signature = global.nacl.sign.detached(signed, core.keys.sign.secretKey);
        const packet = new Uint8Array(1 + epochBytes.length + id.length + nonce.length + signature.length + cipher.length);
        packet[0] = 0x04;
        offset = 1;
        for (const part of [epochBytes, id, nonce, signature, cipher]) {
            packet.set(part, offset);
            offset += part.length;
        }
        return core.bytesToHex(packet);
    }

    async function decryptPacket(core, raw, pid, secrets) {
        const ratchet = ratchetApi();
        if (!secrets?.ratchetRoot || raw.length < 1 + 8 + 16 + 24 + 64 + 16) return null;
        const epochView = new DataView(raw.buffer, raw.byteOffset + 1, 8);
        const epoch = epochView.getUint32(0, false) * 0x100000000 + epochView.getUint32(4, false);
        if (!Number.isSafeInteger(epoch)) return null;
        let rootHex = epoch === secrets.ratchetEpoch ? secrets.ratchetRoot : null;
        if (!rootHex && Array.isArray(secrets.ratchetPreviousRoots)) {
            rootHex = secrets.ratchetPreviousRoots.find(entry => entry?.epoch === epoch)?.root;
        }
        if (!/^[0-9a-f]{64}$/i.test(rootHex || '')) return null;
        const id = raw.slice(9, 25);
        const nonce = raw.slice(25, 49);
        const signature = raw.slice(49, 113);
        const cipher = raw.slice(113);
        if (cipher.length > 4 * 1024 * 1024) return null;
        const epochBytes = raw.slice(1, 9);
        const signed = new Uint8Array(PACKET_DOMAIN.length + epochBytes.length + id.length + nonce.length + cipher.length);
        let offset = 0;
        for (const part of [PACKET_DOMAIN, epochBytes, id, nonce, cipher]) {
            signed.set(part, offset);
            offset += part.length;
        }
        if (!global.nacl.sign.detached.verify(signed, signature, core.hexToBytes(pid))) return null;
        const key = await ratchet.deriveMessageKey(core.hexToBytes(rootHex), direction(core, pid, false), epoch, id);
        const opened = global.nacl.secretbox.open(cipher, nonce, key);
        return opened ? new TextDecoder().decode(opened) : null;
    }

    async function context(core, pid, secrets = null) {
        const ratchet = ratchetApi();
        const storage = storageApi(), check = accountGuard(core);
        const alias = await storage.getAlias(pid, 'L1');
        check();
        secrets = secrets || await storage.getBox('blind_secrets', alias);
        check();
        if (!secrets?.staticShared || !/^[0-9a-f]{64}$/i.test(secrets.staticShared)) {
            throw Error('Account channel is not established');
        }
        const rootHex = /^[0-9a-f]{64}$/i.test(secrets.ratchetRoot || '') ? secrets.ratchetRoot : secrets.staticShared;
        let lastUpdate = null;
        if (secrets.ratchetLastUpdate) {
            const update = ratchet.payloadToUpdate(secrets.ratchetLastUpdate);
            lastUpdate = {epoch: update.epoch, entropy: update.entropy, update_id: update.update_id};
        }
        const state = new ratchet.RatchetState({root: core.hexToBytes(rootHex), epoch: secrets.ratchetEpoch || 0, lastUpdate});
        return {alias, secrets, state, ratchet, storage, check};
    }

    async function handleUpdate(core, message, pid) {
        const contextValue = await context(core, pid);
        const suite = message?.suite;
        const isPqc = !!message?.update?.pqc;
        if (suite !== (isPqc ? 'HYBRID_MLKEM768_V2' : 'CLASSICAL_ROOT_V2')) throw Error('Ratchet control version incompatible; update both peers');
        let update;
        if (isPqc) {
            if (!core.keys.kyber?.secretKey) throw Error('ML-KEM key unavailable');
            const capsule = core.hexToBytes(message.update.pqc.capsule);
            const kyber = global.DmashKyberWasm;
            if (!kyber) throw Error('ML-KEM runtime unavailable');
            const decapsulated = kyber.decapsulate(capsule, core.keys.kyber.secretKey);
            if (!decapsulated.success) throw Error('ML-KEM decapsulation failed');
            update = await contextValue.ratchet.pqcPayloadToUpdate(message.update, decapsulated.ss);
        } else {
            update = contextValue.ratchet.payloadToUpdate(message?.update);
        }
        const updateId = core.bytesToHex(update.update_id);
        if (contextValue.secrets.ratchetSuperseded?.some(entry => entry.epoch === update.epoch && entry.id === updateId)) return true;
        const pending = contextValue.secrets.ratchetPending;
        const pendingWire = pending?.wire || pending;
        if (pendingWire && pendingWire.from_epoch === update.from_epoch && contextValue.state.epoch === update.from_epoch) {
            // Both sides compare the same authenticated random proposal IDs.
            // The lower ID wins; never combine roots from two proposals.
            if (pendingWire.update_id === updateId) throw Error('Ratchet proposal ID collision');
            if (pendingWire.update_id < updateId) {
                contextValue.secrets.ratchetSuperseded = [
                    {epoch: update.epoch, id: updateId},
                    ...(contextValue.secrets.ratchetSuperseded || [])
                ].slice(0, 2);
                await persist(contextValue, contextValue.secrets);
                return true;
            }
            contextValue.secrets.ratchetPending = null;
        }
        const previousRoot = core.bytesToHex(contextValue.state.root);
        const previousEpoch = contextValue.state.epoch;
        const result = await contextValue.state.applyUpdate(update);
        if (result === 'advanced') {
            contextValue.secrets.ratchetRoot = core.bytesToHex(contextValue.state.root);
            contextValue.secrets.ratchetEpoch = contextValue.state.epoch;
            contextValue.secrets.ratchetPreviousRoot = previousRoot;
            contextValue.secrets.ratchetPreviousRoots = [
                {epoch: previousEpoch, root: previousRoot},
                ...(Array.isArray(contextValue.secrets.ratchetPreviousRoots) ? contextValue.secrets.ratchetPreviousRoots : [])
            ].filter((entry, index, all) => /^[0-9a-f]{64}$/i.test(entry?.root || '') &&
                Number.isSafeInteger(entry.epoch) && all.findIndex(candidate => candidate.epoch === entry.epoch) === index).slice(0, 2);
            contextValue.secrets.ratchetLastUpdate = contextValue.ratchet.updateToPayload(update);
        }
        if (result === 'advanced' || result === 'duplicate') {
            const ackRoot = result === 'advanced' ? previousRoot :
                (Array.isArray(contextValue.secrets.ratchetPreviousRoots)
                    ? contextValue.secrets.ratchetPreviousRoots.find(entry => entry.epoch === update.from_epoch)?.root
                    : contextValue.secrets.ratchetPreviousRoot);
            if (!/^[0-9a-f]{64}$/i.test(ackRoot || '')) throw Error('Ratchet previous root unavailable');
            // Commit the advanced receive root and ACK intent together before
            // a peer can receive the ACK and start using the next epoch.
            const ack = {message: {type: 'ratchet_ack', suite, ack: contextValue.ratchet.updateToAck(update)},
                override: {ratchetRoot: ackRoot, ratchetEpoch: update.from_epoch}};
            const latest = await contextValue.storage.getBox('blind_secrets', contextValue.alias) || contextValue.secrets;
            if (result === 'advanced') {
                Object.assign(latest, {
                    ratchetPending: contextValue.secrets.ratchetPending ?? null,
                    ratchetRoot: contextValue.secrets.ratchetRoot,
                    ratchetEpoch: contextValue.secrets.ratchetEpoch,
                    ratchetPreviousRoot: contextValue.secrets.ratchetPreviousRoot,
                    ratchetPreviousRoots: contextValue.secrets.ratchetPreviousRoots,
                    ratchetLastUpdate: contextValue.secrets.ratchetLastUpdate
                });
            }
            latest.ratchetPendingAck = ack;
            await persist(contextValue, latest);
            // A false/throw leaves both the intent and inbound Inbox record
            // retryable. Duplicate updates recreate this same authenticated ACK.
            const sent = await core.sendMessage(ack.message, false, pid, null, true, ack.override);
            if (sent !== true) return false;
            const confirmed = await contextValue.storage.getBox('blind_secrets', contextValue.alias);
            if (confirmed?.ratchetPendingAck?.message?.ack?.update_id === ack.message.ack.update_id) {
                confirmed.ratchetPendingAck = null;
                await persist(contextValue, confirmed);
            }
            return true;
        }
        return false;
    }

    async function handleAck(core, message, pid) {
        const contextValue = await context(core, pid);
        if (!contextValue.secrets.ratchetPending) return false;
        const stored = contextValue.secrets.ratchetPending;
        const wire = stored.wire || stored;
        const suite = wire.pqc ? 'HYBRID_MLKEM768_V2' : 'CLASSICAL_ROOT_V2';
        if (message?.suite !== suite) throw Error('Ratchet ACK suite mismatch');
        const pending = contextValue.ratchet.payloadToUpdate(stored.entropy ? {version: wire.version, from_epoch: wire.from_epoch, epoch: wire.epoch, update_id: wire.update_id, entropy: stored.entropy} : wire);
        const acknowledged = contextValue.ratchet.ackToUpdate(message?.ack, pending.entropy);
        await contextValue.state.restorePending(pending);
        const previousRoot = core.bytesToHex(contextValue.state.root);
        const previousEpoch = contextValue.state.epoch;
        if (!contextValue.state.acknowledge(acknowledged)) return false;
        contextValue.secrets.ratchetRoot = core.bytesToHex(contextValue.state.root);
        contextValue.secrets.ratchetEpoch = contextValue.state.epoch;
        // The initiator can receive delayed packets from before the ACK too.
        // Keep the same bounded two-epoch receive history as the update peer.
        contextValue.secrets.ratchetPreviousRoot = previousRoot;
        contextValue.secrets.ratchetPreviousRoots = [
            {epoch: previousEpoch, root: previousRoot},
            ...(Array.isArray(contextValue.secrets.ratchetPreviousRoots) ? contextValue.secrets.ratchetPreviousRoots : [])
        ].filter((entry, index, all) => /^[0-9a-f]{64}$/i.test(entry?.root || '') &&
            Number.isSafeInteger(entry.epoch) && all.findIndex(candidate => candidate.epoch === entry.epoch) === index).slice(0, 2);
        contextValue.secrets.ratchetLastUpdate = contextValue.ratchet.updateToPayload(pending);
        contextValue.secrets.ratchetPending = null;
        await persist(contextValue, contextValue.secrets);
        return true;
    }

    async function initHandshake(core, pid = core.activePeerId) {
        if (!pid) return false;
        try {
            const contextValue = await context(core, pid);
            let update;
            let wire;
            let pending = contextValue.secrets.ratchetPending;
            if (pending) {
                wire = pending.wire || pending;
                update = contextValue.ratchet.payloadToUpdate(pending.entropy ? {version: wire.version, from_epoch: wire.from_epoch, epoch: wire.epoch, update_id: wire.update_id, entropy: pending.entropy} : wire);
            } else {
                const peerInfo = await contextValue.storage.getBox('blind_peers', contextValue.alias);
                const canUsePqc = core.keys.kyber?.secretKey && /^[0-9a-f]{2368}$/i.test(peerInfo?.kyberPub || '');
                if (canUsePqc) {
                    const kyber = global.DmashKyberWasm;
                    if (!kyber) throw Error('ML-KEM runtime unavailable');
                    kyber.init();
                    const seed = global.nacl.randomBytes(32);
                    const encapsulated = kyber.encapsulate(core.hexToBytes(peerInfo.kyberPub));
                    if (!encapsulated.success) throw Error('ML-KEM encapsulation failed');
                    const entropy = await contextValue.ratchet.deriveHybridEntropy(seed, encapsulated.ss);
                    update = await contextValue.state.proposeUpdate(entropy);
                    wire = contextValue.ratchet.updateToPqcPayload(update, seed, encapsulated.ct);
                    pending = {wire, entropy: core.bytesToHex(update.entropy)};
                } else {
                    update = await contextValue.state.proposeUpdate();
                    wire = contextValue.ratchet.updateToPayload(update);
                    pending = wire;
                }
            }
            contextValue.secrets.ratchetPending = pending;
            contextValue.secrets.ratchetRoot ||= core.bytesToHex(contextValue.state.root);
            contextValue.secrets.ratchetEpoch = contextValue.state.epoch;
            await persist(contextValue, contextValue.secrets);
            const suite = wire.pqc ? 'HYBRID_MLKEM768_V2' : 'CLASSICAL_ROOT_V2';
            const sent = await core.sendMessage({type: 'ratchet_update', suite, update: wire}, false, pid, null, true);
            if (sent) core.customAlert("СИСТЕМА", "Запрос на синхронизацию отправлен.");
            return sent;
        } catch (error) {
            core.shmon('WARN', `Ratchet update deferred: ${error.message}`);
            return false;
        }
    }

    global.DmashAccountRatchetRuntime = Object.freeze({
        direction,
        encryptPacket,
        decryptPacket,
        context,
        handleUpdate: (core, message, pid) => exclusive(core, pid, () => handleUpdate(core, message, pid)),
        handleAck: (core, message, pid) => exclusive(core, pid, () => handleAck(core, message, pid)),
        initHandshake: core => {
            const pid = core.activePeerId;
            return exclusive(core, pid, () => initHandshake(core, pid));
        }
    });
})(window);
