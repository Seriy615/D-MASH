// D-MASH ACCOUNT RATCHET RUNTIME
// Packet and control-plane orchestration kept separate from the Core UI engine.
// The module is deliberately late-bound: Core, Storage, the ratchet primitives,
// and the optional ML-KEM runtime may finish loading in any order.
"use strict";

(function (global) {
    const PACKET_DOMAIN = new TextEncoder().encode('D-MASH|ACCOUNT|RATCHET|V1|PACKET\0');

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
        const storage = storageApi();
        const alias = await storage.getAlias(pid, 'L1');
        secrets = secrets || await storage.getBox('blind_secrets', alias);
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
        return {alias, secrets, state, ratchet, storage};
    }

    async function handleUpdate(core, message, pid) {
        const contextValue = await context(core, pid);
        const suite = message?.suite;
        const isPqc = !!message?.update?.pqc;
        if (suite !== (isPqc ? 'HYBRID_MLKEM768_V1' : 'CLASSICAL_ROOT_V1')) throw Error('Ratchet suite mismatch');
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
            // The ACK is authenticated under the root that was current when
            // the update arrived. This keeps ACKs valid across reordering.
            await core.sendMessage({type: 'ratchet_ack', suite, ack: contextValue.ratchet.updateToAck(update)}, false, pid, null, true,
                {ratchetRoot: ackRoot, ratchetEpoch: update.from_epoch});
            if (result === 'advanced') {
                const latest = await contextValue.storage.getBox('blind_secrets', contextValue.alias) || contextValue.secrets;
                Object.assign(latest, {
                    ratchetRoot: contextValue.secrets.ratchetRoot,
                    ratchetEpoch: contextValue.secrets.ratchetEpoch,
                    ratchetPreviousRoot: contextValue.secrets.ratchetPreviousRoot,
                    ratchetPreviousRoots: contextValue.secrets.ratchetPreviousRoots,
                    ratchetLastUpdate: contextValue.secrets.ratchetLastUpdate
                });
                await contextValue.storage.putBox('blind_secrets', {alias: contextValue.alias, data: latest});
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
        const suite = wire.pqc ? 'HYBRID_MLKEM768_V1' : 'CLASSICAL_ROOT_V1';
        if (message?.suite !== suite) throw Error('Ratchet ACK suite mismatch');
        const pending = contextValue.ratchet.payloadToUpdate(stored.entropy ? {version: wire.version, from_epoch: wire.from_epoch, epoch: wire.epoch, update_id: wire.update_id, entropy: stored.entropy} : wire);
        const acknowledged = contextValue.ratchet.ackToUpdate(message?.ack, pending.entropy);
        await contextValue.state.restorePending(pending);
        if (!contextValue.state.acknowledge(acknowledged)) return false;
        contextValue.secrets.ratchetRoot = core.bytesToHex(contextValue.state.root);
        contextValue.secrets.ratchetEpoch = contextValue.state.epoch;
        contextValue.secrets.ratchetLastUpdate = contextValue.ratchet.updateToPayload(pending);
        contextValue.secrets.ratchetPending = null;
        await contextValue.storage.putBox('blind_secrets', {alias: contextValue.alias, data: contextValue.secrets});
        return true;
    }

    async function initHandshake(core) {
        const pid = core.activePeerId;
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
            await contextValue.storage.putBox('blind_secrets', {alias: contextValue.alias, data: contextValue.secrets});
            const suite = wire.pqc ? 'HYBRID_MLKEM768_V1' : 'CLASSICAL_ROOT_V1';
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
        handleUpdate,
        handleAck,
        initHandshake
    });
})(window);
