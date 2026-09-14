"use strict";

/*
 * Account-layer ratchet primitives.  This module deliberately has no
 * routing, Device, Node or Account identifier inputs.  The wire envelope is
 * kept separate until the authenticated update/ACK protocol is ready.
 */
(function (global) {
    const ROOT_BYTES = 32, MESSAGE_ID_BYTES = 16, MAX_EPOCH = Number.MAX_SAFE_INTEGER;
    const text = value => new TextEncoder().encode(value);
    const hex = value => Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('');
    const fromHex = (value, length, name) => {
        if (typeof value !== 'string' || value.length !== length * 2 || !/^[0-9a-f]+$/i.test(value)) throw Error(`Invalid ${name}`);
        return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
    };
    const bytes = (value, length, name) => {
        if (!(value instanceof Uint8Array) || value.length !== length) throw Error(`Invalid ${name}`);
        return value;
    };
    const join = (...parts) => {
        const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
        let offset = 0;
        for (const part of parts) { result.set(part, offset); offset += part.length; }
        return result;
    };
    const epochBytes = epoch => {
        if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > MAX_EPOCH) throw Error('Invalid ratchet epoch');
        const result = new Uint8Array(8), view = new DataView(result.buffer);
        view.setUint32(0, Math.floor(epoch / 0x100000000), false);
        view.setUint32(4, epoch >>> 0, false);
        return result;
    };
    const directionBytes = direction => {
        if (typeof direction !== 'string' || !direction.length || direction.length > 64 || direction.includes("\0")) {
            throw Error('Invalid ratchet direction');
        }
        return text(direction);
    };
    async function hkdf(ikm, info) {
        const key = await global.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        return new Uint8Array(await global.crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256',
            salt: new Uint8Array(ROOT_BYTES), info}, key, ROOT_BYTES * 8));
    }
    async function deriveMessageKey(root, direction, epoch, messageId) {
        bytes(root, ROOT_BYTES, 'ratchet root'); bytes(messageId, MESSAGE_ID_BYTES, 'message id');
        return hkdf(root, join(text('D-MASH|ACCOUNT|RATCHET|V1|MESSAGE\0'), directionBytes(direction),
            new Uint8Array([0]), epochBytes(epoch), messageId));
    }
    async function deriveEpochRoot(root, epoch, freshEntropy) {
        bytes(root, ROOT_BYTES, 'ratchet root'); bytes(freshEntropy, ROOT_BYTES, 'fresh entropy');
        return hkdf(join(root, freshEntropy), join(text('D-MASH|ACCOUNT|RATCHET|V1|EPOCH\0'), epochBytes(epoch)));
    }
    async function deriveHybridEntropy(classicalEntropy, pqSecret) {
        bytes(classicalEntropy, ROOT_BYTES, 'classical entropy'); bytes(pqSecret, ROOT_BYTES, 'post-quantum secret');
        return new Uint8Array(await global.crypto.subtle.digest('SHA-256', join(
            text('D-MASH|ACCOUNT|RATCHET|V1|HYBRID-ENTROPY\0'), classicalEntropy, pqSecret)));
    }
    function classifyEpoch(current, incoming, maxGap = 64) {
        if (!Number.isSafeInteger(current) || current < 0 || !Number.isSafeInteger(incoming) || incoming < 0 ||
            !Number.isSafeInteger(maxGap) || maxGap < 0) throw Error('Invalid epoch window');
        if (incoming < current) return 'stale';
        if (incoming === current) return 'current';
        return incoming - current <= maxGap ? 'advance' : 'too_far';
    }
    function randomMessageId() { return global.crypto.getRandomValues(new Uint8Array(MESSAGE_ID_BYTES)); }
    const copy = value => new Uint8Array(value);
    const same = (left, right) => left.length === right.length && left.every((value, index) => value === right[index]);
    function updateShape(update) {
        if (!update || update.version !== 1 || !Number.isSafeInteger(update.from_epoch) || update.from_epoch < 0 ||
            !Number.isSafeInteger(update.epoch) || update.epoch !== update.from_epoch + 1 ||
            !(update.entropy instanceof Uint8Array) || update.entropy.length !== ROOT_BYTES ||
            !(update.update_id instanceof Uint8Array) || update.update_id.length !== MESSAGE_ID_BYTES) {
            throw Error('Invalid ratchet update');
        }
        return update;
    }
    function updateToPayload(update) {
        updateShape(update);
        return {version: 1, from_epoch: update.from_epoch, epoch: update.epoch,
            entropy: hex(update.entropy), update_id: hex(update.update_id)};
    }
    function payloadToUpdate(payload) {
        if (!payload || Object.keys(payload).length !== 5 || payload.version !== 1 ||
            !Object.prototype.hasOwnProperty.call(payload, 'from_epoch') ||
            !Object.prototype.hasOwnProperty.call(payload, 'epoch') ||
            !Object.prototype.hasOwnProperty.call(payload, 'entropy') ||
            !Object.prototype.hasOwnProperty.call(payload, 'update_id')) throw Error('Invalid ratchet update payload');
        return updateShape({version: 1, from_epoch: payload.from_epoch, epoch: payload.epoch,
            entropy: fromHex(payload.entropy, ROOT_BYTES, 'ratchet entropy'),
            update_id: fromHex(payload.update_id, MESSAGE_ID_BYTES, 'ratchet update id')});
    }
    function updateToAck(update) {
        updateShape(update);
        return {version: 1, from_epoch: update.from_epoch, epoch: update.epoch, update_id: hex(update.update_id)};
    }
    function ackToUpdate(payload, entropy) {
        if (!payload || Object.keys(payload).length !== 4 || payload.version !== 1 ||
            !Number.isSafeInteger(payload.from_epoch) || !Number.isSafeInteger(payload.epoch) ||
            payload.epoch !== payload.from_epoch + 1) throw Error('Invalid ratchet ACK payload');
        return updateShape({version: 1, from_epoch: payload.from_epoch, epoch: payload.epoch,
            entropy: bytes(entropy, ROOT_BYTES, 'ratchet entropy'),
            update_id: fromHex(payload.update_id, MESSAGE_ID_BYTES, 'ratchet update id')});
    }
    class RatchetState {
        constructor({root, epoch = 0, maxGap = 64, lastUpdate = null} = {}) {
            bytes(root, ROOT_BYTES, 'ratchet root');
            if (!Number.isSafeInteger(epoch) || epoch < 0 || !Number.isSafeInteger(maxGap) || maxGap < 0) {
                throw Error('Invalid ratchet state');
            }
            this.root = copy(root); this.epoch = epoch; this.maxGap = maxGap;
            this.pending = null; this.lastUpdate = lastUpdate ? {
                epoch: lastUpdate.epoch, update_id: copy(lastUpdate.update_id), entropy: copy(lastUpdate.entropy)
            } : null;
            if (this.lastUpdate) updateShape({version: 1, from_epoch: this.lastUpdate.epoch - 1,
                epoch: this.lastUpdate.epoch, entropy: this.lastUpdate.entropy, update_id: this.lastUpdate.update_id});
        }
        async messageKey(direction, messageId) {
            return deriveMessageKey(this.root, direction, this.epoch, messageId);
        }
        async proposeUpdate(entropy = null) {
            if (this.pending) return {
                version: 1, from_epoch: this.pending.from_epoch, epoch: this.pending.epoch,
                entropy: copy(this.pending.entropy), update_id: copy(this.pending.update_id)
            };
            const pending = {from_epoch: this.epoch, epoch: this.epoch + 1,
                entropy: entropy ? copy(bytes(entropy, ROOT_BYTES, 'ratchet entropy')) : global.crypto.getRandomValues(new Uint8Array(ROOT_BYTES)),
                update_id: randomMessageId()};
            pending.nextRoot = await deriveEpochRoot(this.root, pending.epoch, pending.entropy);
            this.pending = pending;
            return {version: 1, from_epoch: pending.from_epoch, epoch: pending.epoch,
                entropy: copy(pending.entropy), update_id: copy(pending.update_id)};
        }
        async restorePending(update) {
            updateShape(update);
            if (update.from_epoch !== this.epoch || update.epoch !== this.epoch + 1) throw Error('Invalid pending ratchet update');
            const nextRoot = await deriveEpochRoot(this.root, update.epoch, update.entropy);
            this.pending = {from_epoch: update.from_epoch, epoch: update.epoch,
                entropy: copy(update.entropy), update_id: copy(update.update_id), nextRoot};
            return true;
        }
        async applyUpdate(update) {
            updateShape(update);
            const status = classifyEpoch(this.epoch, update.epoch, this.maxGap);
            if (status === 'stale') return 'stale';
            if (status === 'too_far') throw Error('Ratchet epoch jump exceeds bound');
            if (status === 'current') {
                if (this.lastUpdate && this.lastUpdate.epoch === update.epoch &&
                    same(this.lastUpdate.update_id, update.update_id) && same(this.lastUpdate.entropy, update.entropy)) return 'duplicate';
                throw Error('Conflicting ratchet update');
            }
            if (update.from_epoch !== this.epoch) throw Error('Ratchet update base is unavailable');
            const nextRoot = await deriveEpochRoot(this.root, update.epoch, update.entropy);
            this.root = nextRoot; this.epoch = update.epoch;
            this.lastUpdate = {epoch: update.epoch, update_id: copy(update.update_id), entropy: copy(update.entropy)};
            return 'advanced';
        }
        acknowledge(update) {
            updateShape(update);
            if (!this.pending || this.pending.epoch !== update.epoch || this.pending.from_epoch !== update.from_epoch ||
                !same(this.pending.update_id, update.update_id) || !same(this.pending.entropy, update.entropy)) return false;
            this.root = this.pending.nextRoot; this.epoch = this.pending.epoch;
            this.lastUpdate = {epoch: this.pending.epoch, update_id: copy(this.pending.update_id), entropy: copy(this.pending.entropy)};
            this.pending = null;
            return true;
        }
    }
    function updateToPqcPayload(update, classicalEntropy, capsule) {
        updateShape(update); bytes(classicalEntropy, ROOT_BYTES, 'classical entropy'); bytes(capsule, 1088, 'ML-KEM capsule');
        return {version: 1, from_epoch: update.from_epoch, epoch: update.epoch, update_id: hex(update.update_id),
            pqc: {algorithm: 'ML-KEM-768', seed: hex(classicalEntropy), capsule: hex(capsule)}};
    }
    async function pqcPayloadToUpdate(payload, pqSecret) {
        if (!payload || Object.keys(payload).length !== 5 || payload.version !== 1 ||
            !Number.isSafeInteger(payload.from_epoch) || !Number.isSafeInteger(payload.epoch) ||
            payload.epoch !== payload.from_epoch + 1 || typeof payload.update_id !== 'string' ||
            !payload.pqc || Object.keys(payload.pqc).length !== 3 || payload.pqc.algorithm !== 'ML-KEM-768') {
            throw Error('Invalid post-quantum ratchet payload');
        }
        const seed = fromHex(payload.pqc.seed, ROOT_BYTES, 'classical entropy');
        fromHex(payload.pqc.capsule, 1088, 'ML-KEM capsule');
        const entropy = await deriveHybridEntropy(seed, bytes(pqSecret, ROOT_BYTES, 'post-quantum secret'));
        return updateShape({version: 1, from_epoch: payload.from_epoch, epoch: payload.epoch,
            entropy, update_id: fromHex(payload.update_id, MESSAGE_ID_BYTES, 'ratchet update id')});
    }
    global.DmashAccountRatchet = Object.freeze({ROOT_BYTES, MESSAGE_ID_BYTES, RatchetState, deriveMessageKey,
        deriveEpochRoot, deriveHybridEntropy, classifyEpoch, randomMessageId, updateToPayload, payloadToUpdate,
        updateToPqcPayload, pqcPayloadToUpdate, updateToAck, ackToUpdate});
})(typeof window !== 'undefined' ? window : globalThis);
