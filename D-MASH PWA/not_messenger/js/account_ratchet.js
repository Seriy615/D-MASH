"use strict";

/*
 * Account-layer ratchet primitives.  This module deliberately has no
 * routing, Device, Node or Account identifier inputs.  The wire envelope is
 * kept separate until the authenticated update/ACK protocol is ready.
 */
(function (global) {
    const ROOT_BYTES = 32, MESSAGE_ID_BYTES = 16, MAX_EPOCH = Number.MAX_SAFE_INTEGER;
    const text = value => new TextEncoder().encode(value);
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
    class RatchetState {
        constructor({root, epoch = 0, maxGap = 64} = {}) {
            bytes(root, ROOT_BYTES, 'ratchet root');
            if (!Number.isSafeInteger(epoch) || epoch < 0 || !Number.isSafeInteger(maxGap) || maxGap < 0) {
                throw Error('Invalid ratchet state');
            }
            this.root = copy(root); this.epoch = epoch; this.maxGap = maxGap;
            this.pending = null; this.lastUpdate = null;
        }
        async messageKey(direction, messageId) {
            return deriveMessageKey(this.root, direction, this.epoch, messageId);
        }
        async proposeUpdate() {
            if (this.pending) return {
                version: 1, from_epoch: this.pending.from_epoch, epoch: this.pending.epoch,
                entropy: copy(this.pending.entropy), update_id: copy(this.pending.update_id)
            };
            const pending = {from_epoch: this.epoch, epoch: this.epoch + 1,
                entropy: global.crypto.getRandomValues(new Uint8Array(ROOT_BYTES)),
                update_id: randomMessageId()};
            pending.nextRoot = await deriveEpochRoot(this.root, pending.epoch, pending.entropy);
            this.pending = pending;
            return {version: 1, from_epoch: pending.from_epoch, epoch: pending.epoch,
                entropy: copy(pending.entropy), update_id: copy(pending.update_id)};
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
    global.DmashAccountRatchet = Object.freeze({ROOT_BYTES, MESSAGE_ID_BYTES, RatchetState, deriveMessageKey,
        deriveEpochRoot, classifyEpoch, randomMessageId});
})(typeof window !== 'undefined' ? window : globalThis);
