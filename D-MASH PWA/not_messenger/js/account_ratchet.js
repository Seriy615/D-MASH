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
    global.DmashAccountRatchet = Object.freeze({ROOT_BYTES, MESSAGE_ID_BYTES, deriveMessageKey,
        deriveEpochRoot, classifyEpoch, randomMessageId});
})(typeof window !== 'undefined' ? window : globalThis);
