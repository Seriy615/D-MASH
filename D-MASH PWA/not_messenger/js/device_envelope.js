"use strict";

(function (global) {
    const PREFIX = "D-MASH|DEVICE-ENVELOPE|V1\0";
    const MAX_PLAINTEXT = 32 * 1024;
    const MAX_CIPHERTEXT = 64 * 1024;
    const codec = () => global.DmashSecureSession;
    const text = value => new TextEncoder().encode(value);
    const decode = bytes => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    function validate(envelope) {
        if (!envelope || Object.keys(envelope).sort().join(",") !== "account_payload,device_metadata,packet_id,route_id,type,version" ||
            envelope.version !== 1 || typeof envelope.route_id !== "string" || !envelope.route_id || envelope.route_id.length > 256 ||
            typeof envelope.type !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(envelope.type) ||
            typeof envelope.packet_id !== "string" || !/^[a-f0-9]{32,64}$/.test(envelope.packet_id) ||
            typeof envelope.account_payload !== "string" || !envelope.device_metadata ||
            typeof envelope.device_metadata !== "object" || Array.isArray(envelope.device_metadata)) throw new Error("Invalid DeviceEnvelopeV1");
        if (text(codec().canonical(envelope)).length > MAX_PLAINTEXT) throw new Error("Device envelope size limit");
        return envelope;
    }
    function create(routeId, type, accountPayload, deviceMetadata = {}) {
        const packetId = Array.from(global.crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, "0")).join("");
        return validate({ version: 1, route_id: routeId, type, packet_id: packetId,
            device_metadata: deviceMetadata, account_payload: accountPayload });
    }
    function seal(recipientPublicKey, envelope) {
        validate(envelope);
        if (!(recipientPublicKey instanceof Uint8Array) || recipientPublicKey.length !== 32) throw new Error("Invalid Device box key");
        const ephemeral = global.nacl.box.keyPair();
        const nonce = global.crypto.getRandomValues(new Uint8Array(24));
        const plaintext = text(PREFIX + codec().canonical(envelope));
        try {
            const shared = global.nacl.scalarMult(ephemeral.secretKey, recipientPublicKey);
            const valid = shared.some(byte => byte !== 0); shared.fill(0);
            if (!valid) throw new Error("Invalid Device box key");
            const ciphertext = global.nacl.box(plaintext, nonce, recipientPublicKey, ephemeral.secretKey);
            const wire = codec().b64(text(codec().canonical({ v: 1, e: codec().b64(ephemeral.publicKey), n: codec().b64(nonce), c: codec().b64(ciphertext) })));
            if (wire.length > MAX_CIPHERTEXT) throw new Error("Device ciphertext size limit");
            return wire;
        } finally { ephemeral.secretKey.fill(0); plaintext.fill(0); }
    }
    function open(recipientSecretKey, ciphertext) {
        if (!(recipientSecretKey instanceof Uint8Array) || recipientSecretKey.length !== 32 ||
            typeof ciphertext !== "string" || ciphertext.length > MAX_CIPHERTEXT) throw new Error("Invalid Device ciphertext");
        const wireText = decode(codec().unb64(ciphertext)), wire = JSON.parse(wireText);
        if (Object.keys(wire).sort().join(",") !== "c,e,n,v" || wire.v !== 1 || codec().canonical(wire) !== wireText) throw new Error("Invalid Device ciphertext format");
        const plaintext = global.nacl.box.open(codec().unb64(wire.c), codec().unb64(wire.n, 24), codec().unb64(wire.e, 32), recipientSecretKey);
        if (!plaintext) throw new Error("Device decrypt failed");
        try {
            const decoded = decode(plaintext);
            if (!decoded.startsWith(PREFIX)) throw new Error("Invalid Device encryption domain");
            const body = decoded.slice(PREFIX.length), envelope = JSON.parse(body);
            if (codec().canonical(envelope) !== body) throw new Error("Noncanonical Device envelope");
            return validate(envelope);
        } finally { plaintext.fill(0); }
    }
    global.DeviceEnvelope = { create, validate, seal, open, MAX_PLAINTEXT, MAX_CIPHERTEXT };
    if (typeof module !== "undefined") module.exports = global.DeviceEnvelope;
})(typeof window !== "undefined" ? window : globalThis);
