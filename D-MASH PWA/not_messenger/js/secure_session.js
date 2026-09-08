"use strict";

// Shared v3 wire layer; does not grant Device or Node operations by itself.
(function (global) {
    const SUITE = "X25519-HKDF-SHA256-XSALSA20POLY1305";
    const DOMAIN = "D-MASH|DMP-C|3|";
    const MAX_RECORD_BYTES = 1024 * 1024;
    const text = value => new TextEncoder().encode(value);
    const join = (...parts) => {
        const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let offset = 0;
        for (const part of parts) { result.set(part, offset); offset += part.length; }
        return result;
    };
    const b64 = bytes => {
        let value = "";
        for (let i = 0; i < bytes.length; i += 8192) value += String.fromCharCode(...bytes.subarray(i, i + 8192));
        return btoa(value);
    };
    const unb64 = (value, length) => {
        if (typeof value !== "string") throw new Error("Invalid encoding");
        const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
        if (b64(bytes) !== value || (length !== undefined && bytes.length !== length)) throw new Error("Invalid encoding");
        return bytes;
    };
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    const unhex = value => {
        if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error("Invalid identity");
        return Uint8Array.from(value.match(/../g), b => parseInt(b, 16));
    };
    function canonical(value, depth = 0) {
        if (depth > 32) throw new Error("Payload nesting limit");
        if (value === null || typeof value === "boolean") return JSON.stringify(value);
        if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
        if (typeof value === "string") return JSON.stringify(value).replace(/[\u0080-\uffff]/g, c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
        if (Array.isArray(value)) return "[" + value.map(v => canonical(v, depth + 1)).join(",") + "]";
        if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
            const keys = Object.keys(value).sort();
            if (keys.some(k => /[^\x00-\x7f]/.test(k))) throw new Error("ASCII object keys required");
            return "{" + keys.map(k => canonical(k) + ":" + canonical(value[k], depth + 1)).join(",") + "}";
        }
        throw new Error("Unsupported canonical value");
    }
    const digest = async bytes => new Uint8Array(await global.crypto.subtle.digest("SHA-256", bytes));
    async function hkdf(ikm, salt, info, length) {
        const key = await global.crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
        return new Uint8Array(await global.crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
    }
    const nonce = sequence => {
        const bytes = new Uint8Array(24);
        new DataView(bytes.buffer).setBigUint64(16, BigInt(sequence));
        return bytes;
    };
    class Session {
        constructor(sendKey, receiveKey, transcriptHash) {
            this.sendKey = new Uint8Array(sendKey); this.receiveKey = new Uint8Array(receiveKey);
            this.transcriptHash = transcriptHash;
            this.sendSequence = 0; this.receiveSequence = 0; this.closed = false;
        }
        seal(payload) {
            if (this.closed || this.sendSequence > 0xffffffff) throw new Error("Session closed or exhausted");
            if (!payload || Array.isArray(payload) || typeof payload !== "object") throw new Error("Object payload required");
            const raw = text(canonical(payload));
            if (raw.length > MAX_RECORD_BYTES) throw new Error("Record too large");
            const sequence = this.sendSequence;
            const ciphertext = global.nacl.secretbox(raw, nonce(sequence), this.sendKey);
            this.sendSequence++;
            return { type: "SECURE", version: 3, sequence, ciphertext: b64(ciphertext) };
        }
        open(frame) {
            if (this.closed) throw new Error("Session closed");
            try {
                if (!frame || Object.keys(frame).sort().join(",") !== "ciphertext,sequence,type,version" ||
                    frame.type !== "SECURE" || frame.version !== 3 || !Number.isSafeInteger(frame.sequence) ||
                    frame.sequence !== this.receiveSequence || frame.sequence > 0xffffffff ||
                    typeof frame.ciphertext !== "string" || frame.ciphertext.length > Math.floor((MAX_RECORD_BYTES + 18) / 3) * 4) throw new Error("Invalid record");
                const raw = global.nacl.secretbox.open(unb64(frame.ciphertext), nonce(frame.sequence), this.receiveKey);
                if (!raw || raw.length > MAX_RECORD_BYTES) throw new Error("Invalid ciphertext");
                const wire = new TextDecoder("utf-8", { fatal: true }).decode(raw);
                const payload = JSON.parse(wire);
                if (!payload || Array.isArray(payload) || typeof payload !== "object" || canonical(payload) !== wire) throw new Error("Invalid payload");
                this.receiveSequence++;
                return payload;
            } catch (error) { this.close(); throw error; }
        }
        close() { this.sendKey.fill(0); this.receiveKey.fill(0); this.closed = true; }
    }
    class Initiator {
        constructor(signing, role = "DEVICE") {
            if (!["DEVICE", "NODE"].includes(role)) throw new Error("Invalid role");
            this.signing = signing; this.role = role;
            this.private = global.crypto.getRandomValues(new Uint8Array(32));
            this.used = false;
        }
        initiate() {
            if (this.used || this.hello) throw new Error("Handshake already used");
            this.hello = { type: "HELLO", protocol: "DMP-C", version: 3, suite: SUITE,
                role: this.role, public_key: hex(this.signing.publicKey),
                ephemeral: b64(global.nacl.scalarMult.base(this.private)),
                nonce: b64(global.crypto.getRandomValues(new Uint8Array(32))) };
            return { ...this.hello };
        }
        async finish(response, expectedNodeId, now = Math.floor(Date.now() / 1000)) {
            if (this.used || !this.hello) throw new Error("Invalid handshake state");
            this.used = true;
            try {
                const challenge = { ...response }, signature = unb64(challenge.signature, 64);
                delete challenge.signature;
                if (Object.keys(challenge).sort().join(",") !== "ephemeral,expires_at,nonce,peer_role,protocol,public_key,role,suite,type,version" ||
                    challenge.type !== "CHALLENGE" || challenge.protocol !== "DMP-C" || challenge.version !== 3 ||
                    challenge.suite !== SUITE || challenge.role !== "NODE" || challenge.peer_role !== this.role ||
                    challenge.public_key !== expectedNodeId || !Number.isSafeInteger(challenge.expires_at) ||
                    challenge.expires_at <= now || challenge.expires_at > now + 15) throw new Error("Invalid challenge");
                const nodeKey = unhex(expectedNodeId);
                unb64(challenge.nonce, 32);
                const ephemeral = unb64(challenge.ephemeral, 32);
                const hash = await digest(join(text(DOMAIN + "HANDSHAKE\0"), text(canonical([this.hello, challenge]))));
                if (!global.nacl.sign.detached.verify(join(text(DOMAIN + "RESPONDER\0"), hash), signature, nodeKey)) throw new Error("Node signature failed");
                const auth = { type: "AUTH", version: 3, signature: b64(global.nacl.sign.detached(join(text(DOMAIN + "INITIATOR\0"), hash), this.signing.secretKey)) };
                const shared = global.nacl.scalarMult(this.private, ephemeral);
                if (!shared.some(b => b !== 0)) throw new Error("Invalid shared secret");
                const ikm = join(text("X25519\0"), new Uint8Array([0, 0, 0, 32]), shared);
                let keys;
                try { keys = await hkdf(ikm, hash, text(DOMAIN + SUITE), 64); }
                finally { shared.fill(0); ikm.fill(0); }
                try { return { auth, session: new Session(keys.subarray(0, 32), keys.subarray(32), hash) }; }
                finally { keys.fill(0); }
            } finally { this.close(); }
        }
        close() { this.private.fill(0); this.signing = null; this.used = true; }
    }
    global.DmashSecureSession = { Initiator, Session, canonical, b64, unb64, hkdf, SUITE };
    if (typeof module !== "undefined") module.exports = global.DmashSecureSession;
})(typeof window !== "undefined" ? window : globalThis);
