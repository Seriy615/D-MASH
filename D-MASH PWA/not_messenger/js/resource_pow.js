"use strict";

/*
 * Browser implementation of D-MASH activation PoW v2.
 *
 * v2 deliberately uses SHA-256 because it is available everywhere the PWA
 * runs and can be implemented deterministically without shipping a second
 * cryptographic runtime only for proof-of-work. The transcript stays bound to
 * NodeID, Device transport public key, resource type, resource, expiry and
 * nonce. Backend resource_pow.py implements the exact same byte layout.
 */
(function (global) {
    const VERSION = 2;
    const DOMAIN = new TextEncoder().encode("D-MASH|ACTIVATION-POW|V2\0");
    const TYPES = new Set(["DNSS", "ENTRY_GRANT"]);
    const K = new Uint32Array([
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);
    const H0 = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const enc = new TextEncoder();
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    const add = (...values) => values.reduce((sum, value) => (sum + value) >>> 0, 0);
    const asBytes = (value, name) => {
        if (value instanceof Uint8Array) return new Uint8Array(value);
        if (typeof value === "string" && value.length) return enc.encode(value);
        throw new TypeError(name + " must be non-empty text or Uint8Array");
    };
    const u16 = value => Uint8Array.of((value >>> 8) & 255, value & 255);
    const u32 = value => Uint8Array.of((value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
    const u64 = value => {
        const n = typeof value === "bigint" ? value : BigInt(value);
        if (n < 0n || n >= (1n << 64n)) throw new RangeError("uint64 out of range");
        const out = new Uint8Array(8);
        for (let index = 7, x = n; index >= 0; index--, x >>= 8n) out[index] = Number(x & 255n);
        return out;
    };
    const join = (...parts) => {
        const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
        let at = 0; for (const part of parts) { out.set(part, at); at += part.length; }
        return out;
    };
    const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

    function sha256(message) {
        const input = message instanceof Uint8Array ? message : new Uint8Array(message);
        const bitLength = BigInt(input.length) * 8n;
        const paddedLength = Math.ceil((input.length + 1 + 8) / 64) * 64;
        const padded = new Uint8Array(paddedLength);
        padded.set(input); padded[input.length] = 0x80;
        for (let index = 0; index < 8; index++) padded[paddedLength - 1 - index] = Number((bitLength >> BigInt(index * 8)) & 255n);

        const h = new Uint32Array(H0);
        const w = new Uint32Array(64);
        for (let offset = 0; offset < padded.length; offset += 64) {
            for (let i = 0; i < 16; i++) {
                const at = offset + i * 4;
                w[i] = ((padded[at] << 24) | (padded[at + 1] << 16) | (padded[at + 2] << 8) | padded[at + 3]) >>> 0;
            }
            for (let i = 16; i < 64; i++) {
                const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
                const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
                w[i] = add(w[i - 16], s0, w[i - 7], s1);
            }
            let [a,b,c,d,e,f,g,hh] = h;
            for (let i = 0; i < 64; i++) {
                const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
                const ch = ((e & f) ^ (~e & g)) >>> 0;
                const t1 = add(hh, S1, ch, K[i], w[i]);
                const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
                const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
                const t2 = add(S0, maj);
                hh = g; g = f; f = e; e = add(d, t1); d = c; c = b; b = a; a = add(t1, t2);
            }
            h[0]=add(h[0],a); h[1]=add(h[1],b); h[2]=add(h[2],c); h[3]=add(h[3],d);
            h[4]=add(h[4],e); h[5]=add(h[5],f); h[6]=add(h[6],g); h[7]=add(h[7],hh);
        }
        const out = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            out[i*4] = h[i] >>> 24; out[i*4+1] = h[i] >>> 16; out[i*4+2] = h[i] >>> 8; out[i*4+3] = h[i];
        }
        return out;
    }

    function leadingZeroBits(digest) {
        let bits = 0;
        for (const byte of digest) {
            if (byte === 0) { bits += 8; continue; }
            for (let mask = 0x80; mask && (byte & mask) === 0; mask >>= 1) bits++;
            break;
        }
        return bits;
    }

    function activationPrefix(nodeId, activationType, deviceTransportKey, resource, expiresAt) {
        if (!TYPES.has(activationType)) throw new TypeError("invalid activation type");
        const node = asBytes(nodeId, "nodeId");
        const key = asBytes(deviceTransportKey, "deviceTransportKey");
        const item = asBytes(resource, "resource");
        if (node.length > 0xffff || key.length > 0xffff || item.length > 0xffffffff) throw new RangeError("activation input too large");
        return { prefix: join(DOMAIN, u16(node.length), node, enc.encode(activationType), Uint8Array.of(0), u16(key.length), key, u32(item.length), item, u64(expiresAt)), item };
    }

    function activationDigest(nodeId, activationType, deviceTransportKey, resource, nonce, expiresAt) {
        const { prefix } = activationPrefix(nodeId, activationType, deviceTransportKey, resource, expiresAt);
        return sha256(join(prefix, u64(nonce)));
    }

    async function mineActivationPow({ nodeId, activationType, deviceTransportKey, resource, expiresAt, difficulty = 22, startNonce = 0, onProgress = null } = {}) {
        if (!Number.isInteger(difficulty) || difficulty < 0 || difficulty > 256) throw new RangeError("difficulty must be 0..256");
        if (!Number.isSafeInteger(startNonce) || startNonce < 0) throw new RangeError("startNonce must be a non-negative safe integer");
        const { prefix, item } = activationPrefix(nodeId, activationType, deviceTransportKey, resource, expiresAt);
        const work = new Uint8Array(prefix.length + 8); work.set(prefix);
        const started = performance?.now?.() ?? Date.now();
        for (let nonce = startNonce; Number.isSafeInteger(nonce); nonce++) {
            work.set(u64(nonce), prefix.length);
            const digest = sha256(work);
            if (leadingZeroBits(digest) >= difficulty) {
                return Object.freeze({
                    v: VERSION, type: activationType,
                    resource: resource instanceof Uint8Array ? hex(item) : String(resource),
                    nonce, expires_at: expiresAt, difficulty, digest: hex(digest),
                    elapsed_ms: Math.round((performance?.now?.() ?? Date.now()) - started)
                });
            }
            if ((nonce - startNonce + 1) % 4096 === 0) {
                onProgress?.({ attempts: nonce - startNonce + 1, elapsedMs: (performance?.now?.() ?? Date.now()) - started });
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        throw new Error("PoW nonce space exhausted");
    }

    const api = Object.freeze({ VERSION, sha256, leadingZeroBits, activationDigest, mineActivationPow });
    global.DmashResourcePow = api;
    if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
