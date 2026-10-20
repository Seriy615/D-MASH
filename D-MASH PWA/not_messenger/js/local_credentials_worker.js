"use strict";
// Dedicated, one-job lifetime. Only the existing standard Argon2 WASM runs here.
const vendor = new URL("vendor/argon2-bundled.min.js", self.location.href);
vendor.search = self.location.search;
importScripts(vendor.href);
self.onmessage = async ({ data }) => {
    let hash;
    try {
        const p = data;
        if (!p || typeof p.pass !== "string" || typeof p.salt !== "string" || p.salt.length > 128 || ![0, 2].includes(p.type) || p.time !== 3 || p.mem !== 65536 || p.parallelism !== 1 || p.hashLen !== 32 || p.version !== 19) throw Error("Invalid credential KDF profile");
        const result = await argon2.hash({ pass: p.pass, salt: p.salt, type: p.type, time: 3, mem: 65536, parallelism: 1, hashLen: 32 });
        hash = new Uint8Array(result.hash);
        if (hash.length !== 32) throw Error("Invalid credential KDF result");
        self.postMessage({ hash: hash.buffer }, [hash.buffer]);
    } catch (_) { self.postMessage({ error: "ARGON2_FAILED" }); }
    finally { if (hash?.byteLength) hash.fill(0); self.close(); }
};
