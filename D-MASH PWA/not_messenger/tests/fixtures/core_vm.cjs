'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const nacl = require('../../js/vendor/nacl-fast.min.js');
const js = path.join(__dirname, '../../js');
async function createCore({kyber = false} = {}) {
    const rows = new Map();
    const storage = {
        getAlias: async id => id,
        getBox: async (table, alias) => structuredClone(rows.get(table + alias) || null),
        putBox: async (table, {alias, data}) => rows.set(table + alias, structuredClone(data)),
    };
    const ctx = {console, Uint8Array, TextEncoder, TextDecoder, DataView, crypto, URL, Map, Set,
        Storage: storage, localStorage: {getItem: () => null}, sessionStorage: {getItem: () => null},
        document: {getElementById: () => null}, location: {}, addEventListener() {}, setTimeout: () => 0,
        nacl};
    ctx.window = ctx;
    vm.createContext(ctx);
    if (kyber) {
        await new Promise((resolve, reject) => {
            ctx.KyberModule = {wasmBinary: fs.readFileSync(path.join(js, 'vendor/kyber768.wasm')),
                locateFile: name => path.join(js, 'vendor', name), onRuntimeInitialized: resolve, onAbort: reject};
            vm.runInContext(fs.readFileSync(path.join(js, 'vendor/kyber768.js'), 'utf8'), ctx);
        });
    }
    vm.runInContext(fs.readFileSync(path.join(js, 'core_engine.js'), 'utf8'), ctx);
    const core = ctx.Core;
    core.shmon = () => {};
    const sign = nacl.sign.keyPair();
    core.keys = {sign, pub_hex: Buffer.from(sign.publicKey).toString('hex'), box: nacl.box.keyPair()};
    if (kyber) {
        const generated = ctx.DmashKyberWasm.generateKeys();
        if (!generated.success) throw Error('Kyber key generation failed');
        core.keys.kyber = {publicKey: generated.pk, secretKey: generated.sk};
    }
    return {core, ctx, storage, rows};
}
module.exports = {createCore, nacl};
