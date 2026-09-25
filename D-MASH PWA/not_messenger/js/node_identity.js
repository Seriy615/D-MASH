'use strict';
// Node identity work is identical for every runtime: BLAKE3(lowercase Ed25519
// public-key hex) starts with 0520. Account keys are never inputs here.
(function (global) {
    const PREFIX = '0520';
    const MAX_MINING_MS = 15 * 60 * 1000;
    const scriptUrl = global.document?.currentScript?.src || global.DMASH_NODE_WORKER_URLS?.identity;
    const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    const hash = value => hex(global.DmashBlake3.blake3(new TextEncoder().encode(value)));
    const verify = nodeId => typeof nodeId === 'string' && /^[0-9a-f]{64}$/.test(nodeId) && hash(nodeId).startsWith(PREFIX);
    let active = null;
    function mine({signal, timeoutMs = MAX_MINING_MS} = {}) {
        if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_MINING_MS) return Promise.reject(Error('Invalid mining deadline'));
        if (signal?.aborted) return Promise.reject(Error('Node identity mining cancelled'));
        if (active) return Promise.reject(Error('Node identity miner busy'));
        if (!global.Worker || !scriptUrl) return Promise.reject(Error('Node identity mining requires a Worker'));
        return new Promise((resolve, reject) => {
            const worker = new global.Worker(scriptUrl);
            active = worker;
            let finished = false;
            const finish = (error, seed) => {
                if (finished) { seed?.fill(0); return; }
                finished = true;
                clearTimeout(timer);
                signal?.removeEventListener('abort', cancel);
                worker.terminate();
                if (active === worker) active = null;
                if (error) { seed?.fill(0); reject(error); } else resolve(seed);
            };
            const cancel = () => finish(Error('Node identity mining cancelled'));
            const timer = setTimeout(() => finish(Error('Node identity mining expired')), timeoutMs);
            signal?.addEventListener('abort', cancel, {once:true});
            worker.onerror = () => finish(Error('Node identity Worker failed'));
            worker.onmessage = ({data}) => {
                if (data?.type === 'EXPIRED') { finish(Error('Node identity mining expired')); return; }
                const seed = data?.seed;
                if (data?.type !== 'NODE_IDENTITY' || !(seed instanceof Uint8Array) || seed.length !== 32) {
                    finish(Error('Invalid Node identity result'), seed instanceof Uint8Array ? seed : undefined); return;
                }
                let signing;
                try {
                    signing = global.nacl.sign.keyPair.fromSeed(seed);
                    if (!verify(hex(signing.publicKey))) throw Error('Node identity work rejected');
                    finish(null, seed);
                } catch (error) { finish(error, seed); }
                finally { signing?.secretKey.fill(0); }
            };
            worker.postMessage({type:'MINE_NODE_IDENTITY', timeoutMs});
        });
    }
    async function unlockDeviceIdentity(deviceRoot, options = {}) {
        const session = deviceRoot?.state;
        if (!session?.root || typeof deviceRoot.deviceMaterial !== 'function') throw Error('Device must be unlocked');
        let seed, signing;
        try {
            // Independent random seed behind the installation root; never derive
            // from an Account or reuse the older DEVICE signing identity.
            seed = await deviceRoot.deviceMaterial('node-ed25519-pow-v4', () => mine(options));
            if (deviceRoot.state !== session || options.signal?.aborted) throw Error('Device session changed');
            if (!(seed instanceof Uint8Array) || seed.length !== 32) throw Error('Invalid persisted Node identity');
            signing = global.nacl.sign.keyPair.fromSeed(seed);
            const nodeId = hex(signing.publicKey);
            if (!verify(nodeId)) throw Error('Persisted Node identity work rejected');
            return Object.freeze({nodeId, signing});
        } catch (error) {
            signing?.secretKey.fill(0);
            throw error;
        } finally { seed?.fill(0); }
    }
    if (typeof WorkerGlobalScope !== 'undefined' && global instanceof WorkerGlobalScope) {
        importScripts('vendor/nacl-fast.min.js', 'vendor/blake3.min.js');
        let mining = false;
        global.onmessage = async ({data}) => {
            if (mining || data?.type !== 'MINE_NODE_IDENTITY' || !Number.isInteger(data.timeoutMs) || data.timeoutMs < 1 || data.timeoutMs > MAX_MINING_MS) {
                global.postMessage({type:'ERROR'}); return;
            }
            mining = true;
            const deadline = Date.now() + data.timeoutMs;
            try {
                // Native Ed25519 avoids repeating the much slower JS public
                // key derivation for every rejected candidate. Same identity
                // distribution and unchanged BLAKE3 work threshold.
                let nativeKeys = null, native = true;
                try { nativeKeys = await global.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']); }
                catch (_) { native = false; }
                while (Date.now() < deadline) {
                    if (native) {
                        nativeKeys ||= await global.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
                        const publicKey = new Uint8Array(await global.crypto.subtle.exportKey('raw', nativeKeys.publicKey));
                        if (verify(hex(publicKey))) {
                            const encoded = new Uint8Array(await global.crypto.subtle.exportKey('pkcs8', nativeKeys.privateKey));
                            // RFC 8410's minimal Ed25519 PrivateKeyInfo wraps a
                            // 32-byte seed. Reject unexpected encodings.
                            if (encoded.length !== 48 || hex(encoded.subarray(0, 16)) !== '302e020100300506032b657004220420') {
                                encoded.fill(0); throw Error('Unexpected Ed25519 private key encoding');
                            }
                            const seed = encoded.slice(16); encoded.fill(0);
                            global.postMessage({type:'NODE_IDENTITY', seed}, [seed.buffer]); return;
                        }
                        nativeKeys = null;
                    } else {
                        const seed = global.nacl.randomBytes(32), signing = global.nacl.sign.keyPair.fromSeed(seed);
                        const valid = verify(hex(signing.publicKey));
                        signing.secretKey.fill(0);
                        if (valid) { global.postMessage({type:'NODE_IDENTITY', seed}, [seed.buffer]); return; }
                        seed.fill(0);
                    }
                }
                global.postMessage({type:'EXPIRED'});
            } catch (_) { global.postMessage({type:'ERROR'}); }
            finally { mining = false; }
        };
    }
    global.DmashNodeIdentity = Object.freeze({verify, hash, mine, unlockDeviceIdentity, PREFIX});
    if (typeof module !== 'undefined') module.exports = global.DmashNodeIdentity;
})(typeof window !== 'undefined' ? window : globalThis);
