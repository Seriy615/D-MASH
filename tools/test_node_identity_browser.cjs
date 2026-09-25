'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), http = require('node:http');
const {execFileSync} = require('node:child_process');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '..');
const files = new Set(['/js/vendor/nacl-fast.min.js', '/js/vendor/blake3.min.js', '/js/node_identity.js', '/js/device_root.js']);
(async () => {
    const server = http.createServer((request, response) => {
        if (request.url === '/') {
            response.setHeader('Content-Type', 'text/html');
            response.end('<script src="/js/vendor/nacl-fast.min.js"></script><script src="/js/vendor/blake3.min.js"></script><script src="/js/node_identity.js"></script><script src="/js/device_root.js"></script>');
        } else if (files.has(request.url)) {
            response.setHeader('Content-Type', 'application/javascript');
            response.end(fs.readFileSync(path.join(root, 'D-MASH PWA/not_messenger', request.url)));
        } else { response.statusCode = 404; response.end(); }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let browser;
    try {
        browser = await chromium.launch({executablePath:process.env.DMASH_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
        const page = await browser.newPage();
        await page.goto(`http://127.0.0.1:${server.address().port}/`);
        const result = await page.evaluate(async () => {
            const controller = new AbortController();
            const stopped = DmashNodeIdentity.mine({signal:controller.signal});
            controller.abort();
            let cancelled = false;
            try { await stopped; } catch (error) { cancelled = /cancelled/.test(error.message); }
            let ticks = 0;
            const timer = setInterval(() => ticks++, 10);
            try {
                const task = DmashNodeIdentity.mine({timeoutMs:600000});
                let bounded = false;
                try { await DmashNodeIdentity.mine(); } catch (error) { bounded = /busy/.test(error.message); }
                const seed = await task;
                const signing = nacl.sign.keyPair.fromSeed(seed);
                const nodeId = Array.from(signing.publicKey, b => b.toString(16).padStart(2,'0')).join('');
                let stored;
                const storage = {async put(record) { stored = structuredClone(record); }};
                const root = crypto.getRandomValues(new Uint8Array(32));
                DeviceRoot.setStoreForTests(storage);
                DeviceRoot.state = {root:root.slice(), record:{id:'root', version:1, materials:{}}};
                await DeviceRoot.deviceMaterial('node-ed25519-pow-v4', async () => seed);
                seed.fill(0); signing.secretKey.fill(0);
                DeviceRoot.lock();
                DeviceRoot.state = {root:root.slice(), record:structuredClone(stored)};
                root.fill(0);
                const restored = await DmashNodeIdentity.unlockDeviceIdentity(DeviceRoot);
                const persistent = restored.nodeId === nodeId;
                restored.signing.secretKey.fill(0);
                // Corrupt material must fail closed, with no replacement mining.
                DeviceRoot.state.record.materials['node-ed25519-pow-v4'].ciphertext = 'AAAA';
                let corruptRejected = false;
                try { await DmashNodeIdentity.unlockDeviceIdentity(DeviceRoot); }
                catch (error) { corruptRejected = error.code === 'STORAGE_CORRUPT'; }
                DeviceRoot.lock();
                let lockedRejected = false;
                try { await DmashNodeIdentity.unlockDeviceIdentity(DeviceRoot); }
                catch (_) { lockedRejected = true; }
                return {nodeId, persistent, corruptRejected, lockedRejected, valid:DmashNodeIdentity.verify(nodeId), cancelled, bounded, ticks};
            } finally { clearInterval(timer); }
        });
        assert(result.persistent); assert(result.corruptRejected); assert(result.lockedRejected);
        assert(result.cancelled); assert(result.bounded); assert(result.valid);
        assert(result.ticks > 0, 'identity mining must leave the browser main thread responsive');
        execFileSync(process.env.DMASH_PYTHON || path.join(root,'.venv/bin/python'), ['-c',
            'import sys,blake3; assert blake3.blake3(sys.argv[1].encode()).hexdigest().startswith("0520")', result.nodeId]);
        console.log('PASS real browser Worker Node identity: production PoW, Python parity, cancellation, single-worker admission, responsive main thread, encrypted DeviceRoot persistence and fail-closed reload');
    } finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => {console.error(error.message); process.exitCode = 1;});
