'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), http = require('node:http');
const {execFileSync} = require('node:child_process');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '..');
const files = new Set(['/js/vendor/nacl-fast.min.js', '/js/vendor/blake3.min.js', '/js/node_identity.js']);
(async () => {
    const server = http.createServer((request, response) => {
        if (request.url === '/') {
            response.setHeader('Content-Type', 'text/html');
            response.end('<script src="/js/vendor/nacl-fast.min.js"></script><script src="/js/vendor/blake3.min.js"></script><script src="/js/node_identity.js"></script>');
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
                seed.fill(0); signing.secretKey.fill(0);
                return {nodeId, valid:DmashNodeIdentity.verify(nodeId), cancelled, bounded, ticks};
            } finally { clearInterval(timer); }
        });
        assert(result.cancelled); assert(result.bounded); assert(result.valid);
        assert(result.ticks > 0, 'identity mining must leave the browser main thread responsive');
        execFileSync(process.env.DMASH_PYTHON || path.join(root,'.venv/bin/python'), ['-c',
            'import sys,blake3; assert blake3.blake3(sys.argv[1].encode()).hexdigest().startswith("0520")', result.nodeId]);
        console.log('PASS real browser Worker Node identity: production PoW, Python parity, cancellation, single-worker admission, responsive main thread');
    } finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => {console.error(error.message); process.exitCode = 1;});
