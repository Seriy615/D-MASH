'use strict';
// Fresh synthetic local profile only. Run separately from owned live QA browsers.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {execFileSync} = require('node:child_process');
const crypto = require('node:crypto');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT || '/tmp/dmash-browser-tools/node_modules/playwright');
const root = process.env.DMASH_TEST_PWA_ROOT || path.resolve(__dirname, '../D-MASH PWA/not_messenger');
const artifactDir = process.env.DMASH_TEST_ARTIFACT_DIR || '/tmp/dmash-sw37-fixture-' + Date.now();
fs.mkdirSync(artifactDir, {recursive: true, mode: 0o700});
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const report = {startedAt: new Date().toISOString(), productSha: execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root}).toString().trim(), harnessSha256: hash(fs.readFileSync(__filename)), productRoot: root, events: []};
const save = () => fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600});
const oldWorker = execFileSync('git', ['show', '992adf973820e09ee1fbefe0167eb93ef1acfffe:D-MASH PWA/not_messenger/sw.js'], {cwd: root});
const newWorker = fs.readFileSync(path.join(root, 'sw.js'));
const release = fs.readFileSync(path.join(root, 'js/release.js'), 'utf8').match(/id: "([^"]+)"/)[1];
let latest = false, browser, context, page;
const server = http.createServer((req, res) => {
    report.events.push({type:'http', at:Date.now(), url:req.url, latest});
    const rel = new URL(req.url, 'http://localhost').pathname.replace(/^\/not_messenger\//, '');
    if (rel === 'fixture.html') {res.setHeader('Content-Type', 'text/html'); return res.end('<title>SW update fixture</title>');}
    if (rel === 'sw.js') {res.setHeader('Content-Type', 'application/javascript'); res.setHeader('Cache-Control', 'no-store'); return res.end(latest ? newWorker : oldWorker);}
    if (rel === 'nodes.json') {res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'public, max-age=31536000'); return res.end(JSON.stringify({generation: latest ? 'fresh' : 'retired'}));}
    const file = path.resolve(root, rel);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {res.statusCode = 404; return res.end();}
    res.setHeader('Content-Type', {'.js':'application/javascript','.css':'text/css','.html':'text/html','.json':'application/json','.wasm':'application/wasm'}[path.extname(file)] || 'application/octet-stream');
    res.end(fs.readFileSync(file));
});
(async () => {
    try {
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const origin = `http://127.0.0.1:${server.address().port}/not_messenger/`;
        browser = await chromium.launch({headless: true, executablePath: process.env.DMASH_CHROMIUM || '/home/jcode/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome'});
        context = await browser.newContext();
        page = await context.newPage();
        page.on('console', message => report.events.push({type:'console', text:message.text()}));
        page.on('pageerror', error => report.events.push({type:'pageerror', text:error.message}));
        await page.goto(origin + 'fixture.html');
        await page.evaluate(() => {
            window.activationMessages = [];
            navigator.serviceWorker.addEventListener('message', event => {
                if (event.data?.type === 'DMASH_RELEASE_ACTIVATED') window.activationMessages.push({at:Date.now(), ...event.data});
            });
        });
        await page.evaluate(async () => {
            localStorage.setItem('synthetic-identity', 'preserve');
            await new Promise((resolve, reject) => {
                const open = indexedDB.open('synthetic-preserved-vault', 1);
                open.onupgradeneeded = () => open.result.createObjectStore('rows');
                open.onerror = () => reject(open.error);
                open.onsuccess = () => {const db = open.result, tx = db.transaction('rows', 'readwrite'); tx.objectStore('rows').put('ciphertext-sentinel', 'row'); tx.oncomplete = () => {db.close(); resolve();};};
            });
            if ((await (await fetch('nodes.json')).json()).generation !== 'retired') throw Error('HTTP cache seed failed');
            window.swRegistration = await navigator.serviceWorker.register('sw.js');
            await navigator.serviceWorker.ready;
        });
        await page.waitForFunction(() => window.swRegistration?.active?.state === 'activated'
            && navigator.serviceWorker.controller === window.swRegistration.active
            && window.activationMessages.some(message => message.release.endsWith('.36')));
        latest = true;
        await page.evaluate(async () => (await navigator.serviceWorker.getRegistration()).update());
        // Keep the polling predicate synchronous: this Playwright version
        // treats a returned Promise as truthy before its boolean resolves.
        await page.waitForFunction(release => window.swRegistration?.active?.state === 'activated'
            && navigator.serviceWorker.controller === window.swRegistration.active
            && window.activationMessages.some(message => message.release === release), release, {timeout: 60000});
        report.cacheObservation = await page.evaluate(async release => ({
            activationMessages: window.activationMessages, href: location.href, baseURI: document.baseURI, controller: navigator.serviceWorker.controller?.scriptURL,
            caches: await Promise.all((await caches.keys()).map(async name => {
                const cache = await caches.open(name), requests = await cache.keys();
                return {name, requests: requests.map(request => ({url:request.url, cache:request.cache})),
                    relativeCatalog: (await cache.match('nodes.json')) ? true : false,
                    absoluteCatalog: (await cache.match(new URL('nodes.json', location.href).href)) ? true : false};
            }))
        }), release);
        save();
        assert(report.cacheObservation.caches.some(cache => cache.name === 'dmash-static-' + release));
        assert(!report.cacheObservation.caches.some(cache => cache.name.endsWith('.36')), 'old release removed after activation');
        assert.equal(await page.evaluate(async () => (await (await caches.open((await caches.keys()).find(k => k.endsWith('.37')))).match('nodes.json')).text()), JSON.stringify({generation:'fresh'}), 'new installation bypassed stale HTTP catalog');
        assert.equal(await page.evaluate(async () => (await (await fetch('nodes.json', {cache:'no-store'})).json()).generation), 'fresh');
        await page.evaluate(async release => {
            const ghost = await caches.open('dmash-static-ghost-old');
            await ghost.put('ghost-only.js', new Response('ghost-script'));
            await ghost.put('nodes.json', new Response('ghost-catalog'));
            if (localStorage.getItem('synthetic-identity') !== 'preserve') throw Error('identity lost');
            const row = await new Promise((resolve, reject) => {const open = indexedDB.open('synthetic-preserved-vault'); open.onerror = () => reject(open.error); open.onsuccess = () => {const db = open.result, get = db.transaction('rows').objectStore('rows').get('row'); get.onsuccess = () => {db.close(); resolve(get.result);};};});
            if (row !== 'ciphertext-sentinel') throw Error('vault row lost');
        }, release);
        await context.setOffline(true);
        assert.equal(await page.evaluate(async () => (await (await fetch('nodes.json', {cache:'no-store'})).json()).generation), 'fresh', 'current release catalog remains available offline');
        assert(await page.evaluate(async () => {try {await fetch('ghost-only.js'); return false;} catch (_) {return true;}}), 'ghost cache cannot supply unknown script');
        report.result = 'PASS'; save();
        console.log('PASS genuine SW36→37 update: stale HTTP catalog bypass, live catalog, own-version offline fallback, ghost isolation, synthetic identity/vault preserved');
    } catch (error) {
        report.result = 'FAIL_RETAINED'; report.error = error.stack; report.failurePage = await page?.evaluate(async () => ({messages:window.activationMessages, caches:await caches.keys()})).catch(()=>null); save();
        if (context) {await context.storageState({path:path.join(artifactDir, 'synthetic-state.json'), indexedDB:true}); fs.chmodSync(path.join(artifactDir, 'synthetic-state.json'), 0o600);}
        console.error(error); console.error('FAILURE HOLD artifacts ' + artifactDir + ' pid ' + process.pid);
        await new Promise(resolve => process.once('SIGUSR2', resolve));
        throw error;
    } finally {
        await browser?.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => {console.error(error); process.exitCode = 1;});
