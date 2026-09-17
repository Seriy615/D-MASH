'use strict';

const assert = require('node:assert/strict');
const { chromium } = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');

const base = (process.argv[2] || 'https://messenger.d-mash.ru/not_messenger/').replace(/\/$/, '');
const endpointFromCatalog = value => value.replace(/\/(dmp-c|dmash-client)\/v1$/, '/$1/v3');

(async () => {
    const browser = await chromium.launch({
        executablePath: process.env.DMASH_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        headless: true
    });
    const context = await browser.newContext();
    const page = await context.newPage();
    const failures = [];
    page.on('pageerror', error => failures.push(error.message));
    page.on('console', message => {
        if (message.type() === 'error' || /Response body is already used/i.test(message.text())) failures.push(message.text());
    });
    await page.addInitScript(() => {
        window.__dmashUnhandled = [];
        addEventListener('unhandledrejection', event => window.__dmashUnhandled.push(String(event.reason?.message || event.reason)));
    });
    try {
        await page.goto(base + '/', { waitUntil: 'domcontentloaded' });
        await page.evaluate(() => navigator.serviceWorker.ready);
        await page.waitForFunction(() => Boolean(navigator.serviceWorker.controller));
        const worker = context.serviceWorkers()[0];
        await worker.evaluate(() => {
            self.__acceptanceErrors = [];
            self.addEventListener('unhandledrejection', event => self.__acceptanceErrors.push(String(event.reason?.message || event.reason)));
        });
        // Exercise both SW fetch branches repeatedly.  A stale worker or a
        // delayed clone() must not produce an unhandled Response-body error.
        await page.evaluate(async root => {
            for (let round = 0; round < 3; round++) {
                await Promise.all(Array.from({ length: 12 }, (_, i) =>
                    fetch(`${root}/js/core_engine.js?acceptance=${round}-${i}`, { cache: 'no-store' }).then(response => response.arrayBuffer())));
                await (await fetch(`${root}/manifest.json?acceptance=${round}`, { cache: 'no-store' })).arrayBuffer();
            }
        }, base);
        await page.waitForFunction(() => typeof window.sys?.loadAllLibs === 'function', null, { timeout: 15000 });
        await page.evaluate(() => window.sys.loadAllLibs());
        await page.waitForFunction(() => window.DeviceClientV3 && window.DmashSavedMessages && window.DMashStorage, null, { timeout: 20000 });
        const result = await page.evaluate(async root => {
            const endpointFromCatalog = value => value.replace(/\/(dmp-c|dmash-client)\/v1$/, '/$1/v3');
            const catalog = await (await fetch(`${root}/nodes.json?acceptance=catalog`)).json();
            const endpoint = endpointFromCatalog(catalog.nodes?.[0]?.url || '');
            if (!/^wss:\/\//.test(endpoint) || !/\/dmash-client\/v3$/.test(endpoint)) throw Error('published v3 endpoint is invalid');
            // Use the published PWA's NodeManager and DeviceClientV3 path, not
            // a raw HTTP or standalone WebSocket probe.
            window.Core = window.Core || {};
            window.Core.device = { signing: nacl.sign.keyPair() };
            window.DeviceRoot.state = { root: new Uint8Array(32).fill(23) };
            window.DeviceRoot.transportIdentity = async nodeId => ({ nodeId, signing: nacl.sign.keyPair() });
            NodeManager.endpoints = [];
            NodeManager.probeActivePublicDeviceRoutes = async () => [];
            NodeManager.probePrivateRoutesV3 = async () => [];
            NodeManager.pullDeviceMailboxV3 = async () => {};
            const node = NodeManager.add(catalog.nodes[0].url, catalog.nodes[0].label, { public: true });
            await NodeManager.connect(node.url);
            const connection = NodeManager.connections.get(node.url);
            if (connection?.state !== 'connected' || connection.client?.state !== 'connected') throw Error(`PWA NodeManager did not authenticate: ${connection?.state}; ${connection?.error || connection?.client?.state}`);
            const status = await NodeManager.requestOn(connection, 'STATUS');
            if (status.type !== 'STATUS' || status.node_id !== connection.nodeId) throw Error('encrypted STATUS mismatch');

            const master = new Uint8Array(32).fill(19);
            window.Core = window.Core || {};
            window.Core.blindSalt = new Uint8Array(32).fill(17);
            const storage = window.DMashStorage;
            await storage.initGamma(master);
            const core = { activeIdentity: 'production-acceptance-account', activePeerId: DmashSavedMessages.ID, selectPeer: async () => {} };
            await DmashSavedMessages.ensure(storage);
            if (!DmashSavedMessages.isLocal(DmashSavedMessages.ID)) throw Error('Saved Messages identity missing');
            if (!await DmashSavedMessages.send(core, storage, 'production local note', false)) throw Error('local send failed');
            const rows = await storage.loadMessagesGamma(DmashSavedMessages.ID, 10, 0);
            if (rows[0]?.text !== 'production local note' || rows[0]?.transportState !== 'LOCAL') throw Error('local message was transported');
            storage.db.close();
            return { endpoint, nodeId: connection.nodeId, status: status.type, localState: rows[0].transportState };
        }, base);
        assert.deepEqual(failures, [], `production browser errors: ${failures.join('; ')}`);
        assert.deepEqual(await page.evaluate(() => window.__dmashUnhandled), []);
        assert.deepEqual(await worker.evaluate(() => self.__acceptanceErrors), []);
        console.log(JSON.stringify({ passed: true, ...result, checks: ['service-worker asset storm', 'v3 WELCOME', 'encrypted STATUS', 'Saved Messages local send'] }));
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
