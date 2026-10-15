'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const base = 'https://app.example/not_messenger/';
const absolute = value => new URL(typeof value === 'string' ? value : value.url, base).href;

async function fixture() {
    const events = new Map(), stores = new Map(), network = [], httpCache = new Map();
    let offline = false, skipWaiting = false;
    const release = fs.readFileSync(require.resolve('../js/release.js'), 'utf8').match(/id: "([^"]+)"/)[1];
    const ownName = 'dmash-static-' + release;
    const fetch = async (input, options = {}) => {
        const url = absolute(input), cache = options.cache || input.cache || 'default';
        network.push({url, cache});
        if (offline) throw Error('offline');
        if (!['no-store', 'reload'].includes(cache) && httpCache.has(url)) return new Response(httpCache.get(url));
        return new Response(url.endsWith('/nodes.json') ? 'fresh-catalog' : 'fresh:' + url);
    };
    const caches = {
        async open(name) {
            if (!stores.has(name)) stores.set(name, new Map());
            const store = stores.get(name);
            return {
                async match(input) { return store.get(absolute(input))?.clone(); },
                async put(input, response) { store.set(absolute(input), response.clone()); },
                async addAll(inputs) {
                    const entries = await Promise.all(inputs.map(async input => {
                        const response = await fetch(input);
                        assert(response.ok, 'precache rejects failed responses');
                        return [absolute(input), response];
                    }));
                    for (const [url, response] of entries) store.set(url, response);
                }
            };
        },
        async keys() { return [...stores.keys()]; },
        async delete(name) { return stores.delete(name); },
        async match(input) {
            for (const name of stores.keys()) {
                const response = await (await caches.open(name)).match(input);
                if (response) return response;
            }
        }
    };
    const context = {URL, Request, Response, Promise, caches, fetch,
        self: {location: {href: base + 'sw.js'},
            addEventListener(type, listener) { events.set(type, listener); },
            skipWaiting() { skipWaiting = true; },
            clients: {async claim() {}, async matchAll() { return []; }}
        }
    };
    vm.runInNewContext(fs.readFileSync(require.resolve('../sw.js'), 'utf8'), context);
    const dispatch = async (type, request) => {
        const pending = []; let response;
        events.get(type)({request, waitUntil(promise) { pending.push(promise); }, respondWith(value) { response = value; }});
        const result = await response;
        await Promise.all(pending);
        return result;
    };
    return {stores, caches, network, httpCache, ownName, dispatch,
        offline(value) { offline = value; }, skipped() { return skipWaiting; }};
}

(async () => {
    const f = await fixture();
    f.httpCache.set(base + 'nodes.json', 'retired-host-catalog');
    await f.dispatch('install');
    assert(f.skipped());
    assert(f.network.every(request => ['no-store', 'reload'].includes(request.cache)), 'every install asset bypasses stale HTTP cache');
    assert.equal(await (await (await f.caches.open(f.ownName)).match(base + 'nodes.json')).text(), 'fresh-catalog');

    // A later network catalog response must replace even an already-poisoned
    // current release entry. The caller's no-store request must reach network.
    const own = await f.caches.open(f.ownName);
    await own.put(base + 'nodes.json', new Response('retired-host-catalog'));
    const response = await f.dispatch('fetch', new Request(base + 'nodes.json', {cache: 'no-store'}));
    assert.equal(await response.text(), 'fresh-catalog');
    assert.equal(await (await own.match(base + 'nodes.json')).text(), 'fresh-catalog');
    assert.equal(f.network.at(-1).cache, 'no-store');
    await own.put(base + 'nodes.json', new Response('retired-host-catalog'));
    assert.equal(await (await f.dispatch('fetch', new Request(base + 'nodes.json'))).text(), 'fresh-catalog', 'catalog is live even without explicit caller cache option');

    await own.put(base + 'dynamic.json', new Response('stale-dynamic'));
    assert.equal(await (await f.dispatch('fetch', new Request(base + 'dynamic.json', {cache: 'no-store'}))).text(), 'fresh:' + base + 'dynamic.json', 'no-store honored for non-JS requests');
    await own.put(base + 'dynamic.json', new Response('stale-dynamic'));
    assert.equal(await (await f.dispatch('fetch', new Request(base + 'dynamic.json', {cache: 'reload'}))).text(), 'fresh:' + base + 'dynamic.json', 'reload honored');

    // Ghost cache precedes current cache in CacheStorage ordering. Offline
    // fallback must never select its retired catalog, script, or CSS.
    const ghost = new Map();
    f.stores.clear(); f.stores.set('dmash-static-ghost-old-release', ghost);
    const old = await f.caches.open('dmash-static-ghost-old-release');
    const current = await f.caches.open(f.ownName);
    for (const asset of ['nodes.json', 'js/release.js', 'css/foundation.css']) {
        await old.put(base + asset, new Response('ghost-old'));
        await current.put(base + asset, new Response('own-offline:' + asset));
    }
    f.offline(true);
    for (const asset of ['nodes.json', 'js/release.js', 'css/foundation.css']) {
        assert.equal(await (await f.dispatch('fetch', new Request(base + asset))).text(), 'own-offline:' + asset);
    }
    await old.put(base + 'ghost-only.js', new Response('must-not-run'));
    assert.equal((await f.dispatch('fetch', new Request(base + 'ghost-only.js'))).type, 'error', 'missing own-version fallback fails closed');
    console.log('PASS SW fresh precache/catalog, caller cache policy, own-release offline fallback and ghost cache isolation');
})().catch(error => { console.error(error); process.exitCode = 1; });
