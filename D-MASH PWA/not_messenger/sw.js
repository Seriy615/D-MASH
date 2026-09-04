/**
 * D-MASH service worker. Cache names are release-scoped and never touch
 * IndexedDB or localStorage, where user/device data lives.
 */

const RELEASE_ID = 'm1.5-functional-repair-20260905.51';
const CACHE_NAME = `dmash-static-${RELEASE_ID}`;
const CORE_ASSETS = [
    './index.html', './manifest.json', './nodes.json',
    './css/foundation.css', './css/app_shell.css', './css/runtime_fixes.css',
    './js/release.js', './js/locales/en.js', './js/locales/ru.js', './js/i18n.js',
    './js/app_shell.js', './js/ui_logic.js', './js/node_manager.js',
    './js/core_engine.js', './js/storage.js', './js/device_root.js',
    './js/device_routes.js', './js/dmash_links.js', './js/quick_name_registry.js',
    './js/contact_payloads.js', './js/contact_transport.js', './js/pending_contact_requests.js',
    './js/resource_pow.js', './js/ui_global_bridge.js', './js/runtime_fixes.js', './js/public_contact_runtime.js',
    './js/acceptance_fixes.js', './js/acceptance_v50.js', './js/acceptance_v51.js',
    './js/vendor/nacl-fast.min.js', './js/vendor/nacl-util.min.js',
    './js/vendor/qrcode.min.js', './js/vendor/html5-qrcode.min.js',
    './js/vendor/argon2-bundled.min.js', './js/vendor/argon2.wasm',
    './js/vendor/kyber768.js', './js/vendor/kyber768.wasm'
];

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(CORE_ASSETS))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => Promise.all(
            keys.filter(key => key.startsWith('dmash-static-') && key !== CACHE_NAME).map(key => caches.delete(key))
        ))
        .then(() => self.clients.claim())
        .then(() => self.clients.matchAll({ type: 'window' }))
        .then(clients => clients.forEach(client => client.postMessage({
            type: 'DMASH_RELEASE_ACTIVATED', release: RELEASE_ID
        })))
    );
});

self.addEventListener('message', event => {
    if (event.data?.type === 'DMASH_ACTIVATE_RELEASE') self.skipWaiting();
});

self.addEventListener('fetch', event => {
    if (event.request.method !== 'GET') return;
    const url = new URL(event.request.url);
    if (url.pathname.includes('/api/')) return;

    const networkFirst = event.request.mode === 'navigate'
        || url.pathname.endsWith('/index.html')
        || url.pathname.endsWith('/js/release.js')
        || url.pathname.endsWith('.js');
    if (networkFirst) {
        event.respondWith(
            fetch(event.request, { cache: 'no-store' }).then(response => {
                if (response?.ok) caches.open(CACHE_NAME).then(cache => cache.put(event.request, response.clone()));
                return response;
            }).catch(() => caches.match(event.request))
        );
        return;
    }

    event.respondWith(
        caches.match(event.request).then(cached => cached || fetch(event.request).then(response => {
            if (response?.ok) caches.open(CACHE_NAME).then(cache => cache.put(event.request, response.clone()));
            return response;
        }).catch(() => {
            if (event.request.mode === 'navigate') return caches.match('./index.html');
            return Response.error();
        }))
    );
});
