/**
 * D-MASH service worker. Cache names are release-scoped and never touch
 * IndexedDB or localStorage, where user data lives.
 */

const RELEASE_ID = 'm1.5-legacy-stabilization-20260831.20';
const CACHE_NAME = `dmash-static-${RELEASE_ID}`;
const CORE_ASSETS = [
    './index.html', './manifest.json', './nodes.json',
    './css/foundation.css', './css/app_shell.css',
    './js/release.js', './js/locales/en.js', './js/locales/ru.js', './js/i18n.js',
    './js/app_shell.js', './js/ui_logic.js', './js/node_manager.js',
    './js/core_engine.js', './js/storage.js'
];

// 1. Установка: новая полная оболочка кэшируется отдельно и не активируется,
// пока пользователь не выберет обновление. Это исключает mixed shell.
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(CORE_ASSETS))
            // This release is a compatibility rollback. Activate the fully
            // cached legacy shell without requiring the user to clear data.
            .then(() => self.skipWaiting())
    );
});

// 2. Активация: старая generation удаляется только после успешной установки
// новой. IndexedDB/localStorage и пользовательские ключи never touched.
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then(keys => Promise.all(
            keys
                .filter(key => key.startsWith('dmash-static-') && key !== CACHE_NAME)
                .map(key => caches.delete(key))
        ))
        .then(() => self.clients.claim())
        .then(() => self.clients.matchAll({ type: 'window' }))
        .then(clients => clients.forEach(client => client.postMessage({
            type: 'DMASH_RELEASE_ACTIVATED', release: RELEASE_ID
        })))
    );
});

self.addEventListener('message', (event) => {
    if (event.data?.type === 'DMASH_ACTIVATE_RELEASE') self.skipWaiting();
});

// 3. Перехват: Только доставка свежей статики
self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;
    const url = new URL(event.request.url);
    
    // Если это АПИ — воркер вообще не лезет, пусть идет напрямую в сеть
    if (url.pathname.includes('/api/')) return;

    // The shell and release marker must be able to discover a new deployment
    // while an older worker is still controlling the page. Other static assets
    // remain cache-first inside the atomic release cache.
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

    // Cache first inside the active generation. New assets become visible only
    // when the fully cached waiting worker is explicitly activated.
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
