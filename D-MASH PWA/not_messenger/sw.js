/**
 * D-MASH service worker. Cache names are release-scoped and never touch
 * IndexedDB or localStorage, where user data lives.
 */

const RELEASE_ID = 'm1.5-browser-20260825.1';
const CACHE_NAME = `dmash-static-${RELEASE_ID}`;
const CORE_ASSETS = [
    './index.html', './js/release.js', './js/ui_logic.js', './js/node_manager.js',
    './js/core_engine.js', './js/storage.js', './nodes.json', './manifest.json'
];

// 1. Установка: Скидываем старую робу и берем новую мгновенно
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(CORE_ASSETS))
            .then(() => self.skipWaiting())
    );
});

// 2. Активация: Выжигаем ВСЕ старые кэши под ноль
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

// 3. Перехват: Только доставка свежей статики
self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;
    const url = new URL(event.request.url);
    
    // Если это АПИ — воркер вообще не лезет, пусть идет напрямую в сеть
    if (url.pathname.includes('/api/')) return;

    // Для статики (JS, CSS, PNG) юзаем тактику "Network First"
    // Сначала лезем за свежаком, если сеть упала — берем из кармана (кэша)
    event.respondWith(
        fetch(event.request).then(res => {
            // Если получили нормальный ответ — обновляем кэш
            if (res && res.status === 200) {
                const copy = res.clone();
                caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
            }
            return res;
        }).catch(() => {
            // Если сети нет — достаем заначку из кэша
            return caches.match(event.request).then(cached => {
                if (cached) return cached;
                if (event.request.mode === 'navigate') return caches.match('./index.html');
                return Response.error();
            });
        })
    );
});
