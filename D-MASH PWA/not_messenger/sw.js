/**
 * D-MASH GAMMA-1 // SERVICE WORKER // V107.0 // STATIC ONLY MODE
 */

const CACHE_NAME = 'dm-gamma-v107';

// 1. Установка: Скидываем старую робу и берем новую мгновенно
self.addEventListener('install', (e) => {
    self.skipWaiting();
});

// 2. Активация: Выжигаем ВСЕ старые кэши под ноль
self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys().then(keys => Promise.all(
            keys.map(k => caches.delete(k))
        ))
    );
    return self.clients.claim();
});

// 3. Перехват: Только доставка свежей статики
self.addEventListener('fetch', (e) => {
    const url = new URL(e.request.url);
    
    // Если это АПИ — воркер вообще не лезет, пусть идет напрямую в сеть
    if (url.pathname.includes('/api/')) return;

    // Для статики (JS, CSS, PNG) юзаем тактику "Network First"
    // Сначала лезем за свежаком, если сеть упала — берем из кармана (кэша)
    e.respondWith(
        fetch(e.request).then(res => {
            // Если получили нормальный ответ — обновляем кэш
            if (res && res.status === 200) {
                const copy = res.clone();
                caches.open(CACHE_NAME).then(c => c.put(e.request, copy));
            }
            return res;
        }).catch(() => {
            // Если сети нет — достаем заначку из кэша
            return caches.match(e.request);
        })
    );
});

// ВСЁ. НИКАКИХ WATCHER-ОВ, НИКАКИХ POST. ТИШИНА.