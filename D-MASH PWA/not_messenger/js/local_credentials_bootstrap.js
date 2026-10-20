"use strict";
(function (global) {
    const failure = (code, message) => Object.assign(new Error(message), { code });
    let task;
    async function emptyInstallation() {
        if (typeof global.indexedDB?.databases !== "function") throw failure("MIGRATION_DETECTION_UNAVAILABLE", "Невозможно безопасно проверить локальное хранилище.");
        const names = (await global.indexedDB.databases()).map(item => item.name).filter(Boolean);
        if (names.some(name => !["dmash_device_root_v1", "dmash_local_credentials_control_v1"].includes(name))) return false;
        // Public appearance/Node preferences do not authorize access to data.
        // Any preexisting credential/account hint requires explicit recovery.
        for (let i = 0; i < localStorage.length; i++) {
            const name = localStorage.key(i);
            if (name && !/^(dmash\.(theme|locale)$|cfg_|dmash_node_|dmash_active_node_|dmash_transport_mode_|node_|nodes$|dmash_origin_|dmash_release)/.test(name)) return false;
        }
        return true;
    }
    async function assertUpgradeExclusive() {
        const controller = global.navigator.serviceWorker?.controller;
        if (!controller) return; // SW-blocked development/native adapter scope.
        const reply = await new Promise((resolve, reject) => {
            const channel = new MessageChannel();
            const timer = setTimeout(() => { channel.port1.close(); reject(failure("CREDENTIAL_UPGRADE_UNSUPPORTED", "Обновите приложение и закройте другие вкладки перед миграцией кодов.")); }, 3000);
            channel.port1.onmessage = ({ data }) => { clearTimeout(timer); channel.port1.close(); resolve(data); };
            controller.postMessage({ type: "DMASH_CREDENTIAL_UPGRADE_CHECK" }, [channel.port2]);
        });
        if (reply?.release !== global.DMASH_RELEASE.id || reply.otherClients !== 0) throw failure("CREDENTIAL_UPGRADE_OTHER_TABS", "Закройте остальные вкладки D-MASH и повторите вход; локальные ключи не изменены.");
    }
    async function shutdown() {
        if (global.Core?.terminateSession) global.Core.terminateSession(); else global.DeviceRoot.lock();
        for (const runtime of [global.Core?._nodeRuntimeHostV4, global.NodeRuntimeHostV4?.current, global.NodeManager]) {
            await runtime?.close?.(); await runtime?.stop?.(); await runtime?.disconnectAll?.();
        }
        for (const connection of global.NodeManager?.connections?.values?.() || []) connection?.ws?.close?.();
        global.DMashStorage?.db?.close?.(); global.DMashStorage?.registry_instance?.close?.(); global.DeviceRoot._store().close?.();
    }
    async function cleanup() {
        if (global.navigator.storage?.getDirectory) {
            const directory = await global.navigator.storage.getDirectory();
            for await (const [name] of directory.entries()) await directory.removeEntry(name, { recursive: true });
        }
        for (const name of await global.caches?.keys?.() || []) if (!(await caches.delete(name))) throw failure("WIPE_CLEANUP_FAILED", "Не удалось удалить локальный кэш.");
        for (const registration of await global.navigator.serviceWorker?.getRegistrations?.() || []) if (!(await registration.unregister())) throw failure("WIPE_CLEANUP_FAILED", "Не удалось остановить Service Worker.");
        localStorage.clear(); sessionStorage.clear();
        if (localStorage.length || sessionStorage.length) throw failure("WIPE_CLEANUP_FAILED", "Локальные настройки ещё не удалены.");
    }
    global.DmashLocalCredentials = Object.freeze({
        emptyInstallation,
        ensure() {
            if (!task) task = Promise.resolve().then(() => {
                if (!global.DeviceRoot || !global.LocalCredentialService || !global.CredentialWorkerKdf || !global.navigator.locks?.request) throw failure("CREDENTIAL_RUNTIME_UNSUPPORTED", "Защищённое локальное хранилище недоступно. Данные не изменены.");
                const lifecycle = new global.CredentialLifecycle();
                const coordinator = new global.DurableWipeCoordinator({ shutdown, cleanup, lifecycle });
                const kdf = new global.CredentialWorkerKdf({ url: "js/local_credentials_worker.js?v=" + encodeURIComponent(global.DMASH_RELEASE.id) });
                const service = new global.LocalCredentialService({ root: global.DeviceRoot, kdf, lifecycle, inventory: emptyInstallation, upgradeGuard: assertUpgradeExclusive, wipeCoordinator: coordinator });
                let closing = false;
                global.DeviceRoot.onLock(() => {
                    if (!closing && (global.Core?.deviceState || global.Core?.keys?.sign)) {
                        closing = true; try { global.Core.terminateSession(); } finally { closing = false; }
                    }
                });
                global.LocalCredentials = service;
                return service;
            }).catch(error => { task = null; throw error; });
            return task;
        },
        async status() {
            const service = await this.ensure();
            if (await service.wipeCoordinator.pending()) return "wipe-pending";
            const record = await global.DeviceRoot._store().get();
            if (record) { global.DeviceRoot.validateCredentialRecord(record); return record.credentials?.state === "pending-wipe" ? "pending-wipe-code" : "configured"; }
            return await emptyInstallation() ? "fresh" : "recovery-required";
        }
    });
})(window);
