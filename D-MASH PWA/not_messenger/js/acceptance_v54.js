"use strict";

/*
 * D-MASH browser acceptance fixes v54.
 *
 * Emergency local recovery wipe:
 *   1020<MASTER_KEY>=
 *
 * The suffix must match the configured Master key verifier before any
 * destructive action begins. The reserved sequence is tracked separately from
 * the calculator display so it can exceed the normal decoy display length.
 * Device-biometric calculator gestures use a deliberate one-second hold.
 */
(function installAcceptanceV54(global) {
    const UI_PATCH = "__dmashAcceptanceV54EmergencyWipe";
    const PREFIX = "1020";
    const BIOMETRIC_HOLD_MS = 1000;
    const KNOWN_DATABASES = [
        "dm_gamma_vault",
        "dm_registry_v1",
        "dm_registry_secure_v1",
        "dmash_device_root_v1"
    ];

    function appUi() {
        try { if (typeof ui !== "undefined" && ui) return ui; } catch (_) {}
        return global.ui || null;
    }

    function appSys() {
        try { if (typeof sys !== "undefined" && sys) return sys; } catch (_) {}
        return global.DMashSys || null;
    }

    async function sha256Hex(value) {
        const bytes = new TextEncoder().encode(String(value));
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
        return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
    }

    async function masterMatches(masterKey) {
        const expected = localStorage.getItem("sys_m");
        if (!expected || !/^\d+$/.test(masterKey || "")) return false;
        const system = appSys();
        const actual = typeof system?.fastHash === "function"
            ? await system.fastHash(masterKey)
            : await sha256Hex(masterKey);
        return actual === expected;
    }

    function closeKnownHandles() {
        try { global.DMashStorage?.db?.close?.(); } catch (_) {}
        try { global.DMashStorage?.registry_instance?.close?.(); } catch (_) {}
        try { global.DeviceRoot?._store?.().db?.close?.(); } catch (_) {}
        try {
            for (const connection of global.NodeManager?.connections?.values?.() || []) {
                try { connection?.ws?.close?.(); } catch (_) {}
            }
        } catch (_) {}
    }

    async function deleteDatabase(name) {
        if (!name) return;
        await new Promise(resolve => {
            let settled = false;
            const done = () => { if (!settled) { settled = true; resolve(); } };
            try {
                const request = indexedDB.deleteDatabase(name);
                request.onsuccess = done;
                request.onerror = done;
                request.onblocked = () => setTimeout(done, 750);
                setTimeout(done, 2000);
            } catch (_) { done(); }
        });
    }

    async function wipeOriginStorage() {
        closeKnownHandles();

        const names = new Set(KNOWN_DATABASES);
        try {
            if (typeof indexedDB.databases === "function") {
                for (const item of await indexedDB.databases() || []) if (item?.name) names.add(item.name);
            }
        } catch (_) {}

        await Promise.all(Array.from(names, deleteDatabase));

        try {
            if (navigator.storage?.getDirectory) {
                const root = await navigator.storage.getDirectory();
                for await (const [name] of root.entries()) {
                    try { await root.removeEntry(name, { recursive: true }); } catch (_) {}
                }
            }
        } catch (_) {}

        try { for (const key of await caches.keys()) await caches.delete(key); } catch (_) {}
        try { for (const registration of await navigator.serviceWorker?.getRegistrations?.() || []) await registration.unregister(); } catch (_) {}

        try {
            for (const cookie of document.cookie.split(";")) {
                const name = cookie.split("=")[0]?.trim();
                if (!name) continue;
                document.cookie = `${name}=; Max-Age=0; path=/; SameSite=Strict`;
            }
        } catch (_) {}

        try { localStorage.clear(); } catch (_) {}
        try { sessionStorage.clear(); } catch (_) {}
    }

    async function emergencyWipe(uiObject, masterKey) {
        if (!(await masterMatches(masterKey))) {
            uiObject.curr = "0";
            uiObject.hist = "ОШИБКА";
            uiObject.op = null;
            uiObject.leftOperand = null;
            uiObject.update?.();
            return false;
        }

        uiObject.curr = "0";
        uiObject.hist = "УДАЛЕНИЕ...";
        uiObject.op = null;
        uiObject.leftOperand = null;
        uiObject.update?.();

        await wipeOriginStorage();

        try { global.location.replace("about:blank"); }
        catch (_) { try { global.location.reload(); } catch (_) {} }
        return true;
    }

    function patchUi(uiObject) {
        if (!uiObject || uiObject[UI_PATCH]) return false;
        if (typeof uiObject.num !== "function" || typeof uiObject.cmd !== "function" || typeof uiObject.eval !== "function") return false;

        const originalNum = uiObject.num.bind(uiObject);
        const originalCmd = uiObject.cmd.bind(uiObject);
        const originalEval = uiObject.eval.bind(uiObject);
        const originalBeginBiometric = typeof uiObject.beginBiometricTriggerSetup === "function"
            ? uiObject.beginBiometricTriggerSetup.bind(uiObject)
            : null;

        // One second is long enough to distinguish the gesture from a tap while
        // keeping calculator biometric unlock responsive.
        uiObject.biometricHoldMs = BIOMETRIC_HOLD_MS;
        if (originalBeginBiometric) {
            uiObject.beginBiometricTriggerSetup = function beginBiometricTriggerSetupV54(...args) {
                const result = originalBeginBiometric(...args);
                if (result !== false) {
                    this.hist = "УДЕРЖИВАЙТЕ ЛЮБУЮ КНОПКУ 1 СЕК.";
                    this.update?.();
                }
                return result;
            };
        }

        uiObject._emergencyWipeSequence = "";

        uiObject.num = function emergencySequenceNumberV54(token) {
            const suppressed = this._suppressToken === token;
            const result = originalNum(token);

            if (this.mode === 0 && !suppressed && /^[0-9]$/.test(String(token))) {
                const maxMaster = Number.isInteger(this.maxInputLength) ? this.maxInputLength : 10;
                const maxLength = PREFIX.length + maxMaster;
                this._emergencyWipeSequence = (this._emergencyWipeSequence + String(token)).slice(-maxLength);
            } else if (String(token) === ".") {
                this._emergencyWipeSequence = "";
            }
            return result;
        };

        uiObject.cmd = function emergencySequenceCommandV54(command) {
            this._emergencyWipeSequence = "";
            return originalCmd(command);
        };

        uiObject.eval = async function emergencySequenceEvalV54(...args) {
            if (this.mode === 0) {
                const sequence = String(this._emergencyWipeSequence || "");
                this._emergencyWipeSequence = "";
                if (sequence.startsWith(PREFIX)) {
                    const masterKey = sequence.slice(PREFIX.length);
                    const minLength = Number.isInteger(this.minSecretLength) ? this.minSecretLength : 4;
                    const maxLength = Number.isInteger(this.maxInputLength) ? this.maxInputLength : 10;
                    if (masterKey.length >= minLength && masterKey.length <= maxLength) {
                        if (await emergencyWipe(this, masterKey)) return;
                    } else {
                        this.curr = "0";
                        this.hist = "ОШИБКА";
                        this.op = null;
                        this.leftOperand = null;
                        this.update?.();
                    }
                    return;
                }
            }
            return originalEval(...args);
        };

        try { Object.defineProperty(uiObject, UI_PATCH, { value: true }); }
        catch (_) { uiObject[UI_PATCH] = true; }
        return true;
    }

    function install() { patchUi(appUi()); }
    install();
    const timer = setInterval(() => {
        if (patchUi(appUi())) clearInterval(timer);
    }, 25);
    setTimeout(() => clearInterval(timer), 35000);
})(window);
