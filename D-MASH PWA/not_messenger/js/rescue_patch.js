"use strict";

/*
 * D-MASH emergency rescue patch.
 *
 * This file deliberately patches the existing application in place instead of
 * introducing another shell/routing stack. It exists to restore the product
 * behaviour that was regressed by the September global update while the
 * underlying modules are refactored more carefully.
 */
(function rescueDmash(global) {
    const RESCUE_VERSION = "20260904.1";

    const getUi = () => {
        try { return typeof ui !== "undefined" ? ui : null; } catch (_) { return null; }
    };
    const getSys = () => {
        try { return typeof sys !== "undefined" ? sys : null; } catch (_) { return null; }
    };
    const getCore = () => {
        if (global.Core) return global.Core;
        try { return typeof Core !== "undefined" ? Core : null; } catch (_) { return null; }
    };
    const getStorage = () => {
        if (global.Storage) return global.Storage;
        try { return typeof Storage !== "undefined" ? Storage : null; } catch (_) { return null; }
    };

    const escapeHtml = (value) => {
        const core = getCore();
        if (core?.escapeHtml) return core.escapeHtml(String(value ?? ""));
        return String(value ?? "").replace(/[&<>"']/g, ch => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        }[ch]));
    };

    function installCalculatorRefresh() {
        const app = document.getElementById("app-container");
        if (!app || document.getElementById("dmash-calculator-refresh")) return;

        const button = document.createElement("button");
        button.id = "dmash-calculator-refresh";
        button.type = "button";
        button.textContent = "🔄";
        button.setAttribute("aria-label", "Обновить страницу");
        button.title = "Обновить страницу";
        button.style.cssText = [
            "position:fixed",
            "left:10px",
            "top:calc(env(safe-area-inset-top) + 8px)",
            "z-index:10020",
            "border:0",
            "background:transparent",
            "color:#aaa",
            "font-size:20px",
            "line-height:1",
            "padding:6px",
            "cursor:pointer"
        ].join(";");
        button.addEventListener("click", () => global.location.reload());
        app.appendChild(button);

        const badge = document.getElementById("dmash-build-id");
        if (badge) {
            badge.style.left = "auto";
            badge.style.right = "8px";
        }
    }

    function routeShareLink(route) {
        if (typeof global.serializeDmashRouteUri !== "function") {
            throw new Error("КАНОНИЧЕСКИЙ ФОРМАТ МАРШРУТА НЕДОСТУПЕН");
        }
        const fragment = global.serializeDmashRouteUri(route);
        const pathname = global.location.pathname.endsWith("/")
            ? global.location.pathname
            : global.location.pathname.replace(/\/[^/]*$/, "/");
        return `${global.location.origin}${pathname}${fragment}`;
    }

    async function copyText(value, title = "СКОПИРОВАНО") {
        const core = getCore();
        try {
            await global.navigator.clipboard.writeText(value);
            core?.customAlert?.(title, "ДАННЫЕ СКОПИРОВАНЫ");
            return true;
        } catch (_) {
            if (core?.customPrompt) {
                core.customPrompt(title, "СКОПИРУЙТЕ ВРУЧНУЮ:", () => {}, { value, readOnly: true });
            }
            return false;
        }
    }

    function installUiPatch() {
        const u = getUi();
        if (!u || u.__dmashRescueUi === RESCUE_VERSION) return Boolean(u);

        u.renderLoginForm = function renderLoginFormRescue(prefillId = "") {
            const box = document.querySelector(".gate-container");
            if (!box) return;
            box.innerHTML = `
                <div style="position:relative;width:100%;">
                    <div id="gate-status-text" style="color:#0f0;font-size:.7rem;margin-bottom:10px;text-align:center;">ДОСТУП ОГРАНИЧЕН</div>
                    <button id="global-settings-button" class="gate-btn" type="button" aria-label="ГЛОБАЛЬНЫЕ НАСТРОЙКИ" title="ГЛОБАЛЬНЫЕ НАСТРОЙКИ" style="position:absolute;top:-8px;right:0;width:auto;min-width:0;padding:4px 8px;margin:0;" onclick="ui.renderGlobalSettings()">⚙</button>
                </div>
                <form onsubmit="event.preventDefault();sys.loginAndSave();">
                    <input type="text" id="p1" class="gate-input" placeholder="ИДЕНТИФИКАТОР" value="${escapeHtml(prefillId)}" spellcheck="false" autocomplete="username">
                    <input type="password" id="p2" class="gate-input" placeholder="КЛЮЧ ДОСТУПА" autocomplete="current-password">
                    <label style="display:flex;gap:8px;align-items:center;color:#aaa;font-size:.8rem;margin-bottom:12px;">
                        <input type="checkbox" id="save-in-registry"> СОХРАНИТЬ В РЕЕСТРЕ
                    </label>
                    <button type="submit" class="gate-btn">ВОЙТИ</button>
                </form>
                <button class="gate-btn" style="margin-top:10px;background:transparent;color:#666;" onclick="ui.show_gate()">К СПИСКУ</button>
            `;
        };

        u.renderGlobalSettings = function renderGlobalSettingsRescue() {
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return;
            gateBox.innerHTML = `
                <div id="global-settings-title" style="color:var(--main);font-size:.9rem;font-weight:bold;margin-bottom:14px;text-align:center;">НАСТРОЙКИ УСТРОЙСТВА</div>
                <button id="global-public-routes-button" class="sys-modal-btn" type="button" onclick="ui.openPublicRoutes()">🧭 ПУБЛИЧНЫЕ МАРШРУТЫ</button>
                <button id="global-quick-names-button" class="sys-modal-btn" type="button" onclick="ui.renderGlobalQuickNames()">🏷️ БЫСТРЫЕ ИМЕНА</button>
                <button id="global-nodes-button" class="sys-modal-btn" type="button" onclick="ui.renderGlobalNodes()">🌐 УЗЛЫ</button>
                <button class="sys-modal-btn" type="button" onclick="ui.beginBiometricTriggerSetup()">🧬 БИОМЕТРИЯ УСТРОЙСТВА</button>
                <button class="sys-modal-btn" type="button" onclick="ui.startMasterReconfiguration()">🔑 СМЕНИТЬ MASTER-КОД</button>
                <button class="sys-modal-btn" type="button" onclick="ui.repairApplication()" style="border-color:#ff9f0a;color:#ff9f0a;">🛠 ПОЧИНИТЬ ПРИЛОЖЕНИЕ</button>
                <button class="sys-modal-btn primary" type="button" onclick="ui.show_gate()">НАЗАД</button>
            `;
        };

        u.repairApplication = function repairApplicationRescue() {
            const core = getCore();
            const run = async () => {
                try {
                    if ("serviceWorker" in global.navigator) {
                        const registrations = await global.navigator.serviceWorker.getRegistrations();
                        await Promise.all(registrations.map(registration => registration.unregister()));
                    }
                    if (global.caches?.keys) {
                        const keys = await global.caches.keys();
                        await Promise.all(keys.map(key => global.caches.delete(key)));
                    }
                    // Session-only runtime state may legitimately be stale. Do
                    // not touch localStorage: it contains user policy/node
                    // choices and is not an HTTP cache. IndexedDB is never
                    // touched by this repair operation.
                    try { global.sessionStorage.clear(); } catch (_) {}
                    global.location.reload();
                } catch (error) {
                    core?.customAlert?.("ПОЧИНКА", error?.message || "НЕ УДАЛОСЬ ОЧИСТИТЬ КЭШ");
                }
            };
            const message = "Будут удалены Service Worker, CacheStorage и временное состояние сессии. IndexedDB и LocalStorage останутся нетронутыми.";
            if (core?.customConfirm) core.customConfirm("ПОЧИНИТЬ ПРИЛОЖЕНИЕ", message, run);
            else if (global.confirm(message)) void run();
        };

        u.renderGlobalNodes = function renderGlobalNodesRescue() {
            const gateBox = document.querySelector(".gate-container");
            const manager = global.NodeManager;
            if (!gateBox || !manager) return;
            const endpoints = (manager.endpoints || []).filter(endpoint => !manager.isExcludedNode?.(endpoint.url));
            const rows = endpoints.length ? endpoints.map(endpoint => {
                const selected = manager.active?.url === endpoint.url;
                const connection = manager.connections?.get?.(endpoint.url);
                const state = connection?.state || "disconnected";
                const stateLabel = state === "connected" ? "ПОДКЛЮЧЕН" : state === "connecting" || state === "reconnecting" ? "ПОДКЛЮЧЕНИЕ…" : "НЕ ПОДКЛЮЧЕН";
                const encodedUrl = encodeURIComponent(endpoint.url);
                return `<div style="padding:10px;margin:8px 0;border:1px solid ${selected ? "var(--main)" : "#333"};text-align:left;overflow-wrap:anywhere;">
                    <b style="color:${selected ? "var(--main)" : "#ddd"};">${escapeHtml(endpoint.label || endpoint.url)}${selected ? " · ОСНОВНОЙ" : ""}</b>
                    <div style="font-size:.65rem;color:#888;margin-top:4px;">${escapeHtml(endpoint.url)}</div>
                    <div style="font-size:.65rem;color:#aaa;margin-top:4px;">${stateLabel}${connection?.lastLatencyMs != null ? ` · ${connection.lastLatencyMs} ms` : ""}</div>
                    <button class="sys-modal-btn" type="button" onclick="ui.selectGlobalNode(decodeURIComponent('${encodedUrl}'))">СДЕЛАТЬ ОСНОВНЫМ</button>
                    <button class="sys-modal-btn" type="button" style="border-color:#ff003c;color:#ff003c;" onclick="ui.removeGlobalNode(decodeURIComponent('${encodedUrl}'))">УДАЛИТЬ</button>
                </div>`;
            }).join("") : '<div style="padding:15px 0;color:#888;">НА ЭТОМ УСТРОЙСТВЕ УЗЛЫ ЕЩЁ НЕ ДОБАВЛЕНЫ.</div>';

            gateBox.innerHTML = `
                <div style="color:var(--main);font-weight:bold;margin-bottom:8px;">УЗЛЫ УСТРОЙСТВА</div>
                <div style="color:#888;font-size:.7rem;margin-bottom:10px;">«Запросить узел» выбирает доступный публичный Entry Node из каталога D-MASH, сохраняет его и подключается.</div>
                <div style="max-height:280px;overflow-y:auto;">${rows}</div>
                <button id="global-request-node-button" class="sys-modal-btn primary" type="button" onclick="ui.requestGlobalNode()">ЗАПРОСИТЬ УЗЕЛ</button>
                <button id="global-add-node-button" class="sys-modal-btn" type="button" onclick="ui.addGlobalNode()">ДОБАВИТЬ УЗЕЛ ВРУЧНУЮ</button>
                <button class="sys-modal-btn" type="button" onclick="ui.renderGlobalSettings()">НАЗАД</button>
            `;
        };

        u.requestGlobalNode = async function requestGlobalNodeRescue() {
            const core = getCore();
            try {
                const endpoint = await global.NodeManager.requestNode();
                this.renderGlobalNodes();
                core?.customAlert?.("УЗЕЛ", `ПОДКЛЮЧЕН: ${escapeHtml(endpoint.label || endpoint.url)}`);
            } catch (error) {
                core?.customAlert?.("УЗЕЛ", error?.message || "НЕ УДАЛОСЬ ЗАПРОСИТЬ УЗЕЛ");
            }
        };

        u.addGlobalNode = function addGlobalNodeRescue() {
            const core = getCore();
            const add = (value) => {
                if (!value) return;
                try {
                    const endpoint = global.NodeManager.add(value.trim());
                    global.NodeManager.select(endpoint.url);
                    this.renderGlobalNodes();
                } catch (error) {
                    core?.customAlert?.("УЗЕЛ", error?.message || "НЕКОРРЕКТНЫЙ УЗЕЛ");
                }
            };
            if (core?.customPrompt) core.customPrompt("ДОБАВИТЬ УЗЕЛ", "WSS URL УЗЛА:", add);
            else add(global.prompt?.("WSS URL УЗЛА") || "");
        };

        u.openPublicRoutes = function openPublicRoutesRescue() {
            const gateBox = document.querySelector(".gate-container");
            const routesApi = global.DeviceRoutes;
            const core = getCore();
            try {
                if (!gateBox || !routesApi || !global.DeviceRoot?.state) throw new Error("СНАЧАЛА РАЗБЛОКИРУЙТЕ УСТРОЙСТВО");
                const routes = routesApi.list();
                const rows = routes.map(route => {
                    const role = route.current ? "ОСНОВНОЙ" : "ПРЕДЫДУЩИЙ";
                    const status = route.active ? "ПРИЁМ ВКЛЮЧЕН" : "ПРИЁМ ВЫКЛЮЧЕН";
                    const shortId = `${route.routeId.slice(0, 10)}…${route.routeId.slice(-8)}`;
                    const encoded = encodeURIComponent(route.routeId);
                    return `<div style="padding:11px;margin:9px 0;border:1px solid ${route.current ? "var(--main)" : "#444"};text-align:left;overflow-wrap:anywhere;">
                        <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;">
                            <b style="color:${route.current ? "var(--main)" : "#aaa"};">${role}</b>
                            <span style="font-size:.62rem;color:${route.active ? "#00ff41" : "#ff9f0a"};">${status}</span>
                        </div>
                        <div style="font:10px monospace;color:#888;margin-top:7px;">${shortId}</div>
                        <button class="sys-modal-btn" type="button" onclick="ui.copyPublicRoute(decodeURIComponent('${encoded}'))">КОПИРОВАТЬ МАРШРУТ</button>
                        <button class="sys-modal-btn" type="button" onclick="ui.togglePublicRoute(decodeURIComponent('${encoded}'))">${route.active ? "ОТКЛЮЧИТЬ ПРИЁМ" : "ВКЛЮЧИТЬ ПРИЁМ"}</button>
                        ${route.current ? '<button class="sys-modal-btn" type="button" style="border-color:#ff9f0a;color:#ff9f0a;" onclick="ui.reissuePublicRoute()">СМЕНИТЬ КЛЮЧ МАРШРУТА</button>' : ''}
                    </div>`;
                }).join("");

                gateBox.innerHTML = `
                    <div style="color:var(--main);font-weight:bold;">ПУБЛИЧНЫЕ МАРШРУТЫ</div>
                    <div style="color:#888;font-size:.68rem;line-height:1.45;margin:8px 0 12px;text-align:left;">
                        ОСНОВНОЙ — текущий RouteID устройства. ПРЕДЫДУЩИЙ — один резервный RouteID после смены ключа, чтобы переход не был мгновенно обрублен. «Приём включён» означает, что маршрут разрешено объявлять через подключённые узлы. «Сменить ключ» создаёт новый RouteID; старый становится предыдущим.
                    </div>
                    <div style="max-height:300px;overflow-y:auto;">${rows || '<div style="padding:16px 0;color:#888;">МАРШРУТЫ ЕЩЁ НЕ СОЗДАНЫ.</div>'}</div>
                    ${routes.length ? '' : '<button class="sys-modal-btn primary" type="button" onclick="ui.createPublicRoute()">СОЗДАТЬ ПУБЛИЧНЫЙ МАРШРУТ</button>'}
                    <button class="sys-modal-btn" type="button" onclick="ui.renderGlobalSettings()">НАЗАД</button>
                `;
            } catch (error) {
                core?.customAlert?.("ПУБЛИЧНЫЕ МАРШРУТЫ", error?.message || "ОШИБКА МАРШРУТОВ");
            }
        };

        u.copyPublicRoute = async function copyPublicRouteRescue(routeId) {
            const core = getCore();
            try {
                const route = global.DeviceRoutes.list().find(item => item.routeId === routeId);
                if (!route) throw new Error("МАРШРУТ НЕ НАЙДЕН");
                await copyText(routeShareLink(route), "ПУБЛИЧНЫЙ МАРШРУТ");
            } catch (error) {
                core?.customAlert?.("ПУБЛИЧНЫЙ МАРШРУТ", error?.message || "НЕ УДАЛОСЬ СКОПИРОВАТЬ");
            }
        };

        u.createPublicRoute = function createPublicRouteRescue() {
            global.DeviceRoutes.issue({ type: "public-contact", allowedAccounts: [] })
                .then(() => this.openPublicRoutes())
                .catch(error => getCore()?.customAlert?.("ПУБЛИЧНЫЕ МАРШРУТЫ", error.message));
        };
        u.reissuePublicRoute = function reissuePublicRouteRescue() {
            const core = getCore();
            const run = () => global.DeviceRoutes.reissue()
                .then(() => this.openPublicRoutes())
                .catch(error => core?.customAlert?.("ПУБЛИЧНЫЕ МАРШРУТЫ", error.message));
            if (core?.customConfirm) {
                core.customConfirm("СМЕНА ROUTE ID", "Будет создан новый маршрутный ключ. Текущий ключ останется единственным предыдущим fallback-маршрутом.", run);
            } else void run();
        };
        u.togglePublicRoute = function togglePublicRouteRescue(routeId) {
            try {
                const route = global.DeviceRoutes.list().find(item => item.routeId === routeId);
                if (!route) throw new Error("МАРШРУТ НЕ НАЙДЕН");
                global.DeviceRoutes.activate(routeId, !route.active);
                this.openPublicRoutes();
            } catch (error) {
                getCore()?.customAlert?.("ПУБЛИЧНЫЕ МАРШРУТЫ", error.message);
            }
        };

        // The old compatibility patch could miss the calculator long-press
        // because ui_logic.js is loaded dynamically after release.js. Install
        // the trusted-pointerup bridge once ui actually exists.
        if (u.__historicalWebAuthnGestureV1 !== true) {
            const keypad = document.getElementById("keypad");
            if (keypad) {
                const perform = u.handleBiometricHold.bind(u);
                u._qualifiedBiometricToken = null;
                u.handleBiometricHold = function qualifyBiometricHold(token) {
                    this._qualifiedBiometricToken = token;
                    this._suppressToken = token;
                    return Promise.resolve(false);
                };
                const tokenFor = event => event.target?.closest?.("[data-calc-token]")?.dataset?.calcToken || null;
                keypad.addEventListener("pointerup", event => {
                    const token = tokenFor(event);
                    if (!token || u._qualifiedBiometricToken !== token) return;
                    u._qualifiedBiometricToken = null;
                    u._suppressToken = token;
                    void perform(token);
                }, true);
                const cancel = () => { u._qualifiedBiometricToken = null; };
                keypad.addEventListener("pointercancel", cancel, true);
                keypad.addEventListener("pointerleave", cancel, true);
                Object.defineProperty(u, "__historicalWebAuthnGestureV1", { value: true, configurable: false });
            }
        }

        const s = getSys();
        if (s?.loadAllLibs && !s.__dmashRescueLoadHook) {
            const originalLoadAllLibs = s.loadAllLibs.bind(s);
            s.loadAllLibs = async function loadAllLibsRescue(...args) {
                const result = await originalLoadAllLibs(...args);
                installHistoricalDeviceWebAuthnLate();
                installCorePatch();
                return result;
            };
            Object.defineProperty(s, "__dmashRescueLoadHook", { value: true, configurable: false });
        }

        Object.defineProperty(u, "__dmashRescueUi", { value: RESCUE_VERSION, configurable: false });
        return true;
    }

    function installHistoricalDeviceWebAuthnLate() {
        const root = global.DeviceRoot;
        if (!root || root.__historicalWebAuthnV1 === true) return Boolean(root);

        const WRAP = "webauthn-prf-aes-256-gcm-v1";
        const PRF_BYTES = 32;
        const IV_BYTES = 12;
        const ROOT_BYTES = 32;
        const GCM_TAG_BYTES = 16;
        const AAD = new TextEncoder().encode("dmash/device-root-webauthn-prf-wrap/v1");
        const b64 = bytes => btoa(String.fromCharCode(...bytes));
        const decodeB64 = (value, length) => {
            if (typeof value !== "string") throw new Error("invalid base64");
            const bytes = new Uint8Array(atob(value).split("").map(char => char.charCodeAt(0)));
            if (length !== undefined && bytes.length !== length) throw new Error("invalid encoded length");
            return bytes;
        };
        const makeError = (code, message) => {
            if (typeof global.DeviceRootError === "function") return new global.DeviceRootError(code, message);
            const error = new Error(message); error.code = code; return error;
        };
        const rawCredentialId = credential => decodeB64(root._credentialId(credential));
        const prfInput = () => new Uint8Array(PRF_BYTES);

        root.enrollWebAuthnPrf = async function enrollWebAuthnPrfHistoricalRescue() {
            this._requireCrypto();
            this._requireWebAuthn();
            if (!this.state?.root || !this.state?.record) throw makeError("DEVICE_LOCKED", "Unlock the device before enrolling biometrics.");
            if (this.state.record.biometricWrap) throw makeError("WEBAUTHN_ALREADY_ENROLLED", "Device biometric authentication is already enrolled.");

            const salt = prfInput();
            let credential;
            let output;
            try {
                const userId = this._crypto.getRandomValues(new Uint8Array(16));
                credential = await this._credentials().create({ publicKey: {
                    challenge: this._webauthnChallenge(),
                    rp: { name: "MathPro Security", id: global.location?.hostname },
                    user: { id: userId, name: "device", displayName: "MathPro Device" },
                    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                    authenticatorSelection: {
                        authenticatorAttachment: "platform",
                        userVerification: "required",
                        residentKey: "required"
                    },
                    extensions: { prf: { eval: { first: salt } } }
                } });
                output = this._prfResult(credential);
                const credentialId = rawCredentialId(credential);
                const key = await this._prfWrapKey(output);
                const iv = this._crypto.getRandomValues(new Uint8Array(IV_BYTES));
                const ciphertext = await this._crypto.subtle.encrypt(
                    { name: "AES-GCM", iv, additionalData: AAD }, key, this.state.root
                );
                const biometricWrap = {
                    wrap: WRAP,
                    credentialId: b64(credentialId),
                    prfSalt: b64(salt),
                    iv: b64(iv),
                    wrappedRoot: b64(new Uint8Array(ciphertext))
                };
                const record = { ...this.state.record, biometricWrap };
                await this._store().put(record);
                this.state.record = record;
                return Object.freeze({ enrolled: true });
            } catch (error) {
                if (error?.code) throw error;
                throw makeError("WEBAUTHN_ENROLLMENT_FAILED", "Platform WebAuthn enrollment did not complete.");
            } finally { output?.fill?.(0); }
        };

        root.unlockWithWebAuthnPrf = async function unlockWithWebAuthnPrfHistoricalRescue() {
            this._requireCrypto();
            this._requireWebAuthn();
            const record = await this._store().get();
            const wrap = record?.biometricWrap;
            let output;
            try {
                if (!record || record.version !== this.VERSION || !wrap || wrap.wrap !== WRAP) throw new Error("no supported biometric wrap");
                const credentialId = decodeB64(wrap.credentialId);
                const salt = decodeB64(wrap.prfSalt, PRF_BYTES);
                const iv = decodeB64(wrap.iv, IV_BYTES);
                const wrappedRoot = decodeB64(wrap.wrappedRoot, ROOT_BYTES + GCM_TAG_BYTES);
                const assertion = await this._credentials().get({ publicKey: {
                    challenge: this._webauthnChallenge(),
                    timeout: 60000,
                    userVerification: "required",
                    allowCredentials: [{ id: credentialId, type: "public-key" }],
                    extensions: { prf: { eval: { first: salt } } }
                } });
                output = this._prfResult(assertion);
                const key = await this._prfWrapKey(output);
                const plaintext = await this._crypto.subtle.decrypt(
                    { name: "AES-GCM", iv, additionalData: AAD }, key, wrappedRoot
                );
                const unlockedRoot = new Uint8Array(plaintext);
                if (unlockedRoot.length !== ROOT_BYTES) throw new Error("invalid root length");
                const identity = await this.deviceIdentity(unlockedRoot);
                this.state = { root: unlockedRoot, identity, created: false, record };
                return this.state;
            } catch (error) {
                if (this.state?.root) this.lock();
                if (error?.code === "WEBAUTHN_UNAVAILABLE") throw error;
                throw makeError("WEBAUTHN_UNLOCK_FAILED", "Device biometric authentication could not unlock this device.");
            } finally { output?.fill?.(0); }
        };

        Object.defineProperty(root, "__historicalWebAuthnV1", { value: true, configurable: false });
        return true;
    }

    function installPendingContactRows(core) {
        if (!core?.renderPeers || core.__dmashRescuePendingRows) return;
        const originalRenderPeers = core.renderPeers.bind(core);
        core.renderPeers = async function renderPeersWithPendingRequests(...args) {
            const result = await originalRenderPeers(...args);
            const list = document.getElementById("contact-list");
            if (!list) return result;
            list.querySelectorAll(".dmash-pending-contact-row").forEach(row => row.remove());
            try {
                const requests = (await this.getPendingContactRequestStore().list())
                    .filter(request => request.status === "pending")
                    .sort((a, b) => b.receivedAt - a.receivedAt);
                for (const request of [...requests].reverse()) {
                    const row = document.createElement("div");
                    row.className = "peer-item dmash-pending-contact-row";
                    row.style.cssText = "border:1px solid #49b9ff;border-left:3px solid #49b9ff;background:#03131d;padding:10px;margin-bottom:6px;";
                    const encoded = encodeURIComponent(request.id);
                    row.innerHTML = `
                        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
                            <div style="min-width:0;text-align:left;">
                                <b style="color:#7fd2ff;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(request.displayName)}</b>
                                <small style="color:#6d9db8;">ЗАПРОС В КОНТАКТЫ</small>
                            </div>
                            <div style="display:flex;gap:6px;flex-shrink:0;">
                                <button type="button" title="Принять" style="background:transparent;border:1px solid #49b9ff;color:#49b9ff;padding:5px 7px;" onclick="Core.startAcceptPendingContactRequest(decodeURIComponent('${encoded}'))">✅</button>
                                <button type="button" title="Отклонить" style="background:transparent;border:1px solid #49b9ff;color:#49b9ff;padding:5px 7px;" onclick="Core.rejectPendingContactRequest(decodeURIComponent('${encoded}'))">❌</button>
                                <button type="button" title="Сообщение" style="background:transparent;border:1px solid #49b9ff;color:#49b9ff;padding:5px 7px;" onclick="Core.readPendingContactRequest(decodeURIComponent('${encoded}'))">✉️</button>
                            </div>
                        </div>`;
                    list.prepend(row);
                }
            } catch (_) {
                // Device request inbox may be unavailable during an account
                // transition. Normal contacts must still render.
            }
            return result;
        };
        Object.defineProperty(core, "__dmashRescuePendingRows", { value: true, configurable: false });
    }

    function installCorePatch() {
        const core = getCore();
        if (!core || core.__dmashRescueCore === RESCUE_VERSION) return Boolean(core);

        // Account settings contain Account-owned actions only. Device routes,
        // nodes, biometrics, master secret, Telegram beacon and pending-contact
        // inbox remain in the pre-account global settings screen.
        core.openSettings = function openAccountSettingsRescue() {
            const h = `
                <button class="sys-modal-btn" type="button" onclick="Core.saveActiveAccountToRegistry()">СОХРАНИТЬ АККАУНТ В РЕЕСТРЕ</button>
                <button class="sys-modal-btn" type="button" onclick="Core.openAccountManager()">УПРАВЛЕНИЕ АККАУНТАМИ</button>
                <button class="sys-modal-btn primary" type="button" onclick="Core.closeModal()">ЗАКРЫТЬ</button>`;
            this.openModal("НАСТРОЙКИ АККАУНТА", h);
        };

        core.accountLogout = async function accountLogoutRescue() {
            const deviceState = global.DeviceRoot?.state || this.deviceState;
            const deviceIdentity = deviceState?.identity || null;
            const zero = value => {
                if (value instanceof Uint8Array) value.fill(0);
                else if (value && typeof value === "object") Object.values(value).forEach(zero);
            };

            if (this.callState !== "idle" || this.peerConnection || this.localStream) this.endCall?.();
            this.killAllMedia?.();
            if (this.peerConnection) { this.peerConnection.close(); this.peerConnection = null; }
            if (this.syncInterval) { clearInterval(this.syncInterval); this.syncInterval = null; }
            if (this.blobURLs) { this.blobURLs.forEach(url => URL.revokeObjectURL(url)); this.blobURLs = []; }

            zero(this.gammaKeys);
            zero(this.keys);
            this.gammaKeys = { master: null, sign: null, box: null };
            this.keys = { sign: null, box: null, pub_hex: null };
            this.blindSalt?.fill?.(0);
            this.blindSalt = null;
            this.privateRouteProbeGeneration++;
            this.activeIdentity = null;
            this.activePeerId = null;
            this.openingPeerId = null;
            this.pendingInboundByPeer?.clear?.();
            this.historyPrefetch?.clear?.();
            this.isSyncing = false;
            this.chatOffset = 0;
            this.isLoadingHistory = false;
            this.closeModal?.();

            // Drop the Account vault key/reference without deleting IndexedDB.
            const storage = getStorage();
            if (storage) {
                storage.masterKey = null;
                try { storage.db?.close?.(); } catch (_) {}
                storage.db = null;
            }

            // Device state intentionally survives ordinary Account logout.
            this.deviceState = deviceState;
            if (deviceIdentity) {
                this.device = Object.freeze({
                    id: deviceIdentity.deviceId,
                    fingerprints: deviceIdentity.fingerprints,
                    signing: deviceIdentity.signing,
                    agreement: deviceIdentity.agreement
                });
            }

            // Do NOT sessionStorage.clear(): NodeManager route/session state is
            // device scoped and must remain alive while choosing another account.
            const workspace = document.getElementById("workspace");
            if (workspace) { workspace.replaceChildren(); workspace.style.display = "none"; }
            const calculator = document.getElementById("app-container");
            if (calculator) { calculator.style.display = "none"; calculator.style.opacity = "1"; }
            const u = getUi();
            if (u) { u.curr = "0"; u.hist = ""; u.op = null; u.mode = 0; u.update(); }
            await u?.show_gate?.();
        };

        // Never silently erase a DeviceRoot merely because a persisted wrapper
        // failed to decrypt. Recovery/wipe must remain an explicit user action.
        core.recoverDeviceAfterConfirmedMaster = async function refuseImplicitDeviceRecovery() {
            const error = new Error("DeviceRoot НЕ ИЗМЕНЁН. Автоматическое создание новой личности после ошибки unlock запрещено; используйте явное восстановление/очистку только если вы действительно хотите заменить устройство.");
            error.code = "EXPLICIT_RECOVERY_REQUIRED";
            throw error;
        };

        core.showMyQR = async function showMyQrRescue(mode = "private", selectedRouteId = null) {
            this.flipLockSuppressed = true;
            const privateId = this.keys?.server_id || (this.keys?.sign ? this.bytesToHex(this.keys.sign.publicKey) : null);
            if (!privateId) return this.customAlert("ОШИБКА", "АККАУНТ НЕ ИНИЦИАЛИЗИРОВАН");

            let payload;
            let subtitle;
            let selector = "";
            this._shareMode = mode === "public" ? "public" : "private";
            this._shareRouteId = null;

            if (this._shareMode === "public") {
                const routes = global.DeviceRoutes?.list?.() || [];
                if (!routes.length) {
                    this.customAlert("PUBLIC ROUTE", "СНАЧАЛА СОЗДАЙТЕ ПУБЛИЧНЫЙ МАРШРУТ В НАСТРОЙКАХ УСТРОЙСТВА");
                    return;
                }
                const selected = routes.find(route => route.routeId === selectedRouteId) || routes.find(route => route.current) || routes[0];
                this._shareRouteId = selected.routeId;
                payload = routeShareLink(selected);
                subtitle = `PUBLIC ROUTE · ${selected.routeId.slice(0, 12)}…${selected.routeId.slice(-8)}`;
                selector = `<div style="margin:8px 0 12px;text-align:left;color:#888;font-size:.65rem;">ВЫБЕРИТЕ МАРШРУТНЫЙ КЛЮЧ:</div>` + routes.map(route => {
                    const encoded = encodeURIComponent(route.routeId);
                    const active = route.routeId === selected.routeId;
                    return `<button class="sys-modal-btn${active ? " primary" : ""}" type="button" style="font-size:.62rem;overflow-wrap:anywhere;" onclick="Core.showMyQR('public',decodeURIComponent('${encoded}'))">${route.current ? "ОСНОВНОЙ" : "ПРЕДЫДУЩИЙ"} · ${route.routeId.slice(0, 10)}…${route.routeId.slice(-8)}</button>`;
                }).join("");
            } else {
                const contribution = await this.ensurePairingContribution();
                payload = JSON.stringify({ type: "DMASH_PAIRING_V1", version: 1, user_id: privateId, contribution });
                subtitle = `PRIVATE ACCOUNT · ${privateId.slice(0, 16)}…${privateId.slice(-8)}`;
            }

            const c = `
                <div style="text-align:center;">
                    <div style="display:flex;gap:8px;margin-bottom:8px;">
                        <button class="sys-modal-btn${this._shareMode === "private" ? " primary" : ""}" style="margin:0;" onclick="Core.showMyQR('private')">PRIVATE</button>
                        <button class="sys-modal-btn${this._shareMode === "public" ? " primary" : ""}" style="margin:0;" onclick="Core.showMyQR('public')">PUBLIC</button>
                    </div>
                    ${selector}
                    <div id="qr-target" style="background:#fff;padding:15px;margin:10px auto;display:inline-block;border-radius:8px;"></div>
                    <div style="font-size:.62rem;color:#0f0;margin-bottom:12px;word-break:break-all;font-family:monospace;background:#111;padding:10px;border:1px solid #333;">${escapeHtml(subtitle)}</div>
                    <div style="display:flex;gap:10px;">
                        <button class="sys-modal-btn primary" style="flex:1;" onclick="Core.copyMyId()">КОПИРОВАТЬ</button>
                        <button class="sys-modal-btn" style="flex:1;" onclick="Core.closeModal()">ЗАКРЫТЬ</button>
                    </div>
                </div>`;
            this.openModal("МОЙ QR", c);
            setTimeout(() => {
                const container = document.getElementById("qr-target");
                if (!container) return;
                try {
                    if (typeof QRCode === "undefined") throw new Error("QR library unavailable");
                    new QRCode(container, {
                        text: payload, width: 200, height: 200,
                        colorDark: "#000000", colorLight: "#ffffff",
                        correctLevel: QRCode.CorrectLevel.M
                    });
                } catch (error) {
                    container.innerHTML = `<b style="color:red;">${escapeHtml(error.message)}</b>`;
                }
            }, 50);
        };

        core.copyMyId = async function copyMyIdRescue() {
            try {
                if (this._shareMode === "public") {
                    const route = global.DeviceRoutes?.list?.().find(item => item.routeId === this._shareRouteId);
                    if (!route) throw new Error("ВЫБРАННЫЙ МАРШРУТ НЕ НАЙДЕН");
                    return copyText(routeShareLink(route), "PUBLIC ROUTE");
                }
                const myPublicId = this.keys?.server_id;
                if (!myPublicId) throw new Error("ACCOUNT ID НЕ ГОТОВ");
                const contribution = await this.ensurePairingContribution();
                const pairingPackage = JSON.stringify({ type: "DMASH_PAIRING_V1", version: 1, user_id: myPublicId, contribution });
                return copyText(pairingPackage, "PRIVATE ID");
            } catch (error) {
                this.customAlert("КОПИРОВАНИЕ", error?.message || "НЕ УДАЛОСЬ СКОПИРОВАТЬ");
                return false;
            }
        };

        installPendingContactRows(core);

        if (core.rejectPendingContactRequest && !core.__dmashRescueRejectPending) {
            core.rejectPendingContactRequest = function rejectPendingContactRequestRescue(id) {
                this.customConfirm("ОТКЛОНИТЬ ЗАПРОС", "Отклонить запрос в контакты?", async () => {
                    try {
                        await this.getPendingContactRequestStore().reject(id);
                        await this.renderPeers();
                    } catch (error) { this.pendingContactError(error); }
                });
            };
            Object.defineProperty(core, "__dmashRescueRejectPending", { value: true, configurable: false });
        }

        if (core.acceptPendingContactRequest && !core.__dmashRescueAcceptPending) {
            const originalAccept = core.acceptPendingContactRequest.bind(core);
            core.acceptPendingContactRequest = async function acceptPendingContactRequestRescue(...args) {
                const result = await originalAccept(...args);
                await this.renderPeers?.();
                return result;
            };
            Object.defineProperty(core, "__dmashRescueAcceptPending", { value: true, configurable: false });
        }

        Object.defineProperty(core, "__dmashRescueCore", { value: RESCUE_VERSION, configurable: false });
        return true;
    }

    function bootstrap() {
        installCalculatorRefresh();
        installUiPatch();
        installHistoricalDeviceWebAuthnLate();
        installCorePatch();

        // ui_logic/core_engine are lazy scripts. Retry until the UI exists; the
        // loadAllLibs hook installed above handles Core immediately afterwards.
        let attempts = 0;
        const timer = global.setInterval(() => {
            attempts++;
            installCalculatorRefresh();
            const haveUi = installUiPatch();
            installHistoricalDeviceWebAuthnLate();
            const haveCore = installCorePatch();
            if ((haveUi && haveCore) || attempts > 240) global.clearInterval(timer);
        }, 250);
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bootstrap, { once: true });
    else bootstrap();
})(window);
