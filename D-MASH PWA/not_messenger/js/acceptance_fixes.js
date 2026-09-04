"use strict";

/*
 * Browser-acceptance fixes for the device/account boundary and sharing UX.
 *
 * Loaded after runtime_fixes.js.  Keep this file narrowly focused on the
 * user-visible regressions found during real PWA testing:
 * - Global Settings must remain device-scoped and usable after Device unlock.
 * - Public Routes must be viewable without an Account session.
 * - Node selection must expose the explicit public-node request action.
 * - Biometric enrollment must enter its calculator long-press setup reliably.
 * - "My QR" must make PRIVATE pairing vs PUBLIC Route sharing explicit and
 *   clipboard content must exactly match the QR payload.
 */
(function installAcceptanceFixes(global) {
    const PATCH = "dmashAcceptanceFixesV1";

    const esc = value => global.Core?.escapeHtml
        ? global.Core.escapeHtml(String(value ?? ""))
        : String(value ?? "").replace(/[&<>"']/g, ch => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        }[ch]));

    function unlockedState() {
        const state = global.DeviceRoot?.state;
        return state?.root ? state : null;
    }

    function syncCoreDeviceState() {
        const state = unlockedState();
        if (!state || !global.Core) return null;
        global.Core.deviceState = state;
        if (!global.Core.device && state.identity) {
            global.Core.device = Object.freeze({
                id: state.identity.deviceId,
                fingerprints: state.identity.fingerprints,
                signing: state.identity.signing,
                agreement: state.identity.agreement
            });
        }
        return state;
    }

    function requireDevice(title = "УСТРОЙСТВО") {
        const state = syncCoreDeviceState();
        if (state) return state;
        global.Core?.customAlert?.(title, "DeviceRoot заблокирован. Сначала разблокируйте устройство Master-кодом.");
        return null;
    }

    function publicContactLink(route) {
        if (!route?.routeId || !route?.certificate) throw new Error("Public Route повреждён или не содержит RouteCertificate");
        const fragment = global.serializeDmashContactUri({ v: 1, r: route.routeId, c: route.certificate });
        const url = new URL(global.location.href);
        url.search = "";
        url.hash = fragment.startsWith("#") ? fragment.slice(1) : fragment;
        return url.href;
    }

    function pairingPayload() {
        return global.Core.ensurePairingContribution().then(contribution => {
            const accountId = global.Core.keys?.server_id || global.Core.keys?.pub_hex;
            if (!/^[0-9a-f]{64}$/i.test(accountId || "")) throw new Error("Account ID недоступен");
            return JSON.stringify({
                type: "DMASH_PAIRING_V1",
                version: 1,
                user_id: accountId,
                contribution
            });
        });
    }

    async function copyExact(text, title) {
        try {
            await navigator.clipboard.writeText(text);
            global.Core?.customAlert?.("СКОПИРОВАНО", `${title} скопирован.`);
        } catch (_) {
            global.Core?.customPrompt?.(title, "Скопируйте вручную:", () => {}, { value: text, readOnly: true });
        }
    }

    function drawQr(payload) {
        const box = document.getElementById("dmash-share-qr");
        if (!box) return;
        box.replaceChildren();
        if (typeof global.QRCode !== "function") {
            box.textContent = "QR библиотека не загрузилась";
            return;
        }
        new global.QRCode(box, {
            text: payload,
            width: 256,
            height: 256,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: global.QRCode.CorrectLevel?.M
        });
    }

    function patchCore(core) {
        if (!core || core[PATCH]) return;

        // Account Settings stays Account-only.  The device-wide account
        // registry is intentionally moved to Global Settings below.
        core.openSettings = function accountOnlySettings() {
            if (!this.activeIdentity) return global.ui?.renderGlobalSettings?.();
            const accountId = this.keys?.server_id || this.keys?.pub_hex || this.activeIdentity;
            const html = `
                <div class="dmash-settings-title">НАСТРОЙКИ АККАУНТА</div>
                <div class="dmash-settings-note">Только параметры текущего аккаунта. Узлы, Public Routes, DeviceRoot и реестр устройства находятся в общих настройках.</div>
                <div class="dmash-settings-list">
                    <div class="dmash-account-identity">${esc(accountId)}</div>
                    <button class="dmash-settings-action" onclick="Core.copyMyId()">КОПИРОВАТЬ ID АККАУНТА</button>
                    <button class="dmash-settings-action" onclick="Core.setupLazyLogin()">БЕСПАРОЛЬНЫЙ ВХОД АККАУНТА</button>
                    <button class="dmash-settings-action" onclick="Core.showMyQR()">PUBLIC / PRIVATE QR</button>
                    <button class="dmash-settings-action primary" onclick="Core.closeModal()">ЗАКРЫТЬ</button>
                </div>`;
            this.openModal("АККАУНТ", html);
        };

        core.copyPairingPackage = async function copyExactPairingPackage() {
            const payload = await pairingPayload();
            await copyExact(payload, "PRIVATE PAIRING");
            return payload;
        };

        core._shareMode = "private";
        core._sharePublicRouteId = null;
        core._sharePayload = "";

        core.showMyQR = async function repairedShareQr() {
            this.flipLockSuppressed = true;
            if (!this.activeIdentity || !this.keys?.server_id) {
                return this.customAlert("QR", "Сначала войдите в аккаунт.");
            }
            this._shareMode = "private";
            const routes = global.DeviceRoutes?.list?.() || [];
            const preferred = routes.find(route => route.current && route.active)
                || routes.find(route => route.active)
                || routes[0]
                || null;
            this._sharePublicRouteId = preferred?.routeId || null;
            await this.renderShareQr();
        };

        core.setShareMode = async function setShareMode(mode) {
            this._shareMode = mode === "public" ? "public" : "private";
            await this.renderShareQr();
        };

        core.selectSharePublicRoute = async function selectSharePublicRoute(routeId) {
            this._shareMode = "public";
            this._sharePublicRouteId = routeId || null;
            await this.renderShareQr();
        };

        core.copyCurrentSharePayload = async function copyCurrentSharePayload() {
            if (!this._sharePayload) throw new Error("Share payload ещё не сформирован");
            const title = this._shareMode === "public" ? "PUBLIC CONTACT LINK" : "PRIVATE PAIRING";
            await copyExact(this._sharePayload, title);
        };

        core.renderShareQr = async function renderShareQr() {
            let payload = "";
            let modeNote = "";
            let routeSelector = "";

            if (this._shareMode === "public") {
                if (!requireDevice("PUBLIC ROUTE")) return;
                const routes = (global.DeviceRoutes?.list?.() || []).filter(route => route.active);
                if (!routes.length) {
                    const html = `
                        <div class="dmash-share-tabs">
                            <button class="dmash-share-tab" onclick="Core.setShareMode('private')">PRIVATE</button>
                            <button class="dmash-share-tab active" onclick="Core.setShareMode('public')">PUBLIC</button>
                        </div>
                        <div class="dmash-settings-note">Активных Public Routes нет.</div>
                        <button class="dmash-settings-action" onclick="Core.closeModal(); ui.openPublicRoutes()">СОЗДАТЬ PUBLIC ROUTE</button>
                        <button class="dmash-settings-action primary" onclick="Core.closeModal()">ЗАКРЫТЬ</button>`;
                    this.openModal("PUBLIC / PRIVATE", html);
                    return;
                }
                if (!routes.some(route => route.routeId === this._sharePublicRouteId)) this._sharePublicRouteId = routes[0].routeId;
                const route = routes.find(item => item.routeId === this._sharePublicRouteId);
                payload = publicContactLink(route);
                const options = routes.map(item => `<option value="${item.routeId}" ${item.routeId === route.routeId ? "selected" : ""}>${item.current ? "CURRENT · " : ""}${esc(item.routeId.slice(0, 12))}…</option>`).join("");
                routeSelector = `
                    <label class="dmash-share-label" for="dmash-share-route">PUBLIC ROUTE</label>
                    <select id="dmash-share-route" class="dmash-share-select" onchange="Core.selectSharePublicRoute(this.value)">${options}</select>
                    <div class="dmash-route-id">${esc(route.routeId)}</div>`;
                modeNote = "PUBLIC: QR содержит Contact Link + RouteCertificate. AccountID в нём нет.";
            } else {
                payload = await pairingPayload();
                modeNote = "PRIVATE: QR содержит AccountID + одно pair-specific contribution для приватного pairing. Кнопка копирования копирует ровно тот же payload.";
            }

            this._sharePayload = payload;
            const html = `
                <div class="dmash-share-tabs">
                    <button class="dmash-share-tab ${this._shareMode === "private" ? "active" : ""}" onclick="Core.setShareMode('private')">PRIVATE</button>
                    <button class="dmash-share-tab ${this._shareMode === "public" ? "active" : ""}" onclick="Core.setShareMode('public')">PUBLIC</button>
                </div>
                <div class="dmash-settings-note">${modeNote}</div>
                ${routeSelector}
                <div id="dmash-share-qr" class="dmash-share-qr"></div>
                <button class="dmash-settings-action" onclick="Core.copyCurrentSharePayload()">${this._shareMode === "public" ? "КОПИРОВАТЬ CONTACT LINK" : "КОПИРОВАТЬ PRIVATE PAIRING"}</button>
                <button class="dmash-settings-action primary" onclick="Core.closeModal()">ЗАКРЫТЬ</button>`;
            this.openModal("PUBLIC / PRIVATE", html);
            setTimeout(() => drawQr(payload), 0);
        };

        Object.defineProperty(core, PATCH, { value: true });
    }

    function nodeState(manager, endpoint) {
        const connection = manager.connections?.get?.(endpoint.url);
        return {
            connection,
            state: connection?.state || "disconnected",
            nodeId: connection?.nodeId || endpoint.nodeId || null,
            capabilities: [...(connection?.capabilities || [])],
            latency: connection?.lastLatencyMs ?? null
        };
    }

    function patchUi(ui) {
        if (!ui || ui[PATCH]) return;

        ui.renderGlobalSettings = function repairedGlobalSettings() {
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return;
            const unlocked = !!syncCoreDeviceState();
            gateBox.innerHTML = `
                <div class="dmash-settings-title">ОБЩИЕ НАСТРОЙКИ</div>
                <div class="dmash-settings-note">${unlocked ? "DeviceRoot разблокирован. Эти настройки относятся к установке, а не к выбранному аккаунту." : "DeviceRoot заблокирован."}</div>
                <div class="dmash-settings-list">
                    <button class="dmash-settings-card" onclick="ui.openPublicRoutes()"><b>PUBLIC ROUTES</b><small>Создание, активация, выбор RouteID и Contact Link</small></button>
                    <button class="dmash-settings-card" onclick="ui.renderGlobalNodes()"><b>НОДЫ</b><small>Запрос публичной Node, ручное добавление и подключения</small></button>
                    <button class="dmash-settings-card" onclick="ui.renderGlobalQuickNames()"><b>БЫСТРЫЕ ИМЕНА</b><small>Локальный зашифрованный реестр устройства</small></button>
                    <button class="dmash-settings-card" onclick="Core.openAccountManager()"><b>РЕЕСТР АККАУНТОВ</b><small>Все локальные аккаунты этой установки</small></button>
                    <button class="dmash-settings-card" onclick="Core.openPendingContacts()"><b>ЗАПРОСЫ В КОНТАКТЫ</b><small>Входящие запросы через Public Routes</small></button>
                    <button class="dmash-settings-card" onclick="ui.beginBiometricTriggerSetup()"><b>БИОМЕТРИЯ УСТРОЙСТВА</b><small>Привязка нескольких platform credentials к DeviceRoot</small></button>
                    <button class="dmash-settings-card" onclick="Core.setupTelegram()"><b>ТЕЛЕГРАМ-МАЯК</b><small>Уведомления устройства</small></button>
                    <button class="dmash-settings-card" onclick="ui.startMasterReconfiguration()"><b>СМЕНИТЬ MASTER-КОД</b><small>Перешифровать тот же DeviceRoot</small></button>
                </div>
                <button class="gate-btn dmash-settings-back" onclick="ui.show_gate()">НАЗАД К АККАУНТАМ</button>`;
        };

        ui.openPublicRoutes = function repairedPublicRoutes() {
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return;
            const routes = global.DeviceRoutes?.list?.() || [];
            const rows = routes.map(route => `
                <div class="dmash-route-row">
                    <div class="dmash-route-state">${route.current ? "CURRENT" : "PREVIOUS"} · ${route.active ? "ACTIVE" : "INACTIVE"}</div>
                    <div class="dmash-route-id">${esc(route.routeId)}</div>
                    <div class="dmash-route-actions">
                        <button class="gate-btn" onclick="Core.copyPublicContactLink('${route.routeId}')">CONTACT LINK</button>
                        <button class="gate-btn secondary" onclick="ui.togglePublicRoute('${route.routeId}')">${route.active ? "DEACTIVATE" : "ACTIVATE"}</button>
                        ${route.current ? '<button class="gate-btn secondary" onclick="ui.reissuePublicRoute()">REISSUE</button>' : ""}
                    </div>
                </div>`).join("") || '<div class="dmash-settings-note">Public Routes ещё не созданы.</div>';
            gateBox.innerHTML = `
                <div class="dmash-settings-title">PUBLIC ROUTES</div>
                <div class="dmash-settings-note">Маршрут принадлежит Device. Просмотр списка не требует входа в Account. Создание/активация требуют разблокированный DeviceRoot.</div>
                <div id="dmash-route-status" class="dmash-route-status"></div>
                ${rows}
                <button class="dmash-settings-action" onclick="ui.createPublicRoute()">СОЗДАТЬ PUBLIC ROUTE</button>
                <button class="gate-btn dmash-settings-back" onclick="ui.renderGlobalSettings()">НАЗАД</button>`;
        };

        ui.createPublicRoute = async function createPublicRouteAcceptance() {
            if (!requireDevice("PUBLIC ROUTE")) return;
            const status = document.getElementById("dmash-route-status");
            const set = (text, cls = "") => { if (status) { status.textContent = text; status.className = `dmash-route-status ${cls}`; } };
            try {
                set("Генерация Route keypair…");
                const route = await global.DeviceRoutes.issue({ type: "public-contact", allowedAccounts: [] });
                this.openPublicRoutes();
                const status2 = document.getElementById("dmash-route-status");
                if (status2) status2.textContent = "Route создан. Node-bound PoW…";
                const connected = global.NodeManager?.connectedConnections?.() || [];
                if (!connected.length) {
                    if (status2) status2.textContent = "Route создан локально. PoW выполнится при первом подключении к Node.";
                    return route;
                }
                const results = await global.NodeManager.probeActivePublicDeviceRoutes();
                const failures = results.filter(item => item.status === "rejected");
                if (failures.length === results.length && failures.length) throw failures[0].reason;
                if (status2) { status2.textContent = "Route зарегистрирован: EntryGrant + PoW + Probe готовы."; status2.classList.add("ok"); }
                return route;
            } catch (error) { set(error.message, "error"); }
        };

        ui.reissuePublicRoute = async function reissuePublicRouteAcceptance() {
            if (!requireDevice("PUBLIC ROUTE")) return;
            try {
                const route = await global.DeviceRoutes.reissue();
                this.openPublicRoutes();
                const connected = global.NodeManager?.connectedConnections?.() || [];
                if (connected.length) await global.NodeManager.probeActivePublicDeviceRoutes();
                const status = document.getElementById("dmash-route-status");
                if (status) { status.textContent = connected.length ? "Новый Route зарегистрирован и объявлен." : "Новый Route локальный; PoW при подключении к Node."; status.classList.add("ok"); }
                return route;
            } catch (error) { global.Core?.customAlert?.("PUBLIC ROUTE", error.message); }
        };

        ui.togglePublicRoute = async function togglePublicRouteAcceptance(routeId) {
            if (!requireDevice("PUBLIC ROUTE")) return;
            const route = global.DeviceRoutes?.list?.().find(item => item.routeId === routeId);
            if (!route) return;
            global.DeviceRoutes.activate(routeId, !route.active);
            this.openPublicRoutes();
            if (!route.active) {
                try { await global.NodeManager?.probeActivePublicDeviceRoutes?.(); }
                catch (error) { global.Core?.customAlert?.("PUBLIC ROUTE", error.message); }
            }
        };

        ui.renderGlobalNodes = async function repairedGlobalNodes() {
            const gateBox = document.querySelector(".gate-container");
            const manager = global.NodeManager;
            if (!gateBox || !manager) return;
            try { if (!manager.originNodes?.length) await manager.loadOriginList("nodes.json"); } catch (_) {}

            const endpoints = (manager.endpoints || []).filter(endpoint => !manager.isExcludedNode?.(endpoint.url));
            const rows = endpoints.map(endpoint => {
                const info = nodeState(manager, endpoint);
                const primary = manager.active?.url === endpoint.url;
                const connected = info.state === "connected";
                const encoded = encodeURIComponent(endpoint.url);
                return `
                    <div class="dmash-node-card">
                        <div class="dmash-node-head"><b>${esc(endpoint.label || new URL(endpoint.url).host)}</b><span class="dmash-node-state ${connected ? "ok" : ""}">${connected ? "● CONNECTED" : "○ " + esc(info.state.toUpperCase())}</span></div>
                        <div class="dmash-node-url">${esc(endpoint.url)}</div>
                        ${info.nodeId ? `<div class="dmash-node-meta">NodeID ${esc(info.nodeId)}</div>` : '<div class="dmash-node-meta">NodeID появится после DEVICE_AUTH</div>'}
                        <div class="dmash-node-meta">${info.latency != null ? `${info.latency} ms · ` : ""}${info.capabilities.length ? esc(info.capabilities.join(" · ")) : "capabilities пока не получены"}</div>
                        <div class="dmash-node-actions">
                            <button class="gate-btn secondary" onclick="ui.toggleGlobalNodeConnection(decodeURIComponent('${encoded}'))">${connected ? "ОТКЛЮЧИТЬ" : "ПОДКЛЮЧИТЬ"}</button>
                            <button class="gate-btn secondary" onclick="ui.selectGlobalNode(decodeURIComponent('${encoded}'))">${primary ? "ОСНОВНОЙ" : "СДЕЛАТЬ ОСНОВНЫМ"}</button>
                            <button class="gate-btn danger" onclick="ui.removeGlobalNode(decodeURIComponent('${encoded}'))">УДАЛИТЬ</button>
                        </div>
                    </div>`;
            }).join("") || '<div class="dmash-settings-note">На устройстве пока нет добавленных Node.</div>';

            gateBox.innerHTML = `
                <div class="dmash-settings-title">НОДЫ</div>
                <div class="dmash-settings-note">Node не добавляются из каталога автоматически. «Запросить публичную Node» — явное действие пользователя: Node добавляется, становится основной и проходит DEVICE_AUTH.</div>
                ${rows}
                <div class="dmash-node-primary-actions">
                    <button class="dmash-settings-action" onclick="ui.requestGlobalNode()">ЗАПРОСИТЬ ПУБЛИЧНУЮ NODE</button>
                    <button class="dmash-settings-action" onclick="ui.addGlobalNode()">ДОБАВИТЬ ПО WSS</button>
                </div>
                <button class="gate-btn dmash-settings-back" onclick="ui.renderGlobalSettings()">НАЗАД</button>`;
        };

        ui.requestGlobalNode = async function requestGlobalNode() {
            if (!requireDevice("NODE")) return;
            try {
                await global.NodeManager.requestNode();
                await new Promise(resolve => setTimeout(resolve, 250));
                await this.renderGlobalNodes();
            } catch (error) { global.Core?.customAlert?.("NODE", error.message); }
        };

        ui.addGlobalNode = function addGlobalNodeAcceptance() {
            if (!requireDevice("NODE")) return;
            global.Core?.customPrompt?.("ДОБАВИТЬ NODE", "WSS URL:", value => {
                if (!value?.trim()) return;
                try {
                    const endpoint = global.NodeManager.add(value.trim(), "", { autoConnect: false });
                    global.NodeManager.select(endpoint.url);
                    void this.renderGlobalNodes();
                } catch (error) { global.Core?.customAlert?.("NODE", error.message); }
            }, { value: "wss://" });
        };

        ui.toggleGlobalNodeConnection = async function toggleGlobalNodeConnection(url) {
            if (!requireDevice("NODE")) return;
            const manager = global.NodeManager;
            const connection = manager.connections?.get?.(url);
            try {
                if (connection?.state === "connected") manager.disconnectEndpoint?.(url);
                else await manager.connect(url);
                setTimeout(() => void this.renderGlobalNodes(), 300);
            } catch (error) { global.Core?.customAlert?.("NODE", error.message); }
        };

        ui.selectGlobalNode = function selectGlobalNodeAcceptance(url) {
            try { global.NodeManager.select(url); }
            catch (error) { return global.Core?.customAlert?.("NODE", error.message); }
            void this.renderGlobalNodes();
        };

        ui.removeGlobalNode = function removeGlobalNodeAcceptance(url) {
            if (global.confirm && !global.confirm("Удалить Node только из этого устройства?")) return;
            global.NodeManager?.remove(url);
            void this.renderGlobalNodes();
        };

        ui.beginBiometricTriggerSetup = function repairedBiometricSetup() {
            const state = requireDevice("БИОМЕТРИЯ");
            if (!state) return false;
            syncCoreDeviceState();
            const gateBox = document.querySelector(".gate-container");
            if (!gateBox) return false;
            gateBox.innerHTML = `
                <div class="dmash-settings-title">БИОМЕТРИЯ УСТРОЙСТВА</div>
                <div class="dmash-settings-note">Привязка относится к DeviceRoot, а не к Account. После старта выберите любую кнопку калькулятора и удерживайте её 3 секунды. WebAuthn откроется на отпускании кнопки.</div>
                <button class="dmash-settings-action" onclick="ui.enterBiometricTriggerSetup()">НАЧАТЬ ПРИВЯЗКУ</button>
                <button class="gate-btn dmash-settings-back" onclick="ui.renderGlobalSettings()">НАЗАД</button>`;
            return true;
        };

        ui.enterBiometricTriggerSetup = function enterBiometricTriggerSetup() {
            if (!requireDevice("БИОМЕТРИЯ")) return false;
            const calculator = document.getElementById("app-container");
            const settings = document.getElementById("settings-layer");
            if (calculator) {
                calculator.style.display = "flex";
                calculator.style.opacity = "1";
            }
            settings?.style?.setProperty("display", "none", "important");
            this.mode = 6;
            this.curr = "0";
            this.op = null;
            this.leftOperand = null;
            this.hist = "УДЕРЖИВАЙТЕ ЛЮБУЮ КНОПКУ 3 СЕК.";
            this.update?.();
            return true;
        };

        Object.defineProperty(ui, PATCH, { value: true });
    }

    function install() {
        const core = global.Core;
        const ui = global.ui;
        if (!core || !ui || !global.NodeManager || !global.DeviceRoutes || !global.DeviceRoot) return false;
        patchCore(core);
        patchUi(ui);
        return !!core[PATCH] && !!ui[PATCH];
    }

    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        try {
            if (install()) clearInterval(timer);
        } catch (error) {
            console.error("D-MASH acceptance fixes failed", error);
        }
        if (attempts > 1200) clearInterval(timer);
    }, 100);
    queueMicrotask(() => {
        try { if (install()) clearInterval(timer); }
        catch (error) { console.error("D-MASH acceptance fixes failed", error); }
    });
})(window);
