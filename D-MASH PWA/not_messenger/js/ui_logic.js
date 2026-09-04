/**
 * D-MASH GAMMA-1 // UI & DECOY CONTROLLER // V101.0
 * Калькулятор, Умный Вход, Счетчики маляв и запуск Ядра.
 */
"use strict";

const ui = {
    // This is both a UI bound and a resource bound: never let an unbounded
    // calculator value become input to the device-root KDF.
    maxInputLength: 10,
    minSecretLength: 4,
    curr: "0",
    hist: "",
    op: null,
    leftOperand: null,
    mode: 0, // 0: Калькулятор, 1: Master PIN, 2: Wipe PIN
    unlockGeneration: 0,
    biometricHoldMs: 3000,
    biometricTriggerKey: 'cfg_biometric_trigger',
    _holdTimer: null,
    _heldToken: null,
    _suppressToken: null,

    /**
     * СТАРТ СИСТЕМЫ
     */
    async init() {
        const isSetup = localStorage.getItem('sys_configured');
        if (!isSetup) {
            this.mode = 1;
            this.hist = "УСТАНОВКА MASTER-КОДА";
        } else {
            this.mode = 0;
            this.hist = "";
        }

        // Фикс клавиатуры для мобил
        window.addEventListener('focusin', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                setTimeout(() => {
                    e.target.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }, 300);
            }
        });

        this.update();
        this.bindCalculatorBiometricTrigger();
        if (window.NodeManager) {
            window.NodeManager.loadOriginList('nodes.json').catch(() => {});
        }
    },

    configuredBiometricTrigger() {
        const token = localStorage.getItem(this.biometricTriggerKey);
        return typeof token === 'string' && /^[0-9+\-*/%.]$/.test(token) ? token : null;
    },

    // The trigger is deliberately only a public calculator key, not a secret
    // or an unlock verifier.  A short press always remains calculator input.
    bindCalculatorBiometricTrigger() {
        const keypad = document.getElementById('keypad');
        if (!keypad || keypad.dataset.biometricBound === 'true') return;
        keypad.dataset.biometricBound = 'true';
        const tokenFor = (event) => event.target?.closest?.('[data-calc-token]')?.dataset?.calcToken || null;
        const clear = () => { if (this._holdTimer) clearTimeout(this._holdTimer); this._holdTimer = null; this._heldToken = null; };
        keypad.addEventListener('pointerdown', (event) => {
            const token = tokenFor(event);
            if (!token || event.button > 0) return;
            this._heldToken = token;
            this._holdTimer = setTimeout(() => { this._holdTimer = null; this.handleBiometricHold(token); }, this.biometricHoldMs);
        });
        keypad.addEventListener('pointerup', clear);
        keypad.addEventListener('pointercancel', clear);
        keypad.addEventListener('pointerleave', clear);
    },

    consumeLongPress(token) {
        if (this._suppressToken !== token) return false;
        this._suppressToken = null;
        return true;
    },

    async handleBiometricHold(token) {
        // During setup any calculator key may be selected; enrolment starts
        // only after its deliberate hold, not on an ordinary tap.
        if (this.mode === 6) {
            this._suppressToken = token;
            try {
                if (typeof Core === 'undefined' || !(await Core.setupDeviceBiometrics())) throw new Error('unavailable');
                localStorage.setItem(this.biometricTriggerKey, token);
                this.mode = 0; this.resetCalculator();
            } catch (_) { this.hist = ''; this.update(); }
            return;
        }
        if (this.mode !== 0 || token !== this.configuredBiometricTrigger()) return;
        this._suppressToken = token;
        try {
            if (typeof Core === 'undefined' || !(await Core.unlockDeviceWithBiometrics())) return;
            this.resetCalculator();
            await this.show_gate();
        } catch (_) {
            // Preserve the calculator disguise for cancellation/failure.
            this.resetCalculator();
        }
    },

    beginBiometricTriggerSetup() {
        // This entry point is reachable only from the post-device-unlock Global
        // Settings screen.  Do not let an account session become a substitute
        // for an unlocked DeviceRoot.
        if (typeof Core === 'undefined' || !Core.deviceState || window.DeviceRoot?.state !== Core.deviceState) return false;
        const calculator = document.getElementById('app-container');
        const settings = document.getElementById('settings-layer');
        if (calculator) { calculator.style.display = 'flex'; calculator.style.opacity = '1'; }
        settings?.style?.setProperty('display', 'none', 'important');
        this.mode = 6; this.curr = '0'; this.op = null; this.hist = 'УДЕРЖИВАЙТЕ ЛЮБУЮ КНОПКУ 3 СЕК.'; this.update();
        return true;
    },

    /**
     * ПЕРЕХОД К ГЕЙТУ (Gamma-1 Ready)
     */
    async show_gate() {
        const container = document.getElementById('settings-layer');
        const gateBox = document.querySelector('.gate-container');
        const app = document.getElementById('app-container');

        if (gateBox) gateBox.innerHTML = '<div style="color:var(--main); text-align:center; font-family:monospace;">ДОСТУП ОГРАНИЧЕН</div>';
        app.style.opacity = '0';

        // Do not hold the decoy behind an arbitrary 200 ms timeout after a
        // flip-lock. The libraries are loaded on demand by the PIN path; once
        // they are ready, showing the gate should be immediate.
        await new Promise(requestAnimationFrame);
        {
            app.style.display = 'none';
            container.style.setProperty('display', 'flex', 'important');

            const accs = await this.getAccs();
            const hideList = localStorage.getItem('cfg_hide_list') === 'true';

            if (accs.length > 0 && !hideList) {
                await this.renderAccountSelector(accs);
            } else {
                this.renderLoginForm();
            }
            window.scrollTo(0, 0);
        }
    },

    async renderAccountSelector(accs) {
        const gateBox = document.querySelector('.gate-container');
        if (!gateBox) return;

        const listHtml = accs.map((a, idx) => {
            // Login is strictly local.  Do not poll the retired legacy Relay
            // API here: it creates a privacy leak and must never make account
            // selection fail when that separate service is unavailable.
            const badges = "";

            let icons = ''; if (a.lazy) icons += ' ⚡';

            return `
                <button class="gate-btn" style="margin-bottom:10px; background:#111; color:#0f0; border:1px solid #333; display:flex; justify-content:space-between; align-items:center;"
                    onclick="ui.selectAccountForLogin('${a.id}', ${!!a.lazy})">
                    <span style="display:flex; align-items:center;">${badges} ${a.id}</span>
                    <span style="font-size:0.8rem;">${icons}</span>
                </button>`;
        }).join('');

        gateBox.innerHTML = `
            <div style="position:relative; width:100%;">
                <div id="gate-status-text" style="color:#0f0; font-size:0.7rem; margin-bottom:15px; text-align:center;">КТО ЗАХОДИТ?</div>
                <button id="global-settings-button" class="gate-btn" type="button" aria-label="ГЛОБАЛЬНЫЕ НАСТРОЙКИ" title="ГЛОБАЛЬНЫЕ НАСТРОЙКИ" style="position:absolute; top:-8px; right:0; width:auto; min-width:0; padding:4px 8px; margin:0;" onclick="ui.renderGlobalSettings()">⚙</button>
            </div>
            <div class="acc-list-scroll" style="max-height:250px; overflow-y:auto; width:100%;">${listHtml}</div>
            <button class="gate-btn" onclick="ui.renderLoginForm()">+ НОВЫЙ ВХОД</button>
        `;
    },

    // This view is available after DeviceRoot unlock but before an account is
    // selected.  Keep it limited to device-owned state: it must not read or
    // mutate an account vault or use Core.activeIdentity.
    renderGlobalSettings() {
        const gateBox = document.querySelector('.gate-container');
        if (!gateBox) return;
        const sections = [
            'PUBLIC ROUTES',
            'QUICK NAME REGISTRY',
            'NODES',
            'DEVICE BIOMETRIC AUTH'
        ];
        const sectionHtml = sections.map(label => `<li style="padding:9px 0; border-bottom:1px solid #333; color:#ddd;">${label}</li>`).join('');
        gateBox.innerHTML = `
            <div id="global-settings-title" style="color:#0f0; font-size:0.8rem; margin-bottom:10px; text-align:center;">ГЛОБАЛЬНЫЕ НАСТРОЙКИ</div>
            <p style="color:#aaa; font-size:0.72rem; line-height:1.4; margin:0 0 12px; text-align:center;">НАСТРОЙКИ ЭТОГО УСТРОЙСТВА. АККАУНТ НЕ ВЫБРАН.</p>
            <ul aria-labelledby="global-settings-title" style="list-style:none; padding:0; margin:0 0 14px; max-height:250px; overflow-y:auto; text-align:left;">${sectionHtml}</ul>
            <button id="global-public-routes-button" class="gate-btn" type="button" onclick="ui.openPublicRoutes()">PUBLIC ROUTES</button>
            <button id="global-quick-names-button" class="gate-btn" type="button" onclick="ui.openQuickNames()">QUICK NAME REGISTRY</button>
            <button id="global-nodes-button" class="gate-btn" type="button" onclick="ui.renderGlobalNodes()">УПРАВЛЕНИЕ УЗЛАМИ</button>
            <button class="gate-btn" type="button" onclick="ui.beginBiometricTriggerSetup()">НАСТРОИТЬ БИОМЕТРИЮ УСТРОЙСТВА</button>
            <button class="gate-btn" type="button" onclick="ui.show_gate()">К СПИСКУ</button>
        `;
    },
    openPublicRoutes() {
        try {
            if (!window.DeviceRoutes || !window.DeviceRoot?.state) throw new Error('СНАЧАЛА РАЗБЛОКИРУЙТЕ УСТРОЙСТВО');
            const rows = window.DeviceRoutes.list().map(route => `<div style="padding:8px;margin:7px 0;border:1px solid #333;overflow-wrap:anywhere"><b>${route.current ? 'CURRENT' : 'PREVIOUS'} · ${route.active ? 'ACTIVE' : 'INACTIVE'}</b><div style="font-size:.6rem;color:#aaa">${route.routeId}</div><button class="gate-btn" onclick="ui.togglePublicRoute('${route.routeId}')">${route.active ? 'DEACTIVATE' : 'ACTIVATE'}</button>${route.current ? '<button class="gate-btn" style="margin-top:5px" onclick="ui.reissuePublicRoute()">REISSUE</button>' : ''}</div>`).join('') || 'PUBLIC ROUTES НЕ СОЗДАНЫ';
            document.querySelector('.gate-container').innerHTML = `<div style="color:#0f0;text-align:center">PUBLIC ROUTES</div>${rows}<button class="gate-btn" onclick="ui.createPublicRoute()">CREATE PUBLIC ROUTE</button><button class="gate-btn" style="margin-top:8px" onclick="ui.renderGlobalSettings()">НАЗАД</button>`;
        } catch (error) { window.Core?.customAlert?.('PUBLIC ROUTES', error.message); }
    },
    createPublicRoute() { window.DeviceRoutes.issue({ type: 'public-contact', allowedAccounts: [] }).then(() => this.openPublicRoutes()).catch(error => window.Core?.customAlert?.('PUBLIC ROUTES', error.message)); },
    reissuePublicRoute() { window.DeviceRoutes.reissue().then(() => this.openPublicRoutes()).catch(error => window.Core?.customAlert?.('PUBLIC ROUTES', error.message)); },
    togglePublicRoute(id) { const route = window.DeviceRoutes.list().find(item => item.routeId === id); window.DeviceRoutes.activate(id, !route.active); this.openPublicRoutes(); },
    openQuickNames() { return window.Core?.openQuickNames?.(); },
    renderGlobalNodes() {
        const gateBox = document.querySelector('.gate-container');
        const manager = window.NodeManager;
        if (!gateBox || !manager) return;
        const endpoints = (manager.endpoints || []).filter(endpoint => !manager.isExcludedNode?.(endpoint.url));
        const rows = endpoints.length ? endpoints.map(endpoint => {
            const selected = manager.active?.url === endpoint.url ? ' ОСНОВНОЙ' : '';
            return `<li style="padding:9px 0; border-bottom:1px solid #333; color:#ddd; word-break:break-word;">${endpoint.label}${selected}<br><small>${endpoint.url}</small><br><button class="gate-btn" type="button" style="margin-top:6px; padding:7px;" onclick="ui.selectGlobalNode('${endpoint.url}')">СДЕЛАТЬ ОСНОВНЫМ</button> <button class="gate-btn" type="button" style="margin-top:6px; padding:7px; background:#400; color:#fff;" onclick="ui.removeGlobalNode('${endpoint.url}')">УДАЛИТЬ</button></li>`;
        }).join('') : '<li style="padding:9px 0; color:#aaa;">УЗЛЫ НЕ ДОБАВЛЕНЫ</li>';
        gateBox.innerHTML = `
            <div id="global-nodes-title" style="color:#0f0; font-size:0.8rem; margin-bottom:10px; text-align:center;">NODES — УСТРОЙСТВО</div>
            <p style="color:#aaa; font-size:0.72rem; line-height:1.4; margin:0 0 12px; text-align:center;">СПИСОК СОХРАНЯЕТСЯ ТОЛЬКО НА ЭТОМ УСТРОЙСТВЕ.</p>
            <ul aria-labelledby="global-nodes-title" style="list-style:none; padding:0; margin:0 0 14px; max-height:250px; overflow-y:auto; text-align:left;">${rows}</ul>
            <button id="global-add-node-button" class="gate-btn" type="button" onclick="ui.addGlobalNode()">ДОБАВИТЬ УЗЕЛ</button>
            <button class="gate-btn" type="button" onclick="ui.renderGlobalSettings()">НАЗАД</button>
        `;
    },
    addGlobalNode() {
        const url = window.prompt?.('WSS URL УЗЛА');
        if (!url) return;
        try {
            const endpoint = window.NodeManager.add(url.trim());
            window.NodeManager.select(endpoint.url);
        } catch (_) { return; }
        this.renderGlobalNodes();
    },
    selectGlobalNode(url) {
        try { window.NodeManager.select(url); } catch (_) { return; }
        this.renderGlobalNodes();
    },
    removeGlobalNode(url) {
        if (window.confirm && !window.confirm('Удалить узел только из этого устройства?')) return;
        window.NodeManager?.remove(url);
        this.renderGlobalNodes();
    },
    async unlockDeviceWithBiometrics() {
        if (typeof Core === 'undefined' || typeof Core.unlockDeviceWithBiometrics !== 'function') return false;
        return Core.unlockDeviceWithBiometrics();
    },
    /**
     * ФОРМА ВХОДА
     */
    renderLoginForm(prefillId = "") {
        const box = document.querySelector('.gate-container');
        if (box) {
            box.innerHTML = `
                <div id="gate-status-text" style="color:#0f0; font-size:0.7rem; margin-bottom:10px; text-align:center;">ДОСТУП ОГРАНИЧЕН</div>
                <form onsubmit="event.preventDefault(); sys.loginAndSave();">
                    <input type="text" id="p1" class="gate-input" placeholder="ИДЕНТИФИКАТОР" value="${prefillId}" spellcheck="false" autocomplete="username">
                    <input type="password" id="p2" class="gate-input" placeholder="КЛЮЧ ДОСТУПА" autocomplete="current-password">
                    <label style="display:flex; gap:8px; align-items:center; color:#aaa; font-size:.8rem; margin-bottom:12px;">
                        <input type="checkbox" id="save-in-registry"> СОХРАНИТЬ В РЕЕСТРЕ
                    </label>
                    <button type="submit" class="gate-btn">ВОЙТИ</button>
                </form>
                <button class="gate-btn" style="margin-top:10px; background:transparent; color:#444;" onclick="ui.show_gate()">К СПИСКУ</button>
            `;
        }
    },

    async selectAccountForLogin(id, hasLazy) {
        if (typeof Core === 'undefined') return this.renderLoginForm(id);
        this.renderLoginForm(id);
    },

    async getAccs() {
        if (typeof Storage === 'undefined' || !Storage.openRegistry) return [];
        try {
            return await Storage.getAllRegistryAccounts();
        } catch (e) { return []; }
    },

    // Return the decoy calculator to its neutral display without changing the
    // current flow mode. Device unlock must not carry a PIN or calculation
    // into the account-selection surface.
    resetCalculator() {
        this.curr = "0";
        this.hist = "";
        this.op = null;
        this.leftOperand = null;
        this.update();
    },

    /**
     * МАТЕМАТИКА КАЛЬКУЛЯТОРА
     */
    num(n) {
        if (this.consumeLongPress(n)) return;
        // Do not rely on the keypad alone: callers can invoke this public UI
        // object directly. A number may have one decimal point and may never
        // exceed the bound (the former > check admitted eleven characters).
        if (typeof n !== 'string' || !/^[0-9.]$/.test(n)) return;
        if (n === '.' && this.curr.includes('.')) return;
        const next = this.curr === "0" && n !== "." ? n : this.curr + n;
        if (next.length > this.maxInputLength) return;
        this.curr = next;
        this.update();
    },

    cmd(c) {
        if (this.consumeLongPress(c)) return;
        if (c === 'AC') {
            this.curr = "0";
            if (this.mode === 1) this.hist = "УСТАНОВКА MASTER-КОДА";
            else if (this.mode === 2) this.hist = "УСТАНОВКА WIPE-КОДА";
            else this.hist = "";
            this.op = null;
            this.leftOperand = null;
        }
        else if (c === '±') this.setCalculatorValue(parseFloat(this.curr) * -1);
        else if (c === '%') this.setCalculatorValue(parseFloat(this.curr) / 100);
        else {
            // Master-secret and wipe-secret entry deliberately use the same
            // calculator grammar as the decoy. The evaluated value, never
            // stale display/history state, is supplied to the KDF boundary.
            if (this.mode !== 0 && ![1, 2, 3, 4, 5].includes(this.mode)) return;
            if (!['+', '-', '*', '/'].includes(c)) return;
            this.leftOperand = this.curr;
            this.op = c; this.hist = this.curr + " " + c; this.curr = "0";
        }
        this.update();
    },

    setCalculatorValue(value) {
        const next = String(value);
        if (!Number.isFinite(value) || next.length > this.maxInputLength) {
            this.curr = '0'; this.hist = 'ОШИБКА ВЫЧИСЛЕНИЯ'; this.op = null; this.leftOperand = null;
            return false;
        }
        this.curr = next;
        return true;
    },

    resolveExpression() {
        if (!this.op) return this.curr;
        const operator = this.op;
        const a = Number(this.leftOperand);
        const b = Number(this.curr);
        let result;
        if (operator === '+') result = a + b;
        if (operator === '-') result = a - b;
        if (operator === '*') result = a * b;
        if (operator === '/') result = a / b;
        this.op = null;
        this.leftOperand = null;
        this.hist = '';
        if (!this.setCalculatorValue(result)) { this.update(); return null; }
        return this.curr;
    },

    validSecret(value) {
        // DeviceRoot calls this a master PIN. Keep its existing numeric
        // minimum invariant while allowing an arithmetic expression to yield
        // that PIN (for example, 123 + 4567 => 4690).
        return typeof value === 'string' && new RegExp(`^\\d{${this.minSecretLength},${this.maxInputLength}}$`).test(value);
    },

    async eval() {
        if (this.consumeLongPress('=')) return;
        const candidate = this.resolveExpression();
        if (candidate === null) return;
        if (this.mode === 1) {
            if (!this.validSecret(candidate)) { this.hist = 'MASTER-КОД: МИНИМУМ 4 ЦИФРЫ'; this.update(); return; }
            localStorage.setItem('sys_m', await sys.fastHash(candidate));
            this.curr = "0"; this.mode = 2; this.hist = "УСТАНОВКА WIPE-КОДА";
            this.update(); return;
        }
        if (this.mode === 2) {
            if (!this.validSecret(candidate)) { this.hist = 'WIPE-КОД: МИНИМУМ 4 ЦИФРЫ'; this.update(); return; }
            localStorage.setItem('sys_w', await sys.fastHash(candidate));
            localStorage.setItem('sys_configured', 'true');
            this.mode = 0; this.curr = "0"; this.hist = "СИСТЕМА ГОТОВА";
            this.update(); setTimeout(() => { this.cmd('AC'); }, 1000); return;
        }
        if (this.mode === 3) {
            if (!this.validSecret(candidate) || await sys.fastHash(candidate) !== localStorage.getItem('sys_m')) { this.curr = '0'; this.hist = 'НЕВЕРНЫЙ MASTER-КОД'; this.update(); return; }
            this.pendingCurrentMasterSecret = candidate;
            this.curr = '0'; this.mode = 4; this.hist = 'НОВЫЙ MASTER-КОД'; this.update(); return;
        }
        if (this.mode === 4) {
            if (!this.validSecret(candidate)) { this.hist = 'MASTER-КОД: МИНИМУМ 4 ЦИФРЫ'; this.update(); return; }
            this.pendingMasterHash = await sys.fastHash(candidate); this.pendingNextMasterSecret = candidate; this.curr = '0'; this.mode = 5; this.hist = 'НОВЫЙ WIPE-КОД'; this.update(); return;
        }
        if (this.mode === 5) {
            if (!this.validSecret(candidate)) { this.hist = 'WIPE-КОД: МИНИМУМ 4 ЦИФРЫ'; this.update(); return; }
            try {
                // Rewrap first.  Do not replace the local verifier until the
                // existing DeviceRoot has been proved unlockable and safely
                // re-encrypted under the new master secret.
                if (typeof Core?.changeDeviceMasterSecret === 'function') {
                    await Core.changeDeviceMasterSecret(this.pendingCurrentMasterSecret, this.pendingNextMasterSecret);
                }
                localStorage.setItem('sys_m', this.pendingMasterHash); localStorage.setItem('sys_w', await sys.fastHash(candidate));
                this.pendingMasterHash = null; this.pendingCurrentMasterSecret = null; this.pendingNextMasterSecret = null;
                this.mode = 0; this.curr = '0'; this.hist = 'КОДЫ ОБНОВЛЕНЫ'; this.update(); setTimeout(() => this.cmd('AC'), 1000); return;
            } catch (error) {
                this.pendingMasterHash = null; this.pendingCurrentMasterSecret = null; this.pendingNextMasterSecret = null;
                this.mode = 0; this.curr = '0'; this.hist = 'ОШИБКА УСТРОЙСТВА: ' + error.message; this.update(); return;
            }
        }

        const inputHash = await sys.fastHash(candidate);
        if (inputHash === localStorage.getItem('sys_m')) {
            if (!this.validSecret(candidate)) { this.curr = '0'; this.hist = 'НЕВЕРНЫЙ MASTER-КОД'; this.update(); return; }
            const devicePin = candidate;
            const generation = ++this.unlockGeneration;
            this.cmd('AC');
            // Show the loading status only for an intentional unlock.  The
            // flip-lock path resets the calculator directly and therefore
            // never passes through this branch.
            this.hist = "ЗАГРУЗКА ЯДРА...";
            this.update();
            const loaded = await sys.loadAllLibs();
            if (generation !== this.unlockGeneration) return;
            if (loaded) {
                try {
                    await Core.unlockDevice(devicePin);
                    this.resetCalculator();
                    await this.show_gate();
                } catch (error) {
                    // Keep an explicit migration path for records encrypted by
                    // a pre-device-auth build with the Account passphrase.
                    if (error?.code === 'UNLOCK_FAILED' && typeof Core?.migrateDeviceRootFromLegacyAccountPassphrase === 'function') {
                        // Account passphrases are not calculator PINs. Ask for
                        // the legacy account passphrase explicitly; cancellation
                        // and failure leave the encrypted record untouched.
                        const legacyPassphrase = window.prompt?.('Введите пароль прежнего аккаунта для миграции устройства:');
                        if (!legacyPassphrase) {
                            this.hist = 'МИГРАЦИЯ ОТМЕНЕНА. УСТРОЙСТВО НЕ ИЗМЕНЕНО.';
                        } else {
                            try {
                                await Core.migrateDeviceRootFromLegacyAccountPassphrase(legacyPassphrase, devicePin);
                                await Core.unlockDevice(devicePin);
                                this.resetCalculator();
                                await this.show_gate();
                                return;
                            } catch (_) {
                                this.hist = 'ПАРОЛЬ ПРЕЖНЕГО АККАУНТА НЕ ПОДОШЁЛ. УСТРОЙСТВО НЕ ИЗМЕНЕНО.';
                            }
                        }
                    } else this.hist = "ОШИБКА УСТРОЙСТВА: " + error.message;
                    this.update();
                }
            }
            else { this.hist = "ОШИБКА СЕТИ"; this.update(); }
            return;
        }
        if (inputHash === localStorage.getItem('sys_w')) { sys.wipe(); return; }

        if (!this.op) return;
        this.update();
    },

    update() {
        const curEl = document.getElementById('current');
        const histEl = document.getElementById('history');
        if (curEl) curEl.innerText = this.curr;
        if (histEl) histEl.innerText = this.hist;
    }
};

ui.startMasterReconfiguration = function() {
    Core.closeModal();
    document.getElementById('workspace')?.style && (document.getElementById('workspace').style.display = 'none');
    document.getElementById('settings-layer')?.style.setProperty('display', 'none', 'important');
    const calculator = document.getElementById('app-container');
    if (calculator) { calculator.style.display = 'flex'; calculator.style.opacity = '1'; }
    this.mode = 3; this.curr = '0'; this.op = null; this.hist = 'ПОВТОРИТЕ ТЕКУЩИЙ MASTER-КОД'; this.update();
};

const sys = {
    async fastHash(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    wipe() {
        document.getElementById('current').innerText = "УДАЛЕНИЕ...";
        document.body.style.background = '#ff003c';
        localStorage.clear(); sessionStorage.clear();
        indexedDB.databases().then(dbs => { dbs.forEach(db => indexedDB.deleteDatabase(db.name)); });
        setTimeout(() => { window.location.replace("https://google.com"); }, 1500);
    },


// В ui_logic.js
async loadAllLibs() {
    try {
        const ver = window.DMASH_RELEASE?.id || "ui-foundation-20260825.1";
        window.Module = { wasmBinaryFile: 'js/vendor/argon2.wasm' };

        window.KyberModule = {
            locateFile: (path) => path.endsWith('.wasm') ? 'js/vendor/kyber768.wasm' : path,
            // Ждем нашу инъекцию
            onRuntimeInitialized: () => { console.log("🔥 WASM READY"); }
        };

        await Promise.all([
            this.loadScript(`js/vendor/argon2-bundled.min.js?v=${ver}`),
            this.loadScript(`js/vendor/kyber768.js?v=${ver}`),
            this.loadScript(`js/device_root.js?v=${ver}`),
            this.loadScript(`js/storage.js?v=${ver}`),
            this.loadScript(`js/node_manager.js?v=${ver}`),
            this.loadScript(`js/core_engine.js?v=${ver}`),
            this.loadScript(`js/vendor/nacl-fast.min.js`),
            this.loadScript(`js/vendor/html5-qrcode.min.js`),
            this.loadScript(`js/vendor/qrcode.min.js`),
            this.loadScript(`js/vendor/nacl-util.min.js`)
        ]);
        // The direct runtime loader makes NodeManager available before unlock.
        // Repeat the refresh after deferred modules settle to recover safely if
        // an older application shell reached this code first.
        await window.NodeManager?.loadOriginList('nodes.json').catch(() => {});

        let wait = 0;
        while (wait < 100) {
            // ТЕПЕРЬ МЫ ЖДЕМ ИМЕННО HEAPU8, КОТОРУЮ МЫ ВКОЛОЛИ В КОРЕНЬ
            if (window.KyberModule && window.KyberModule.HEAPU8) break;
            await new Promise(r => setTimeout(r, 200));
            wait++;
        }
        // ПРИНУДИТЕЛЬНАЯ ПРОПИСКА QR
        if (typeof window.QRCode === 'undefined' && typeof qrcode !== 'undefined') {
            window.QRCode = qrcode;
        }
        this.shmon("INFO", "Двойной WASM засинхронен!");
        return true;
    } catch (e) { return false; }
},
    /**
     * СИСТЕМА ТОТАЛЬНОГО ШМОНА (LOGGING)
     */
    shmon: function(tag, msg, data = null) {
        const colors = {
            "INFO": "#00ff41", // Зеленый
            "WARN": "#ff9f0a", // Оранжевый
            "ERR":  "#ff003c", // Красный
            "CRYPTO": "#00dbff" // Голубой
        };
        const color = colors[tag] || "#fff";
        console.log(`%c[D-MASH][${tag}] %c${msg}`, `color:${color}; font-weight:bold;`, "color:#ccc;", data || "");
    },
    loadScript(src) {
        return new Promise((resolve, reject) => {
            const baseSrc = src.split('?')[0];
            if (document.querySelector(`script[src="${src}"]`)) return resolve();
            const s = document.createElement('script');
            s.src = src; s.async = true; s.onload = resolve;
            s.onerror = () => {
                setTimeout(() => {
                    const retry = document.createElement('script');
                    retry.src = baseSrc; retry.onload = resolve; retry.onerror = reject;
                    document.head.appendChild(retry);
                }, 1000);
            };
            document.head.appendChild(s);
        });
    },

    async init() {
        const v1 = document.getElementById('p1').value;
        const v2 = document.getElementById('p2').value;
        // Вызываем Core.boot (Gamma-1 Standard)
        if (!v1 || !v2 || typeof Core === 'undefined') return false;
        await Core.boot(v1, v2, { register: Boolean(document.getElementById('save-in-registry')?.checked) });
        return Boolean(Core.keys?.sign);
    },

    // Реестр создаётся Core.boot после успешной разблокировки. Это действие
    // идемпотентно и не сохраняет пароль или ключи в localStorage.
    async loginAndSave() {
        await this.init();
    },

};

ui.init();
