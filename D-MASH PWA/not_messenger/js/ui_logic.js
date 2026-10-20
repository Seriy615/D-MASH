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
    _biometricSetup: null,
    _biometricEnrollment: null,

    /**
     * СТАРТ СИСТЕМЫ
     */
    async init() {
        this.hist = "ПРОВЕРКА ЛОКАЛЬНОГО ХРАНИЛИЩА..."; this.update();
        try {
            await sys.ensureCredentials();
            const status = await window.DmashLocalCredentials.status();
            this.mode = status === 'fresh' ? 1 : 0;
            this._credentialRecoveryAvailable = ['wipe-pending', 'recovery-required'].includes(status);
            this.hist = status === 'fresh' ? 'УСТАНОВКА MASTER-КОДА' : status === 'pending-wipe-code' ? 'ВВЕДИТЕ MASTER ДЛЯ ЗАВЕРШЕНИЯ НАСТРОЙКИ' : status === 'wipe-pending' ? 'ОЧИСТКА НЕ ЗАВЕРШЕНА — ВОССТАНОВЛЕНИЕ В НАСТРОЙКАХ' : status === 'recovery-required' ? 'ТРЕБУЕТСЯ ВОССТАНОВЛЕНИЕ. ДАННЫЕ СОХРАНЕНЫ' : '';
        } catch (error) { this.mode = 0; this._credentialRecoveryAvailable = true; this.hist = 'ХРАНИЛИЩЕ НЕДОСТУПНО: ' + error.message; }

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

    validBiometricTriggerToken(token) {
        return typeof token === 'string' && /^[0-9+\-*/%.]$/.test(token);
    },

    configuredBiometricTrigger() {
        const token = localStorage.getItem(this.biometricTriggerKey);
        return this.validBiometricTriggerToken(token) ? token : null;
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
            if (!this.validBiometricTriggerToken(token) || this._biometricEnrollment) return;
            const setup = this._biometricSetup;
            const request = {};
            this._biometricEnrollment = request;
            try {
                const enrolled = typeof Core !== 'undefined' && await Core.setupDeviceBiometrics();
                // Cancellation only ends trigger selection. An already open OS
                // credential prompt has its own Cancel; do not commit a stale
                // completion to a cancelled/new setup or a different root.
                if (this.mode !== 6 || this._biometricSetup !== setup) return;
                if (!enrolled || !setup?.deviceState || Core.deviceState !== setup.deviceState || window.DeviceRoot?.state !== setup.deviceState) {
                    this.cancelBiometricTriggerSetup(true);
                    return;
                }
                localStorage.setItem(this.biometricTriggerKey, token);
                this._biometricSetup = null;
                this.mode = 0;
                this.resetCalculator();
            } catch (_) {
                if (this.mode === 6 && this._biometricSetup === setup) this.cancelBiometricTriggerSetup(true);
            } finally {
                if (this._biometricEnrollment === request) this._biometricEnrollment = null;
            }
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

    cancelBiometricTriggerSetup(preserveClickSuppression = false) {
        if (this.mode !== 6) return false;
        this._biometricSetup = null;
        if (this._holdTimer) clearTimeout(this._holdTimer);
        this._holdTimer = null;
        this._heldToken = null;
        this._dmashQualifiedBiometricToken = null;
        if (!preserveClickSuppression) this._suppressToken = null;
        this.mode = 0;
        this.resetCalculator();
        if (typeof Core !== 'undefined' && Core.deviceState && window.DeviceRoot?.state === Core.deviceState) {
            this.renderGlobalSettings();
            document.getElementById('app-container')?.style?.setProperty('display', 'none');
            document.getElementById('settings-layer')?.style?.setProperty('display', 'flex', 'important');
        }
        return true;
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
                    ${window.Core.dataActionAttributes("selectAccountForLogin", [a.id, !!a.lazy])}>
                    <span style="display:flex; align-items:center;">${badges} ${this.quickNameEscape(a.id)}</span>
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
        window.Core.bindDataActions(gateBox);
    },

    // This view is available after DeviceRoot unlock but before an account is
    // selected.  Keep it limited to device-owned state: it must not read or
    // mutate an account vault or use Core.activeIdentity.
    renderGlobalSettings() {
        const gateBox = document.querySelector('.gate-container');
        if (!gateBox) return;
        gateBox.innerHTML = `
            <div id="global-settings-title" style="color:#0f0; font-size:0.95rem; font-weight:bold; margin-bottom:8px; text-align:left;">НАСТРОЙКИ УСТРОЙСТВА</div>
            <p style="color:#aaa; font-size:0.76rem; line-height:1.45; margin:0 0 14px; text-align:left;">Эти данные сохраняются только в этом браузере и доступны до выбора аккаунта.</p>
            <div style="display:grid;gap:9px;text-align:left;">
                <button id="global-public-routes-button" class="gate-btn" type="button" style="margin:0;text-align:left;padding:12px 13px;" onclick="ui.openPublicRoutes()"><b style="display:block;color:#0f0;">ПУБЛИЧНЫЕ МАРШРУТЫ</b><small style="color:#aaa;">Приём новых контактов на этом устройстве</small></button>
                <button id="global-quick-names-button" class="gate-btn" type="button" style="margin:0;text-align:left;padding:12px 13px;" onclick="ui.renderGlobalQuickNames()"><b style="display:block;color:#0f0;">БЫСТРЫЕ ИМЕНА</b><small style="color:#aaa;">Локальные подписи и значения, зашифрованные ключом устройства</small></button>
                <button id="global-nodes-button" class="gate-btn" type="button" style="margin:0;text-align:left;padding:12px 13px;" onclick="ui.renderGlobalNodes()"><b style="display:block;color:#0f0;">УЗЛЫ</b><small style="color:#aaa;">Выбор и список узлов только этого устройства</small></button>
                <button class="gate-btn" type="button" style="margin:0;text-align:left;padding:12px 13px;" onclick="ui.beginBiometricTriggerSetup()"><b style="display:block;color:#0f0;">БИОМЕТРИЯ УСТРОЙСТВА</b><small style="color:#aaa;">Разблокирует устройство, но не входит в аккаунт</small></button>
            </div>
            <button class="gate-btn" type="button" style="margin-top:15px;background:transparent;color:#aaa;border-color:#555;" onclick="ui.show_gate()">НАЗАД К ВЫБОРУ АККАУНТА</button>
        `;
    },
    openPublicRoutes() {
        try {
            if (!window.DeviceRoutes || !window.DeviceRoot?.state) throw new Error('СНАЧАЛА РАЗБЛОКИРУЙТЕ УСТРОЙСТВО');
            const rows = window.DeviceRoutes.list().map(route => `<div style="padding:8px;margin:7px 0;border:1px solid #333;overflow-wrap:anywhere"><b>${route.current ? 'CURRENT' : 'PREVIOUS'} · ${route.active ? 'ACTIVE' : 'INACTIVE'}</b><div style="font-size:.6rem;color:#aaa">${this.quickNameEscape(route.routeId)}</div><button class="gate-btn" ${window.Core.dataActionAttributes("togglePublicRoute", [route.routeId])}>${route.active ? 'DEACTIVATE' : 'ACTIVATE'}</button>${route.current ? '<button class="gate-btn" style="margin-top:5px" onclick="ui.reissuePublicRoute()">REISSUE</button>' : ''}</div>`).join('') || 'PUBLIC ROUTES НЕ СОЗДАНЫ';
            document.querySelector('.gate-container').innerHTML = `<div style="color:#0f0;text-align:center">PUBLIC ROUTES</div>${rows}<button class="gate-btn" onclick="ui.createPublicRoute()">CREATE PUBLIC ROUTE</button><button class="gate-btn" style="margin-top:8px" onclick="ui.renderGlobalSettings()">НАЗАД</button>`;
            window.Core.bindDataActions(document.querySelector('.gate-container'));
        } catch (error) { window.Core?.customAlert?.('PUBLIC ROUTES', error.message); }
    },
    createPublicRoute() { window.DeviceRoutes.issue({ type: 'public-contact', allowedAccounts: [] }).then(() => this.openPublicRoutes()).catch(error => window.Core?.customAlert?.('PUBLIC ROUTES', error.message)); },
    reissuePublicRoute() { window.DeviceRoutes.reissue().then(() => this.openPublicRoutes()).catch(error => window.Core?.customAlert?.('PUBLIC ROUTES', error.message)); },
    togglePublicRoute(id) { const route = window.DeviceRoutes.list().find(item => item.routeId === id); window.DeviceRoutes.activate(id, !route.active); this.openPublicRoutes(); },
    openQuickNames() { return this.renderGlobalQuickNames(); },
    quickNameEscape(value) {
        const text = String(value ?? '');
        return window.Core?.escapeHtml ? window.Core.escapeHtml(text) : text.replace(/[&<>'"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
    },
    async renderGlobalQuickNames() {
        const gateBox = document.querySelector('.gate-container');
        if (!gateBox) return;
        try {
            const registry = window.Core?.getQuickNameRegistry?.();
            if (!registry) throw new Error('СНАЧАЛА РАЗБЛОКИРУЙТЕ УСТРОЙСТВО');
            const entries = await registry.list();
            const rows = entries.length ? entries.map(entry => {
                return `<div style="padding:10px 0;border-bottom:1px solid #333;text-align:left;"><b style="color:#0f0;display:block;overflow-wrap:anywhere;">${this.quickNameEscape(entry.name)}</b><div style="font-size:.72rem;color:#ccc;overflow-wrap:anywhere;margin:4px 0 8px;">${this.quickNameEscape(entry.value)}</div><button class="gate-btn" type="button" style="width:auto;margin:0;padding:6px 9px;background:#400;color:#fff;border-color:#a44;" ${window.Core.dataActionAttributes("removeGlobalQuickName", [entry.id])}>УДАЛИТЬ</button></div>`;
            }).join('') : '<div style="padding:18px 0;color:#aaa;text-align:left;">СПИСОК ПУСТ. ДОБАВЬТЕ ИМЯ — ОНО СРАЗУ ПОЯВИТСЯ ЗДЕСЬ.</div>';
            gateBox.innerHTML = `<div id="global-quick-names-title" style="color:#0f0;font-size:.95rem;font-weight:bold;text-align:left;">БЫСТРЫЕ ИМЕНА</div><p style="color:#aaa;font-size:.72rem;line-height:1.45;margin:7px 0 10px;text-align:left;">СОХРАНЯЮТСЯ ЛОКАЛЬНО В ЭТОМ БРАУЗЕРЕ В ЗАШИФРОВАННОМ РЕЕСТРЕ. В АККАУНТ, СЕТЬ ИЛИ НА УЗЕЛ НЕ ОТПРАВЛЯЮТСЯ.</p><div aria-labelledby="global-quick-names-title" style="max-height:250px;overflow-y:auto;margin-bottom:12px;">${rows}</div><button id="global-add-quick-name-button" class="gate-btn" type="button" style="margin:0;" onclick="ui.addGlobalQuickName()">ДОБАВИТЬ БЫСТРОЕ ИМЯ</button><button class="gate-btn" type="button" style="margin-top:9px;background:transparent;color:#aaa;border-color:#555;" onclick="ui.renderGlobalSettings()">НАЗАД К НАСТРОЙКАМ</button>`;
            window.Core.bindDataActions(gateBox);
        } catch (error) { window.Core?.customAlert?.('БЫСТРЫЕ ИМЕНА', error.message); }
    },
    async addGlobalQuickName() {
        const name = window.prompt?.('Название быстрого имени');
        if (name === null || name === undefined) return;
        const value = window.prompt?.('Значение для «' + name + '»');
        if (value === null || value === undefined) return;
        try { await window.Core.getQuickNameRegistry().add({ name, value }); await this.renderGlobalQuickNames(); }
        catch (error) { window.Core?.customAlert?.('БЫСТРЫЕ ИМЕНА', error.message); }
    },
    async removeGlobalQuickName(id) {
        if (window.confirm && !window.confirm('Удалить это быстрое имя только с данного устройства?')) return;
        try { await window.Core.getQuickNameRegistry().remove(id); await this.renderGlobalQuickNames(); }
        catch (error) { window.Core?.customAlert?.('БЫСТРЫЕ ИМЕНА', error.message); }
    },
    renderGlobalNodes() {
        const gateBox = document.querySelector('.gate-container');
        const manager = window.NodeManager;
        if (!gateBox || !manager) return;
        const endpoints = (manager.endpoints || []).filter(endpoint => !manager.isExcludedNode?.(endpoint.url));
        const rows = endpoints.length ? endpoints.map(endpoint => {
            const selected = manager.active?.url === endpoint.url ? ' ОСНОВНОЙ' : '';
            return `<li style="padding:9px 0; border-bottom:1px solid #333; color:#ddd; word-break:break-word;">${this.quickNameEscape(endpoint.label)}${selected}<br><small>${this.quickNameEscape(endpoint.url)}</small><br><button class="gate-btn" type="button" style="margin-top:6px; padding:7px;" ${window.Core.dataActionAttributes("selectGlobalNode", [endpoint.url])}>СДЕЛАТЬ ОСНОВНЫМ</button> <button class="gate-btn" type="button" style="margin-top:6px; padding:7px; background:#400; color:#fff;" ${window.Core.dataActionAttributes("removeGlobalNode", [endpoint.url])}>УДАЛИТЬ</button></li>`;
        }).join('') : '<li style="padding:9px 0; color:#aaa;">УЗЛЫ НЕ ДОБАВЛЕНЫ</li>';
        gateBox.innerHTML = `
            <div id="global-nodes-title" style="color:#0f0; font-size:0.8rem; margin-bottom:10px; text-align:center;">NODES — УСТРОЙСТВО</div>
            <p style="color:#aaa; font-size:0.72rem; line-height:1.4; margin:0 0 12px; text-align:center;">СПИСОК СОХРАНЯЕТСЯ ТОЛЬКО НА ЭТОМ УСТРОЙСТВЕ.</p>
            <ul aria-labelledby="global-nodes-title" style="list-style:none; padding:0; margin:0 0 14px; max-height:250px; overflow-y:auto; text-align:left;">${rows}</ul>
            <button id="global-add-node-button" class="gate-btn" type="button" onclick="ui.addGlobalNode()">ДОБАВИТЬ УЗЕЛ</button>
            <button class="gate-btn" type="button" onclick="ui.renderGlobalSettings()">НАЗАД</button>
        `;
        window.Core.bindDataActions(gateBox);
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
        if (this._credentialPending) this.cancelCredentialOperation();
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
        if (this._credentialPending && c !== 'AC') this.cancelCredentialOperation();
        if (c === 'AC') {
            this.cancelCredentialOperation();
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

    cancelCredentialOperation() {
        this.unlockGeneration++;
        window.LocalCredentials?.cancel();
        this._credentialPending = false;
        this.pendingCurrentMasterSecret = null; this.pendingNextMasterSecret = null;
        this.pendingSetupMaster = null;
        this.pendingRepairHandle?.dispose(); this.pendingRepairHandle = null;
        this.pendingLegacyHandle?.dispose(); this.pendingLegacyHandle = null;
        if ([2, 3, 4, 5].includes(this.mode)) this.mode = 0;
    },
    credentialError(error) {
        if (error.committed && error.useNewMaster) return 'НОВЫЙ MASTER СОХРАНЁН. ОЧИСТКА НЕ ЗАВЕРШЕНА; ВОЙДИТЕ НОВЫМ КОДОМ';
        if (error.committed) return 'КОДЫ СОХРАНЕНЫ. ОЧИСТКА НЕ ЗАВЕРШЕНА; ПОВТОРИТЕ ВХОД';
        if (['UNLOCK_FAILED', 'WIPE_CODE_INVALID'].includes(error.code)) return 'НЕВЕРНЫЙ MASTER-КОД';
        if (['ROOT_MISSING', 'STORAGE_CORRUPT', 'LEGACY_MIGRATION_REQUIRED'].includes(error.code)) return 'ТРЕБУЕТСЯ ВОССТАНОВЛЕНИЕ. ДАННЫЕ НЕ ИЗМЕНЕНЫ';
        if (error.code === 'WIPE_PENDING') return 'ОЧИСТКА НЕ ЗАВЕРШЕНА — ВОССТАНОВЛЕНИЕ В НАСТРОЙКАХ';
        return 'ОШИБКА ХРАНИЛИЩА: ' + error.message;
    },
    async eval() {
        if (this.consumeLongPress('=')) return;
        const candidate = this.resolveExpression();
        if (candidate === null || !this.validSecret(candidate)) {
            if ([1, 2, 3, 4, 5].includes(this.mode)) { this.hist = 'КОД: МИНИМУМ 4 ЦИФРЫ'; this.update(); }
            return;
        }
        const generation = ++this.unlockGeneration, mode = this.mode;
        this._credentialRecoveryAvailable = false;
        this._credentialPending = true;
        const current = () => { if (generation !== this.unlockGeneration) throw Object.assign(new Error('Операция отменена'), { code: 'CREDENTIAL_CANCELLED' }); };
        this.hist = 'ПРОВЕРКА КОДА...'; this.update();
        try {
            const credentials = await sys.ensureCredentials(); current();
            if (mode === 1) {
                await credentials.beginSetup(candidate); current();
                this.pendingSetupMaster = candidate; this.curr = '0'; this.mode = 2; this.hist = 'УСТАНОВКА WIPE-КОДА'; this.update(); return;
            }
            if (mode === 2) {
                if (!this.pendingSetupMaster) throw Object.assign(new Error('Повторите master для завершения настройки'), { code: 'ROOT_MISSING' });
                await credentials.completeSetup(this.pendingSetupMaster, candidate); current();
                this.pendingSetupMaster = null; this.mode = 0; this.curr = '0'; this.hist = 'СИСТЕМА ГОТОВА'; this.update(); return;
            }
            if (mode === 3) {
                await credentials.verifyMaster(candidate); current();
                this.pendingCurrentMasterSecret = candidate; this.curr = '0'; this.mode = 4; this.hist = 'НОВЫЙ MASTER-КОД'; this.update(); return;
            }
            if (mode === 4) {
                this.pendingNextMasterSecret = candidate; this.curr = '0'; this.mode = 5; this.hist = 'НОВЫЙ WIPE-КОД'; this.update(); return;
            }
            if (mode === 5) {
                if (this.pendingLegacyHandle) await credentials.completeLegacyRecovery(this.pendingLegacyHandle, this.pendingNextMasterSecret, candidate);
                else if (this.pendingRepairHandle) await credentials.repairFromBiometric(this.pendingRepairHandle, this.pendingNextMasterSecret, candidate);
                else await credentials.change(this.pendingCurrentMasterSecret, this.pendingNextMasterSecret, candidate);
                this.pendingRepairHandle = null; this.pendingLegacyHandle = null; current();
                this.pendingCurrentMasterSecret = null; this.pendingNextMasterSecret = null;
                this.mode = 0; this.curr = '0'; this.hist = 'КОДЫ ОБНОВЛЕНЫ'; this.update(); return;
            }
            if (mode !== 0) return;
            this.hist = 'ЗАГРУЗКА ЯДРА...'; this.update();
            const loaded = await sys.loadAllLibs(); current();
            if (!loaded) throw Object.assign(new Error('Не удалось загрузить защищённые модули'), { code: 'CREDENTIAL_RUNTIME_UNSUPPORTED' });
            try {
                const state = await Core.unlockDevice(candidate, { isCurrent: () => generation === this.unlockGeneration }); current();
                if (state?.pendingSetup) { this.pendingSetupMaster = candidate; this.mode = 2; this.curr = '0'; this.hist = 'УСТАНОВКА WIPE-КОДА'; this.update(); return; }
                this.resetCalculator(); await this.show_gate(); current();
            } catch (error) {
                current();
                if (error.code !== 'UNLOCK_FAILED') throw error;
                const result = await credentials.wipe(candidate);
                if (result?.complete) window.location.replace('about:blank');
            }
        } catch (error) {
            if (error.wipeAccepted) { this.mode = 0; this.curr = '0'; this._credentialRecoveryAvailable = true; this.hist = 'ОЧИСТКА НЕ ЗАВЕРШЕНА: ' + error.message; this.update(); return; }
            if (generation !== this.unlockGeneration || ['CREDENTIAL_CANCELLED', 'DEVICE_LOCKED', 'AbortError'].includes(error.code || error.name)) return;
            if (mode === 5) { this.pendingCurrentMasterSecret = null; this.pendingNextMasterSecret = null; this.pendingRepairHandle?.dispose(); this.pendingRepairHandle = null; this.pendingLegacyHandle?.dispose(); this.pendingLegacyHandle = null; this.mode = 0; }
            this._credentialRecoveryAvailable = ['UNLOCK_FAILED', 'WIPE_CODE_INVALID', 'ROOT_MISSING', 'STORAGE_CORRUPT', 'LEGACY_MIGRATION_REQUIRED', 'WIPE_PENDING'].includes(error.code);
            this.hist = this.credentialError(error); this.update();
        } finally { if (generation === this.unlockGeneration) this._credentialPending = false; }
    },

    async openCredentialRecovery() {
        if (await sys.loadAllLibs()) Core.openCredentialRecovery();
    },
    update() {
        let recovery = document.getElementById('local-credential-recovery');
        if (this._credentialRecoveryAvailable) {
            if (!recovery) { recovery = document.createElement('button'); recovery.id = 'local-credential-recovery'; recovery.className = 'gate-btn'; recovery.type = 'button'; recovery.textContent = 'ВОССТАНОВЛЕНИЕ ДОСТУПА'; recovery.onclick = () => this.openCredentialRecovery(); document.getElementById('app-container')?.appendChild(recovery); }
        } else recovery?.remove();
        let cancel = document.getElementById('biometric-setup-cancel');
        if (this.mode === 6) {
            if (!this._biometricSetup) this._biometricSetup = { deviceState: typeof Core === 'undefined' ? null : Core.deviceState };
            const seconds = this.biometricHoldMs / 1000;
            this.hist = `УДЕРЖИВАЙТЕ ЦИФРУ ИЛИ + − × ÷ % , ${seconds} СЕК.`;
            if (!cancel) {
                cancel = document.createElement('button');
                cancel.id = 'biometric-setup-cancel';
                cancel.type = 'button';
                cancel.className = 'gate-btn';
                cancel.textContent = 'ОТМЕНА ПРИВЯЗКИ КНОПКИ';
                cancel.onclick = () => this.cancelBiometricTriggerSetup();
                document.getElementById('app-container')?.appendChild(cancel);
            }
        } else {
            this._biometricSetup = null;
            cancel?.remove();
        }
        const curEl = document.getElementById('current');
        const histEl = document.getElementById('history');
        if (curEl) curEl.innerText = this.curr;
        if (histEl) histEl.innerText = this.hist;
    }
};

ui.startLegacyRootRecovery = function(handle) {
    this.startMasterReconfiguration(); this.pendingLegacyHandle = handle;
    this.mode = 4; this.hist = 'НОВЫЙ MASTER-КОД'; this.update();
};

ui.startBiometricMasterRepair = function(handle) {
    this.startMasterReconfiguration();
    this.pendingRepairHandle = handle; this.mode = 4; this.hist = 'НОВЫЙ MASTER-КОД'; this.update();
};

ui.startMasterReconfiguration = function() {
    this.cancelCredentialOperation();
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

    async ensureCredentials() {
        if (!this._credentialTask) this._credentialTask = (async () => {
            const ver = window.DMASH_RELEASE?.id;
            if (!ver) throw new Error('Версия защищённых модулей неизвестна');
            await Promise.all(['vendor/argon2-bundled.min.js', 'vendor/nacl-fast.min.js', 'device_root.js', 'local_credentials.js'].map(name => this.loadScript(`js/${name}?v=${ver}`)));
            await this.loadScript(`js/local_credentials_bootstrap.js?v=${ver}`);
            if (!window.DeviceRoot?.prepareUnlock || !window.DmashLocalCredentials) throw new Error('Защищённые модули несовместимы');
            return window.DmashLocalCredentials.ensure();
        })().catch(error => { this._credentialTask = null; throw error; });
        return this._credentialTask;
    },
    async wipe(pin) {
        const credentials = await this.ensureCredentials();
        const result = await credentials.wipe(pin);
        if (result?.complete) window.location.replace('about:blank');
        return result;
    },

// В ui_logic.js
loadAllLibs() {
    // Re-entry and concurrent unlocks share the initialized WASM runtime.
    // Replacing KyberModule while its script is already loaded loses HEAPU8.
    if (!this._libsReadyTask) {
        this._libsReadyTask = this._loadAllLibs().then(ready => {
            if (!ready) this._libsReadyTask = null;
            return ready;
        });
    }
    return this._libsReadyTask;
},
async _loadAllLibs() {
    try {
        const ver = window.DMASH_RELEASE?.id || "ui-foundation-20260825.1";
        window.Module ||= { wasmBinaryFile: 'js/vendor/argon2.wasm' };

        window.KyberModule ||= {
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
        if (!window.KyberModule?.HEAPU8) throw new Error('Kyber WASM initialization timed out');
        // ПРИНУДИТЕЛЬНАЯ ПРОПИСКА QR
        if (typeof window.QRCode === 'undefined' && typeof qrcode !== 'undefined') {
            window.QRCode = qrcode;
        }
        await window.DmashRuntimeReadiness?.compose();
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
        this._scriptTasks ||= new Map();
        if (this._scriptTasks.has(src)) return this._scriptTasks.get(src);
        const task = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src; script.async = true;
            script.onload = resolve;
            script.onerror = () => reject(new Error('MODULE_LOAD_FAILED: ' + src.split('?')[0]));
            document.head.appendChild(script);
        });
        this._scriptTasks.set(src, task);
        return task.catch(error => { this._scriptTasks.delete(src); throw error; });
    },

    async init() {
        const v1 = document.getElementById('p1').value;
        const v2 = document.getElementById('p2').value;
        // Вызываем Core.boot (Gamma-1 Standard)
        if (!v1 || !v2 || typeof Core === 'undefined') return false;
        return await Core.boot(v1, v2, { register: Boolean(document.getElementById('save-in-registry')?.checked) });
    },

    // Реестр создаётся Core.boot после успешной разблокировки. Это действие
    // идемпотентно и не сохраняет пароль или ключи в localStorage.
    async loginAndSave() {
        if (this._loginPending) return;
        this._loginPending = true;
        const form = document.querySelector('.gate-container form');
        const submit = form?.querySelector('button[type="submit"]');
        const status = document.getElementById('gate-status-text');
        if (submit) submit.disabled = true;
        if (status) status.textContent = 'ВХОД…';
        try {
            const ok = await this.init();
            if (!ok) throw new Error('Проверьте идентификатор и ключ доступа.');
        } catch (error) {
            if (status) status.textContent = `ОШИБКА ВХОДА: ${error?.message || 'неизвестная ошибка'}`;
            if (submit) submit.disabled = false;
            console.error('D-MASH account login failed', error);
        } finally {
            this._loginPending = false;
            if (submit) submit.disabled = false;
        }
    },

};

ui.init();
window.DmashRuntimeReadiness?.flush();
