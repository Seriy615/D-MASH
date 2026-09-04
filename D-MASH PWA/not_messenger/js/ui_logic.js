/**
 * D-MASH GAMMA-1 // UI & DECOY CONTROLLER // V101.0
 * Калькулятор, Умный Вход, Счетчики маляв и запуск Ядра.
 */
"use strict";

const ui = {
    curr: "0",
    hist: "",
    op: null,
    mode: 0, // 0: Калькулятор, 1: Master PIN, 2: Wipe PIN
    unlockGeneration: 0,

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
        if (window.NodeManager) {
            window.NodeManager.loadOriginList('nodes.json').catch(() => {});
        }
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
            
            let icons = a.bio ? ' 🧬' : ''; if (a.lazy) icons += ' ⚡';
            
            return `
                <button class="gate-btn" style="margin-bottom:10px; background:#111; color:#0f0; border:1px solid #333; display:flex; justify-content:space-between; align-items:center;" 
                    onclick="ui.selectAccountForLogin('${a.id}', ${!!a.bio}, ${!!a.lazy})">
                    <span style="display:flex; align-items:center;">${badges} ${a.id}</span>
                    <span style="font-size:0.8rem;">${icons}</span>
                </button>`;
        }).join('');

        gateBox.innerHTML = `
            <div id="gate-status-text" style="color:#0f0; font-size:0.7rem; margin-bottom:15px; text-align:center;">КТО ЗАХОДИТ?</div>
            <div class="acc-list-scroll" style="max-height:250px; overflow-y:auto; width:100%;">${listHtml}</div>
            <button class="gate-btn" onclick="ui.renderLoginForm()">+ НОВЫЙ ВХОД</button>
        `;
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

    async selectAccountForLogin(id, hasBio, hasLazy) {
        if (typeof Core === 'undefined') return this.renderLoginForm(id);
        if (hasLazy) { if (await Core.lazyLogin(id)) return; }
        if (hasBio) { if (await Core.biometricLogin(id)) return; }
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
        this.update();
    },

    /**
     * МАТЕМАТИКА КАЛЬКУЛЯТОРА
     */
    num(n) {
        if (this.curr.length > 10) return;
        if (this.curr === "0" && n !== ".") this.curr = n;
        else this.curr += n;
        this.update();
    },

    cmd(c) {
        if (c === 'AC') { 
            this.curr = "0"; 
            if (this.mode === 1) this.hist = "УСТАНОВКА MASTER-КОДА";
            else if (this.mode === 2) this.hist = "УСТАНОВКА WIPE-КОДА";
            else this.hist = "";
            this.op = null; 
        }
        else if (c === '±') this.curr = (parseFloat(this.curr) * -1).toString();
        else if (c === '%') this.curr = (parseFloat(this.curr) / 100).toString();
        else {
            if (this.mode !== 0) return; 
            this.op = c; this.hist = this.curr + " " + c; this.curr = "0";
        }
        this.update();
    },

    async eval() {
        if (this.mode === 1) {
            localStorage.setItem('sys_m', await sys.fastHash(this.curr));
            this.curr = "0"; this.mode = 2; this.hist = "УСТАНОВКА WIPE-КОДА";
            this.update(); return;
        }
        if (this.mode === 2) {
            localStorage.setItem('sys_w', await sys.fastHash(this.curr));
            localStorage.setItem('sys_configured', 'true');
            this.mode = 0; this.curr = "0"; this.hist = "СИСТЕМА ГОТОВА";
            this.update(); setTimeout(() => { this.cmd('AC'); }, 1000); return;
        }
        if (this.mode === 3) {
            if (await sys.fastHash(this.curr) !== localStorage.getItem('sys_m')) { this.curr = '0'; this.hist = 'НЕВЕРНЫЙ MASTER-КОД'; this.update(); return; }
            this.curr = '0'; this.mode = 4; this.hist = 'НОВЫЙ MASTER-КОД'; this.update(); return;
        }
        if (this.mode === 4) {
            if (!/^\d{4,}$/.test(this.curr)) { this.hist = 'MASTER-КОД: МИНИМУМ 4 ЦИФРЫ'; this.update(); return; }
            this.pendingMasterHash = await sys.fastHash(this.curr); this.curr = '0'; this.mode = 5; this.hist = 'НОВЫЙ WIPE-КОД'; this.update(); return;
        }
        if (this.mode === 5) {
            if (!/^\d{4,}$/.test(this.curr)) { this.hist = 'WIPE-КОД: МИНИМУМ 4 ЦИФРЫ'; this.update(); return; }
            localStorage.setItem('sys_m', this.pendingMasterHash); localStorage.setItem('sys_w', await sys.fastHash(this.curr));
            this.pendingMasterHash = null; this.mode = 0; this.curr = '0'; this.hist = 'КОДЫ ОБНОВЛЕНЫ'; this.update(); setTimeout(() => this.cmd('AC'), 1000); return;
        }

        const inputHash = await sys.fastHash(this.curr);
        if (inputHash === localStorage.getItem('sys_m')) {
            const devicePin = this.curr;
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
                    this.hist = "ОШИБКА УСТРОЙСТВА: " + error.message;
                    this.update();
                }
            }
            else { this.hist = "ОШИБКА СЕТИ"; this.update(); }
            return;
        }
        if (inputHash === localStorage.getItem('sys_w')) { sys.wipe(); return; }

        if (!this.op) return;
        let res = 0, a = parseFloat(this.hist), b = parseFloat(this.curr);
        if (this.op === '+') res = a + b;
        if (this.op === '-') res = a - b;
        if (this.op === '*') res = a * b;
        if (this.op === '/') res = a / b;
        this.hist = ""; this.op = null; this.curr = res.toString().slice(0, 12);
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
