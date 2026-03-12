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

        // Запрос прав на уведомления
        if ("Notification" in window && Notification.permission === "default") {
            Notification.requestPermission();
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
    },

    /**
     * ПЕРЕХОД К ГЕЙТУ (Gamma-1 Ready)
     */
    async show_gate() {
        const container = document.getElementById('settings-layer');
        const gateBox = document.querySelector('.gate-container');
        const app = document.getElementById('app-container');
        
        if (gateBox) gateBox.innerHTML = '<div style="color:var(--main); text-align:center; font-family:monospace;">ПОДГОТОВКА ТЕРМИНАЛА...</div>';
        
        app.style.opacity = '0';
        
        setTimeout(async () => {
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
        }, 200);
    },

async renderAccountSelector(accs) {
        const gateBox = document.querySelector('.gate-container');
        if (!gateBox) return;

        // ФИКС: Берем только первые 64 символа (ServerID) для проверки на сервере!
        const hashes = await Promise.all(accs.map(a => sys.fastHash(a.pk.substring(0, 64))));

        let stats = [];
        try {
            const res = await fetch('../api/pidorskiy_api.php', {
                method: 'POST',
                headers: { 'X-DMASH-AGENT': 'V1Silent-Node', 'Content-Type': 'application/json' },
                body: JSON.stringify({ check_batch: true, hashes: hashes })
            });
            stats = await res.json();
        } catch (e) {}

        const listHtml = accs.map((a, idx) => {
            const h = hashes[idx];
            const info = (Array.isArray(stats) ? stats.find(s => s.r_hash === h) : null) || { msgs: 0, calls: 0 };
            
            let badges = "";
            if (parseInt(info.msgs) > 0) badges += `<span class="unread-badge">${info.msgs}</span>`;
            if (parseInt(info.calls) > 0) badges += `<span class="unread-badge" style="background:#ff9f0a; box-shadow:0 0 8px #ff9f0a;">📞</span>`;
            
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
                <form onsubmit="event.preventDefault(); sys.init();">
                    <input type="text" id="p1" class="gate-input" placeholder="ИДЕНТИФИКАТОР" value="${prefillId}" spellcheck="false" autocomplete="username">
                    <input type="password" id="p2" class="gate-input" placeholder="КЛЮЧ ДОСТУПА" autocomplete="current-password">
                    <button type="submit" class="gate-btn">ВОЙТИ В СИСТЕМУ</button>
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

        const inputHash = await sys.fastHash(this.curr);
        if (inputHash === localStorage.getItem('sys_m')) {
            this.cmd('AC');
            this.hist = "ЗАГРУЗКА ЯДРА...";
            this.update();
            if (await sys.loadAllLibs()) this.show_gate();
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
        const ver = "vQUANT-1.1";
        window.Module = { wasmBinaryFile: 'js/vendor/argon2.wasm' };

        window.KyberModule = {
            locateFile: (path) => path.endsWith('.wasm') ? 'js/vendor/kyber768.wasm' : path,
            // Ждем нашу инъекцию
            onRuntimeInitialized: () => { console.log("🔥 WASM READY"); }
        };

        await Promise.all([
            this.loadScript(`js/vendor/argon2-bundled.min.js?v=${ver}`),
            this.loadScript(`js/vendor/kyber768.js?v=${ver}`),
            this.loadScript(`js/storage.js?v=${ver}`),
            this.loadScript(`js/core_engine.js?v=${ver}`),
            this.loadScript(`js/vendor/nacl-fast.min.js`),
            this.loadScript(`js/vendor/html5-qrcode.min.js`),
            this.loadScript(`js/vendor/qrcode.min.js`),
            this.loadScript(`js/vendor/nacl-util.min.js`)
        ]);

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
            if (document.querySelector(`script[src^="${baseSrc}"]`)) return resolve();
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
        if (v1 && v2 && typeof Core !== 'undefined') Core.boot(v1, v2);
    }
};

ui.init();