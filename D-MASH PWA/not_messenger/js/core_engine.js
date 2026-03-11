// D-MASH SILENT // CORE ENGINE V25.0 // SMOOTH UI, PAGINATION & ACCOUNT MGR
"use strict";

const iceConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' }, // Гугл для простых проверок
        { 
            urls: 'turn:85.198.64.183:3478', 
            username: 'dmash_turn', 
            credential: '&fV+CJ2_0l7Ji^EzWPf^#nRvbkIqe6' // Тот пароль, что вписал в конфиг
        }
    ],
    iceCandidatePoolSize: 10
};


const Core = {
    activePeerId: null,
    activeIdentity: null,
    scanner: null,
    blobURLs: [],
    chatOffset: 0,
    chatLimit: 50,
    isLoadingHistory: false,
    mediaRecorder: null,
    audioChunks: [],
    isRecording: false,
    activeAudio: null,
    isDrawing: false,
    
    // ИНИЦИАЛИЗИРУЕМ ОБЪЕКТЫ СРАЗУ, ЧТОБ НЕ БЫЛО undefined
    gammaKeys: { master: null, sign: null, box: null },
    keys: { sign: null, box: null, pub_hex: null },
    isSyncing: false, chatOffset: 0, chatLimit: 50, isLoadingHistory: false,
    hex_lut: Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0')),
    
    peerConnection: null,
    callState: 'idle', // idle, calling, receiving, connected
    iceQueue: [], // ОЧЕРЕДЬ ДЛЯ ТЕХ, КТО ПРИШЕЛ РАНЬШЕ СРОКА
    activeCallId: null,
    callTimer: null,
    callPeerId: null, // ЗАМОК НА СОБЕСЕДНИКА
    callSeconds: 0,
    localStream: null,
    audioCtx: null, // Для генерации сигналов
    currentCamera: 'user',
    isSpeakerOn: false,
    screenStream: null,
    
/**
     * ВХОД В СИСТЕМУ GAMMA-1 (Полная версия)
     */
    async boot(identity, passphrase) {
        const statusEl = document.getElementById('gate-status-text');
        try {
            if (statusEl) statusEl.innerText = "КУЗНИЦА КЛЮЧЕЙ (1024 bit)...";
            
            // 1. Выжимаем 128 байт энтропии через Argon2id
            const result = await window.argon2.hash({
                pass: passphrase,
                salt: identity + "D_MASH_GAMMA_V1_STABLE",
                time: 3, mem: 65536, hashLen: 128, type: window.argon2.argon2id
            });
            const fullHash = result.hash;

            // 2. Распил ключей по мастям
            this.gammaKeys.master = fullHash.slice(0, 32);  // Сейф БД
            this.blindSalt = fullHash.slice(32, 64);        // RAM-only соль
            const seedSign = fullHash.slice(64, 96);        // Для подписи (Ed)
            const seedBox = fullHash.slice(96, 128);        // Для шифра (Curve)

            // 3. Генерация крипто-пар
            this.keys.sign = window.nacl.sign.keyPair.fromSeed(seedSign);
            this.keys.box = window.nacl.box.keyPair.fromSecretKey(seedBox);
            
            // Твой публичный ID для кентов (QR): Ed_Pub (64) + Curve_Pub (64)
            const edPubHex = this.bytesToHex(this.keys.sign.publicKey);
            const curvePubHex = this.bytesToHex(this.keys.box.publicKey);
            this.keys.pub_hex = edPubHex + curvePubHex; 
            
            // Твоя ксива для сервера (только Ed_Pub)
            this.keys.server_id = edPubHex;
            
            this.activeIdentity = identity;

            this.shmon("INFO", `Gamma-1 готова. ServerID: ${this.keys.server_id.substring(0,8)}`);

            // 4. Инициализация хранилища и реестра
            await Storage.initGamma(this.gammaKeys.master);
            await Storage.registerAccount(identity, this.keys.pub_hex);
            
            if (navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({ 
                    type: 'REGISTER_ACCOUNT', 
                    id: identity, 
                    pk: this.keys.pub_hex 
                });
            }
            
            this.launchWorkspace();
        } catch (e) { 
            console.error(e);
            if (statusEl) statusEl.innerText = "ОШИБКА ЯДРА: " + e.message; 
        }
    },

async sendEmergencyHandshake(pid) {
        // Защита от спама хендшейками
        if (this._lastHandshakeTime && Date.now() - this._lastHandshakeTime < 30000) return;
        this._lastHandshakeTime = Date.now();

        this.shmon("WARN", `Инициирую экстренную синхронизацию с ${pid.substring(0,8)}`);
        
        const aliasL1 = await Storage.getAlias(pid, "L1");
        let peerInfo = await Storage.getBox('blind_peers', aliasL1);
        if (!peerInfo) return;

        // Ставим метку тревоги
        peerInfo.securityAlert = true;
        await Storage.putBox('blind_peers', { alias: aliasL1, data: peerInfo });
        if (this.activePeerId === pid) document.getElementById('security-alert').style.display = 'block';

        const originalActive = this.activePeerId;
        this.activePeerId = pid;
        
        // ШЛЕМ С ФЛАГОМ ПРИНУДИТЕЛЬНОГО ХЕНДШЕЙКА
        await this.sendMessage({ 
            type: "emergency_sync", 
            content: "🔄 СИСТЕМА: Ключи связи обновлены. Безопасность восстановлена." 
        }, true);

        this.activePeerId = originalActive;
        await this.renderPeers();
    },
    
async encrypt(data, pid, forceHandshake = false) {
        this.shmon("INFO", `Шифрую для ${pid.substring(0,8)} ${forceHandshake ? '[FORCE]' : ''}`);
        const aliasL1 = await Storage.getAlias(pid, "L1");
        let secrets = await Storage.getBox('blind_secrets', aliasL1);
        
        if (!secrets || !secrets.staticShared || forceHandshake) {
            const peerInfo = await Storage.getBox('blind_peers', aliasL1);
            
            // ЕСЛИ НЕТ КЛЮЧА КЕНТА — ШЛЕМ SOS ПАКЕТ (ТИП 0x02)
            if (!peerInfo || !peerInfo.curvePub) {
                this.shmon("WARN", "Curve-ключ кента утерян. Генерирую SOS-пакет (0x02)...");
                const sos = new Uint8Array(33);
                sos[0] = 0x02; // Магический байт SOS
                sos.set(this.keys.box.publicKey, 1); // Твой новый ключ
                return this.bytesToHex(sos); // На выход чистый HEX
            }

            // Обычный SealedBox (0x01)
            const shared = window.nacl.box.before(this.hexToBytes(peerInfo.curvePub), this.keys.box.secretKey);
            const newPSK = this.bytesToHex(window.nacl.randomBytes(32));
            const newShift = Math.floor(Math.random() * 1000000);
            secrets = { staticShared: this.bytesToHex(shared), psk: newPSK, epochShift: newShift, msgCount: 0 };
            await Storage.putBox('blind_secrets', { alias: aliasL1, data: secrets });
            
            const eph = window.nacl.box.keyPair();
            const nonce = window.nacl.randomBytes(24);
            const helloPacket = { myCurvePub: this.bytesToHex(this.keys.box.publicKey), psk: secrets.psk, shift: secrets.epochShift, content: data };
            const msgUint8 = new TextEncoder().encode(JSON.stringify(helloPacket));
            const encrypted = window.nacl.box(msgUint8, nonce, this.hexToBytes(peerInfo.curvePub), eph.secretKey);
            
            const res = new Uint8Array(1 + 24 + 32 + encrypted.length);
            res[0] = 0x01; res.set(nonce, 1); res.set(eph.publicKey, 25); res.set(encrypted, 57);
            return this.bytesToHex(res); 
        }

        // Обычный T-Ratchet (0x00)
        const epochID = Math.floor(Date.now() / 1000 / 180) + (secrets.epochShift || 0);
        const ikm = await this.fastHash(this.hexToBytes(secrets.staticShared + secrets.psk));
        const messageKey = this.hexToBytes(await this.fastHash(ikm + epochID.toString())).slice(0, 32);
        const nonce = window.nacl.randomBytes(24);
        const encrypted = window.nacl.secretbox(new TextEncoder().encode(typeof data === 'object' ? JSON.stringify(data) : data), nonce, messageKey);
        const res = new Uint8Array(1 + 24 + encrypted.length);
        res[0] = 0x00; res.set(nonce, 1); res.set(encrypted, 25);
        return this.bytesToHex(res);
    },
    
async decrypt(hb, pid) {
        this.shmon("INFO", `Вскрываю пакет от ${pid.substring(0,8)}`);
        try {
            const raw = this.hexToBytes(hb);
            const type = raw[0];
            const aliasL1 = await Storage.getAlias(pid, "L1");

            // --- ТИП 0x02: SOS-СИГНАЛ ---
            if (type === 0x02) {
                const hisNewCurvePub = this.bytesToHex(raw.slice(1, 33));
                this.shmon("WARN", `Принят SOS от ${pid.substring(0,8)}. Он обнулился.`);
                
                let peerInfo = await Storage.getBox('blind_peers', aliasL1) || { id: pid, name: `New-${pid.substring(0,4)}` };
                peerInfo.curvePub = hisNewCurvePub;
                peerInfo.securityAlert = true; 
                await Storage.putBox('blind_peers', { alias: aliasL1, data: peerInfo });

                if (this.activePeerId === pid) document.getElementById('security-alert').style.display = 'block';

                // Шлем ему в ответ SealedBox (0x01)
                await this.sendEmergencyHandshake(pid);
                return "🔄 СИСТЕМА: Собеседник сбросил ключи. Связь восстановлена.";
            }

            // --- ТИП 0x01: SealedBox ---
            if (type === 0x01) {
                const nonce = raw.slice(1, 25);
                const ephPub = raw.slice(25, 57);
                const ciphertext = raw.slice(57);
                const opened = window.nacl.box.open(ciphertext, nonce, ephPub, this.keys.box.secretKey);
                if (opened) {
                    const hello = JSON.parse(new TextDecoder().decode(opened));
                    const oldSecrets = await Storage.getBox('blind_secrets', aliasL1);
                    let peerInfo = await Storage.getBox('blind_peers', aliasL1) || { id: pid, name: `New-${pid.substring(0,4)}` };
                    
                    if (oldSecrets) peerInfo.securityAlert = true;
                    peerInfo.curvePub = hello.myCurvePub;
                    await Storage.putBox('blind_peers', { alias: aliasL1, data: peerInfo });
                    if (this.activePeerId === pid && peerInfo.securityAlert) document.getElementById('security-alert').style.display = 'block';

                    const shared = window.nacl.box.before(this.hexToBytes(hello.myCurvePub), this.keys.box.secretKey);
                    await Storage.putBox('blind_secrets', { 
                        alias: aliasL1, 
                        data: { staticShared: this.bytesToHex(shared), psk: hello.psk, epochShift: hello.shift, msgCount: 0 } 
                    });
                    return hello.content;
                }
            }

            // --- ТИП 0x00: T-Ratchet ---
            if (type === 0x00) {
                let secrets = await Storage.getBox('blind_secrets', aliasL1);
                let decrypted = null;
                if (secrets && secrets.staticShared) {
                    const ikm = await this.fastHash(this.hexToBytes(secrets.staticShared + secrets.psk));
                    const currentE = Math.floor(Date.now() / 1000 / 180) + (secrets.epochShift || 0);
                    for (let e of [currentE, currentE - 1, currentE + 1]) {
                        const messageKey = this.hexToBytes(await this.fastHash(ikm + e.toString())).slice(0, 32);
                        const res = window.nacl.secretbox.open(raw.slice(25), raw.slice(1, 25), messageKey);
                        if (res) { decrypted = new TextDecoder().decode(res); break; }
                    }
                }
                if (!decrypted) {
                    this.shmon("ERR", "Нечитаемый T-Ratchet. Шлю SOS...");
                    await this.sendEmergencyHandshake(pid);
                    return null; 
                }
                return decrypted;
            }
            return null;
        } catch (e) { return null; }
    },
    
    
    
/**
     * СИНХРОНИЗАЦИЯ GAMMA-1 (V108.0 - TOTAL CONTROL)
     * Разводит потоки: Системные пакеты, Звонки и Малявы.
     */
async syncNetwork() {
        if (this.isSyncing) return; 
        this.isSyncing = true;
        try {
            const myServerId = this.keys.server_id;
            const h = await this.fastHash(myServerId);
            const ts = Math.floor(Date.now() / 1000).toString();
            const mts = new Uint8Array(this.hexToBytes(myServerId).length + new TextEncoder().encode(ts).length);
            mts.set(this.hexToBytes(myServerId));
            mts.set(new TextEncoder().encode(ts), this.hexToBytes(myServerId).length);
            const sig = window.nacl.sign.detached(mts, this.keys.sign.secretKey);
            
            const rnd = Math.random().toString(36).substring(7);
            const res = await fetch(`../api/pidorskiy_api.php?h=${h}&pub=${myServerId}&ts=${ts}&sig=${this.bytesToHex(sig)}&_=${rnd}`, { 
                headers: { 'X-DMASH-AGENT': 'V1Silent-Node' }, cache: 'no-store'
            });

            const data = await res.json();
            if (data && data.length > 0) {
                let needRefresh = false;
                for (let env of data) {
                    const sid = env.s_pub;
                    const aliasL1 = await Storage.getAlias(sid, "L1");
                    if (!(await Storage.getBox('blind_peers', aliasL1))) {
                        await Storage.savePeerGamma(sid, `New-${sid.substring(0,4)}`);
                        needRefresh = true;
                    }

                    const dec = await this.decrypt(env.blob, sid);
                    if (dec) {
                        let msgData;
                        // ФИКС ЗВОНКОВ: Пробуем парсить JSON
                        try { msgData = JSON.parse(dec); } catch(e) { msgData = dec; }

                        if (typeof msgData === 'object' && msgData.type?.startsWith('voip_')) {
                            this.shmon("INFO", "Принят сигнал звонка", msgData.type);
                            this.handleVoipSignal(msgData, sid);
                        } else {
                            const isCurrent = (this.activePeerId === sid);
                            await Storage.saveMessageGamma(sid, dec, true, isCurrent);
                            if (isCurrent) {
                                document.getElementById('log').insertAdjacentHTML('beforeend', this.buildMsgHtml({ text: dec, inbound: true }, Date.now()));
                                document.getElementById('log').scrollTop = document.getElementById('log').scrollHeight;
                            } else { needRefresh = true; }
                        }
                    }
                }
                if (needRefresh) await this.renderPeers();
            }
        } catch (e) { this.shmon("WARN", "Sync failed"); }
        this.isSyncing = false;
    },
    
/**
     * ПЛАВНАЯ ЗАГРУЗКА ЧАТА (FIX: loadMessagesGamma)
     */
    loadChat: async function(prepend = false) {
        if (!Core.activePeerId || Core.isLoadingHistory) return;
        if (prepend) Core.isLoadingHistory = true;
        else { Core.chatOffset = 0; Core.isDrawing = true; }

        const log = document.getElementById('log');
        const oldH = log.scrollHeight;

        if (!prepend) {
            log.innerHTML = '<div style="text-align:center; color:#444; margin-top:50px;">РАСШИФРОВКА...</div>';
            if (Core.blobURLs) Core.blobURLs.forEach(u => URL.revokeObjectURL(u));
            Core.blobURLs = [];
        }

        // ВЫЗОВ НОВОЙ ФУНКЦИИ ИЗ STORAGE
        const rawBatch = await Storage.loadMessagesGamma(Core.activePeerId, Core.chatLimit, Core.chatOffset);
        
        if (rawBatch.length === 0) {
            if (!prepend) log.innerHTML = '<div style="text-align:center; color:#333; margin-top:50px;">НЕТ СООБЩЕНИЙ</div>';
            Core.isLoadingHistory = false; Core.isDrawing = false;
            return;
        }

        let html = "";
        for (let m of rawBatch) {
            // В Gamma малява уже расшифрована при выходе из Storage.getBox
            html += Core.buildMsgHtml(m, m.ts);
        }

        if (prepend) {
            log.insertAdjacentHTML('afterbegin', html);
            log.scrollTop = log.scrollHeight - oldH;
        } else {
            log.innerHTML = html;
            log.scrollTop = log.scrollHeight;
        }

        Core.chatOffset += rawBatch.length;
        Core.isLoadingHistory = false; Core.isDrawing = false;
    },

/**
     * ОТПРАВКА (С флагом тишины для ТГ)
     */
async sendMessage(c = null, forceHandshake = false) {
        if (this.isRecordingCircle && !c) { this.cancelRecording = false; this.stopCircleUI(); return; }
        let p = c; 
        const inp = document.getElementById('msgInput');
        if (!p) { p = inp.value.trim(); if (!p) return; }
        if (!this.activePeerId) return;

        const isVoip = typeof p === 'object' && p.type?.startsWith('voip_');
        const isSilent = isVoip && (p.type === 'voip_ice' || p.type === 'voip_answer' || p.type === 'voip_hangup');

        try {
            const dataToEncrypt = (typeof p === 'object') ? JSON.stringify(p) : p;
            const blob = await this.encrypt(dataToEncrypt, this.activePeerId, forceHandshake);
            if (!blob) return;

            const sig = window.nacl.sign.detached(this.hexToBytes(blob), this.keys.sign.secretKey);
            
            await fetch('../api/pidorskiy_api.php', {
                method: 'POST', 
                headers: { 'X-DMASH-AGENT': 'V1Silent-Node', 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    r_hash: await this.fastHash(this.activePeerId),
                    s_pub: this.keys.server_id,
                    sig: this.bytesToHex(sig),
                    blob: blob,
                    is_voip: isVoip,
                    silent: isSilent 
                })
            });

            if (!isVoip) {
                // Получаем ID (seqNum) сохраненной малявы
                const seqId = await Storage.saveMessageGamma(this.activePeerId, p, false, true);
                
                const log = document.getElementById('log');
                if (log.innerHTML.includes("НЕТ СООБЩЕНИЙ")) log.innerHTML = "";
                
                // ФИКС: Передаем seqId в buildMsgHtml
                log.insertAdjacentHTML('beforeend', this.buildMsgHtml({ text: p, inbound: false }, Date.now(), seqId));
                log.scrollTop = log.scrollHeight;
                if (inp) { inp.value = ""; inp.style.height = '45px'; }
            }
        } catch (e) { this.shmon("ERR", "Send fail", e); }
    },



async selectPeer(id) {
        this.shmon("INFO", `Открываю хату: ${id.substring(0,8)}`);
        try {
            this.activePeerId = id;
            const aliasL1 = await Storage.getAlias(id, "L1");
            const peer = await Storage.getBox('blind_peers', aliasL1);

            // ФИКС 1: Гасим маяк непрочитанных
            if (peer && peer.unread) {
                peer.unread = false;
                await Storage.putBox('blind_peers', { alias: aliasL1, data: peer });
            }

            // ФИКС БАННЕРА
            const alertEl = document.getElementById('security-alert');
            if (alertEl) alertEl.style.display = (peer && peer.securityAlert) ? 'block' : 'none';

            // ФИКС 6: Возвращаем копирование полного ID (Ed + Curve)
            const fullIdToCopy = peer ? (peer.id + peer.curvePub) : id;
            document.getElementById('chat-header').innerHTML = `
                <button id="back-btn" class="action-btn" onclick="Core.closeChat()">←</button>
                <div style="flex-grow:1; margin-left:10px; cursor:pointer;" onclick="Core.copyPeerId('${fullIdToCopy}')">
                    <b id="chat-title">${peer ? peer.name.toUpperCase() : id.substring(0,8)}</b><br>
                    <small style="font-size:0.6rem; color:#555;">ID: ${id.substring(0,8)}... (КОПИРОВАТЬ)</small>
                </div>
                <div style="display:flex; gap:10px;">
                    <button class="action-btn" id="voip-btn" onclick="Core.initVoip()">📞</button>
                </div>
            `;
            
            document.getElementById('input-area').style.display = 'flex';
            if (document.getElementById('main-grid')) document.getElementById('main-grid').classList.add('chat-active');
            
            const log = document.getElementById('log');
            log.innerHTML = "";
            await this.renderPeers();
            
            const msgs = await Storage.loadMessagesGamma(id, 50, 0);
            if (msgs.length > 0) {
                msgs.forEach(m => {
    if (m && m.text) log.insertAdjacentHTML('beforeend', this.buildMsgHtml(m, m.ts, m.id)); // <-- добавил m.id
});
            } else {
                log.innerHTML = '<div style="text-align:center; color:#333; margin-top:50px;">НЕТ СООБЩЕНИЙ</div>';
            }
            setTimeout(() => { log.scrollTop = log.scrollHeight; }, 100);
            if (window.history.state?.view !== 'chat') window.history.pushState({ view: 'chat' }, "");

        } catch (e) { this.shmon("ERR", "Сбой открытия чата", e); }
    },

    deriveRootKey: (id, pwd) => new Promise((res, rej) => {
        if (typeof window.argon2 === 'undefined') return rej(new Error("Argon2 missing"));
        window.argon2.hash({
            pass: `${id}::[SILENT_v11]_${pwd}`, salt: "D_MASH_SALT_STABLE_V11",
            time: 3, mem: 65536, hashLen: 64, parallelism: 2, type: window.argon2.argon2id
        }).then(r => res(r.hashHex)).catch(e => rej(e));
    }),
initHandshake: async function() {
        const newShift = Math.floor(Math.random() * 1000000);
        const newPSK = this.bytesToHex(window.nacl.randomBytes(32));
        
        // Шлем спец-пакет кенту
        await this.sendMessage({
            type: "voip_handshake",
            shift: newShift,
            psk: newPSK
        });
        
        // Сохраняем у себя в L2
        const aliasL1 = await Storage.getAlias(this.activePeerId, "L1");
        const secrets = await Storage.getBox('blind_secrets', aliasL1);
        secrets.epochShift = newShift;
        secrets.psk = newPSK;
        await Storage.putBox('blind_secrets', { alias: aliasL1, data: secrets });
        
        this.customAlert("СИСТЕМА", "Запрос на синхронизацию отправлен.");
    },
/**
     * ЗАПУСК РАБОЧЕЙ ХАТЫ (V91 - Fix)
     */
    launchWorkspace: async function() {
        // 1. Прячем гейт и калькулятор
        document.getElementById('settings-layer').style.display = 'none';
        const calcView = document.getElementById('calc-view');
        if (calcView) calcView.style.display = 'none';

        // 2. Готовим воркспейс
        const ws = document.getElementById('workspace');
        ws.style.display = 'flex'; // Включаем Flex, чтоб растянулся
        
        // 3. Рисуем внутрянку
        ws.innerHTML = `
            <div class="terminal-grid" id="main-grid" style="width:100%; height:100%; display:flex;">
                <div class="sidebar">
                    <div class="side-header">D-MASH PWA Beta 3</div>
                    <div class="my-id-card" onclick="Core.showMyQR()">
                        <div style="color:#888; font-size:0.6rem; margin-bottom:4px;">МОЙ ID:</div>
                        <b style="color:#fff; font-size:0.75rem;">${Core.keys.pub_hex.substring(0, 24)}...</b>
                    </div>
                    <div class="nav-tools">
                        <button onclick="Core.openScanner()">[ QR ]</button>
                        <button onclick="Core.addPeerPrompt()">[ + ]</button>
                        <button onclick="Core.openSettings()">[ НАСТРОЙКИ ]</button>
                    </div>
                    <div id="contact-list" class="peer-list"></div>
                    <button class="exit-btn" onclick="Core.terminateSession()">[ ВЫХОД ]</button>
                </div>
                <div class="chat-main">
                    <div id="chat-header">
                        <button id="back-btn" class="action-btn" onclick="Core.closeChat()">←</button>
                        <b id="chat-title">ВЫБЕРИТЕ ЦЕЛЬ</b>
                        <div style="display:flex; gap:10px;">
                            <button class="action-btn" id="voip-btn" onclick="Core.initVoip()" style="display:none">📞</button>
                            <button class="edit-btn" onclick="Core.renameCurrent()">✎</button>
                        </div>
                    </div>
                    <div id="security-alert" style="display:none; background:#ff003c; color:#fff; padding:15px; text-align:center; font-weight:bold; font-size:0.9rem; border-bottom:2px solid #000;">
    ⚠️ ВНИМАНИЕ: КЛЮЧИ СВЯЗИ ОБНУЛЕНЫ!<br>
    <small style="font-weight:normal; opacity:0.8;">Собеседник сбросил базу или вы зашли с нового устройства. Убедитесь, что это ваш кент.</small>
<!-- В index.html внутри баннера -->
<button onclick="Core.dismissAlert()" style="background:#fff; color:#ff003c; border:none; margin-top:10px; padding:5px 10px; font-weight:bold; cursor:pointer;">Я ПРОВЕРИЛ КЕНТА</button></div>
                    <div id="log" class="chat-log"></div>
                    
                    <!-- ПАНЕЛЬ ВВОДА -->
                    <div id="input-area" class="chat-input-area" style="display:none">
                        <button class="action-btn" onclick="Core.uiAttach()">📎</button>
                        <textarea id="msgInput" placeholder="Сообщение..." rows="1" spellcheck="false"></textarea>
                        <button class="action-btn" id="circle-btn" onclick="Core.uiCircle()">⭕</button>
                        <button class="action-btn" id="voice-btn" onclick="Core.uiVoice()">🎤</button>
                        <button class="action-btn send-btn" onmousedown="event.preventDefault()" onclick="Core.sendMessage()">SEND</button>
                    </div>
                </div>
            </div>`;

        // 4. Вешаем события (как и раньше)
        const chatLog = document.getElementById('log');
        chatLog.addEventListener('scroll', () => {
            if (chatLog.scrollTop < 50 && !Core.isLoadingHistory && Core.chatOffset >= Core.chatLimit) {
                Core.loadChat(true); 
            }
        });

        navigator.serviceWorker.addEventListener('message', (event) => {
            if (event.data.type === 'MAIL_FOUND') {
                Core.fastHash(Core.keys.pub_hex).then(myHash => {
                    if (event.data.hashes.includes(myHash)) Core.syncNetwork();
                });
            }
        });

        const msgInp = document.getElementById('msgInput');
        msgInp.addEventListener('keydown', (e) => {
            if(e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); Core.sendMessage(); }
        });
        msgInp.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });

        const fileInp = document.getElementById('file-input');
        if (fileInp) fileInp.onchange = (e) => Core.handleFileSelect(e);

        // 5. Запускаем процессы
        await Core.renderPeers();
        Core.syncNetwork(); 
        if (Core.syncInterval) clearInterval(Core.syncInterval);
        Core.syncInterval = setInterval(() => Core.syncNetwork(), 7000); 
    },
async dismissAlert() {
        if (!this.activePeerId) return;
        const aliasL1 = await Storage.getAlias(this.activePeerId, "L1");
        let peer = await Storage.getBox('blind_peers', aliasL1);
        if (peer) {
            peer.securityAlert = false;
            await Storage.putBox('blind_peers', { alias: aliasL1, data: peer });
            document.getElementById('security-alert').style.display = 'none';
            this.shmon("INFO", "Тревога снята юзером.");
        }
    },

/**
     * ЯДЕРНАЯ ЗАЧИСТКА (TERMINATE SESSION)
     * Выжигает RAM-соль, сносит ключи и уходит в несознанку.
     */
    terminateSession: function() {
        console.log("[!!!] ШУХЕР! ГАСИМ ПРИБОРЫ...");

        // 1. Выжигаем SecretSalt (забиваем нулями Uint8Array)
        if (this.blindSalt) {
            this.blindSalt.fill(0);
            this.blindSalt = null;
        }

        // 2. Сносим ключи и ксивы
        this.gammaKeys = null;
        this.keys = { master: null, alias: null, sign: null, box: null, pub_hex: null };
        this.activeIdentity = null;
        this.activePeerId = null;

        // 3. Чистим сессионный мусор
        sessionStorage.clear();

        // 4. Уходим в глухую несознанку (релоад на чистый калькулятор)
        // replace юзаем, чтоб нельзя было кнопкой "Назад" вернуться
        window.location.replace(window.location.origin + window.location.pathname);
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
    /**
     * ПАНЕЛЬ НАСТРОЕК И АККАУНТОВ
     */
        openSettings: function() {
        const flipOff = localStorage.getItem('cfg_flip_off') === 'true';
        const hideList = localStorage.getItem('cfg_hide_list') === 'true';
        const h = `
            <div style="display:flex; flex-direction:column; gap:10px;">
                <button class="sys-modal-btn" onclick="Core.setupTelegram()">✈️ ПРИВЯЗАТЬ ТЕЛЕГРАМ-МАЯК</button>
                <button class="sys-modal-btn" onclick="Core.toggleFlipper()">ФЛИП-ЛОК: ${flipOff ? 'ВЫКЛ' : 'ВКЛ'}</button>
                <button class="sys-modal-btn" onclick="Core.toggleAccountList()">СПИСОК АККАУНТОВ: ${hideList ? 'СКРЫТ' : 'ВИДЕН'}</button>
                <button class="sys-modal-btn" onclick="Core.setupBiometrics()">🧬 ПРИВЯЗАТЬ ОТПЕЧАТОК/FACE</button>
                <button class="sys-modal-btn" onclick="Core.setupLazyLogin()">💤 ВКЛЮЧИТЬ БЕСПАРОЛЬНЫЙ ВХОД</button>
                <button class="sys-modal-btn primary" onclick="Core.openAccountManager()">👥 РЕЕСТР УСТРОЙСТВА</button>
                <button class="sys-modal-btn" onclick="Core.changePinFlow('M')">СМЕНИТЬ MASTER-КОД</button>
                <button class="sys-modal-btn danger" onclick="sys.wipe()">ПОЛНАЯ ОЧИСТКА</button>
                <button class="sys-modal-btn primary" onclick="Core.closeModal()">ЗАКРЫТЬ</button>
            </div>`;
        Core.openModal("НАСТРОЙКИ", h);
    },
    toggleAccountList: function() {
        const cur = localStorage.getItem('cfg_hide_list') === 'true';
        localStorage.setItem('cfg_hide_list', !cur);
        Core.openSettings();
    },
                // И сам метод:
async setupTelegram() {
        // Привязываемся строго к ServerID (Ed25519), по которому сервер ищет малявы
        const h = await this.fastHash(this.keys.server_id);
        const botUrl = `https://t.me/D_mash_notice_bot?start=${h}`;
        
        const h_html = `
            <div style="margin-bottom:20px; font-size:0.9rem; color:#ccc;">
                Жми кнопку и в Телеге нажми <b>"СТАРТ"</b>.<br>
                <small style="color:#555;">Hash: ${h.substring(0,16)}...</small>
            </div>
            <a href="${botUrl}" target="_blank" class="sys-modal-btn primary" style="text-decoration:none; display:block; text-align:center;">ОТКРЫТЬ БОТА</a>
            <button class="sys-modal-btn" onclick="Core.closeModal()" style="margin-top:10px;">ГОТОВО</button>
        `;
        this.openModal("TELEGRAM МАЯК", h_html);
    },
    /**
     * ПРИВЯЗКА К ЖЕЛЕЗУ (PRF Extension)
     */
    setupBiometrics: async function() {
        if (!window.PublicKeyCredential) return Core.customAlert("ОШИБКА", "Браузер не поддерживает биометрию.");
        
        Core.customPrompt("KNOX HARDWARE", "Введи КЛЮЧ ДОСТУПА для привязки к железу:", async (key) => {
            if (!key) return;
            try {
                const challenge = new Uint8Array(32); window.crypto.getRandomValues(challenge);
                const userId = new Uint8Array(16); window.crypto.getRandomValues(userId);

                const createCreds = await navigator.credentials.create({
                    publicKey: {
                        challenge,
                        rp: { name: "MathPro Security", id: window.location.hostname },
                        user: { id: userId, name: Core.activeIdentity, displayName: Core.activeIdentity },
                        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                        authenticatorSelection: { 
                            authenticatorAttachment: "platform",
                            userVerification: "required",
                            residentKey: "required"
                        },
                        // ТА САМАЯ МАГИЯ: Запрашиваем секрет у Knox
                        extensions: { prf: { eval: { first: new Uint8Array(32) } } }
                    }
                });

                if (createCreds) {
                    const credId = Core.bytesToHex(new Uint8Array(createCreds.rawId));
                    
                    // Пробуем достать секрет из ответа Knox
                    let hardwareKey = null;
                    const extensionRes = createCreds.getClientExtensionResults();
                    if (extensionRes.prf && extensionRes.prf.results) {
                        hardwareKey = new Uint8Array(extensionRes.prf.results.first);
                        console.log("[*] Knox PRF: Hardware key derived.");
                    }

                    // Шифруем: если Knox дал секрет - юзаем его, если нет - fallback на Master PIN (как было)
                    const encryptedKey = await Core.encryptWithHardware(key, hardwareKey);
                    
                    await Storage.updateAccountAuth(Core.activeIdentity, { 
                        bio: true, 
                        bio_key: encryptedKey,
                        cred_id: credId,
                        has_prf: !!hardwareKey // Пометка, что это железный шифр
                    });
                    Core.customAlert("УСПЕХ", hardwareKey ? "Ключ прибит к железу Knox!" : "Палец привязан (Software mode).");
                }
            } catch (e) { Core.customAlert("ОТКАЗ", "Knox не ответил: " + e.message); }
        });
    },

    /**
     * БЕСПАРОЛЬНЫЙ ВХОД (Для рисковых)
     */
    setupLazyLogin: function() {
        Core.customPrompt("БЕСПАРОЛЬНЫЙ ВХОД", "Введи КЛЮЧ ДОСТУПА для сохранения:", async (key) => {
            if (!key) return;
            const encryptedKey = await Core.encryptForBio(key); // Тоже шифруем Мастер-кодом
            await Storage.updateAccountAuth(Core.activeIdentity, { lazy: true, lazy_key: encryptedKey });
            Core.customAlert("ГОТОВО", "Теперь вход для этого акка — в один тап.");
        });
    },
 
        /**
     * ВХОД ЧЕРЕЗ ЖЕЛЕЗО
     */
    biometricLogin: async function(id) {
        try {
            const acc = await Storage.getRegistryAccount(id);
            if (!acc || !acc.bio_key) return false;

            const challenge = new Uint8Array(32); window.crypto.getRandomValues(challenge);
            const getAssertion = await navigator.credentials.get({
                publicKey: { 
                    challenge, 
                    timeout: 60000, 
                    userVerification: "required",
                    allowCredentials: [{ id: Core.hexToBytes(acc.cred_id), type: 'public-key' }],
                    // Запрашиваем секрет обратно
                    extensions: { prf: { eval: { first: new Uint8Array(32) } } }
                }
            });

            if (getAssertion) {
                let hardwareKey = null;
                const extRes = getAssertion.getClientExtensionResults();
                if (extRes.prf && extRes.prf.results) {
                    hardwareKey = new Uint8Array(extRes.prf.results.first);
                }

                const key = await Core.decryptWithHardware(acc.bio_key, hardwareKey);
                if (key) { await Core.boot(id, key); return true; }
                else { Core.customAlert("ОШИБКА", "Не удалось вскрыть железный контейнер."); }
            }
            return false;
        } catch (e) { return false; }
    },
    /**
     * ПРОСТО ВХОД ПО ТАПУ
     */
    lazyLogin: async function(id) {
        const acc = await Storage.getRegistryAccount(id);
        if (!acc || !acc.lazy_key) return false;
        const key = await Core.decryptFromBio(acc.lazy_key);
        if (key) { await Core.boot(id, key); return true; }
        return false;
    },

    // Шифровальни для биометрии (Ключ аккаунта лежит в базе, зашифрованный Master PIN-ом)
    encryptForBio: async function(key) {
        try {
            const master = localStorage.getItem('sys_m'); // Хеш Master PIN
            if (!master) return null;
            const n = window.nacl.randomBytes(24);
            // Берем первые 32 байта хеша как ключ для secretbox
            const masterKey = Core.hexToBytes(master).slice(0, 32);
            const e = window.nacl.secretbox(new TextEncoder().encode(key), n, masterKey);
            const res = new Uint8Array(n.length + e.length); 
            res.set(n); res.set(e, n.length);
            return Core.bytesToHex(res);
        } catch (e) { return null; }
    },

    decryptFromBio: async function(blob) {
        try {
            const master = localStorage.getItem('sys_m');
            if (!master) return null;
            const masterKey = Core.hexToBytes(master).slice(0, 32);
            const r = Core.hexToBytes(blob);
            if (r.length < 24) return null;
            const n = r.slice(0, 24), c = r.slice(24);
            const d = window.nacl.secretbox.open(c, n, masterKey);
            return d ? new TextDecoder().decode(d) : null;
        } catch (e) { return null; }
    },
        // Вспомогательные шифровальни: мешаем Hardware Secret и Master PIN
    encryptWithHardware: async function(key, hwKey) {
        const master = localStorage.getItem('sys_m');
        let baseKey = Core.hexToBytes(master).slice(0, 32);
        
        // Если Knox дал секрет - мешаем его с Master PIN через XOR или просто HASH
        if (hwKey) {
            const combined = new Uint8Array(32);
            for (let i = 0; i < 32; i++) combined[i] = baseKey[i] ^ hwKey[i];
            baseKey = combined;
        }

        const n = window.nacl.randomBytes(24);
        const e = window.nacl.secretbox(new TextEncoder().encode(key), n, baseKey);
        const res = new Uint8Array(n.length + e.length); res.set(n); res.set(e, n.length);
        return Core.bytesToHex(res);
    },

    decryptWithHardware: async function(blob, hwKey) {
        const master = localStorage.getItem('sys_m');
        let baseKey = Core.hexToBytes(master).slice(0, 32);

        if (hwKey) {
            const combined = new Uint8Array(32);
            for (let i = 0; i < 32; i++) combined[i] = baseKey[i] ^ hwKey[i];
            baseKey = combined;
        }

        const r = Core.hexToBytes(blob);
        if (r.length < 24) return null;
        const n = r.slice(0, 24), c = r.slice(24);
        const d = window.nacl.secretbox.open(c, n, baseKey);
        return d ? new TextDecoder().decode(d) : null;
    },
    
        /**
     * ОТПРАВКА СИГНАЛА ИМЕННО СОБЕСЕДНИКУ
     */
    sendVoipSignal: async function(data) {
        if (!Core.callPeerId) return;
        // Юзаем стандартный sendMessage, но подменяем временный ID, если надо
        const oldActive = Core.activePeerId;
        Core.activePeerId = Core.callPeerId;
        await Core.sendMessage(data);
        Core.activePeerId = oldActive;
    },
    
    initProximity: async function() {
        window.addEventListener('deviceorientation', (e) => {
            // Если в звонке или пишем кружок — не лочим (чтоб не вылететь случайно)
            if (this.callState !== 'idle' || this.isRecordingCircle || localStorage.getItem('cfg_flip_off') === 'true') return;

            // Если телефон перевернут (угол больше 110 градусов)
            if (e.beta !== null && Math.abs(e.beta) > 110) {
                // КОНЦЫ В ВОДУ!
                this.terminateSession();
            }
        }, true);
    },

    toggleVideo: function() {
        const vt = Core.localStream.getVideoTracks()[0];
        if (vt) {
            vt.enabled = !vt.enabled;
            document.getElementById('btn-vid-toggle').classList.toggle('off', !vt.enabled);
        }
    },

    toggleMic: function() {
        const at = Core.localStream.getAudioTracks()[0];
        if (at) {
            at.enabled = !at.enabled;
            document.getElementById('btn-mic-toggle').classList.toggle('off', !at.enabled);
        }
    },

    /**
     * ОБНОВЛЕННЫЙ МЕНЕДЖЕР: Теперь со сбросом прав
     */
    openAccountManager: async function() {
        const accounts = await Storage.getAllRegistryAccounts();
        let listHtml = accounts.map(acc => {
            const hasExtra = acc.bio || acc.lazy;
            return `
            <div style="background:#111; padding:12px; margin-bottom:10px; border:1px solid #333; text-align:left;">
                <div style="margin-bottom:8px;">
                    <b style="color:var(--main);">${acc.id}</b>
                    <div style="font-size:0.6rem; color:#555;">${acc.pk.substring(0,16)}...</div>
                    <div style="font-size:0.6rem; color:var(--op); margin-top:4px;">
                        ${acc.bio ? '[🧬 БИОМЕТРИЯ] ' : ''} ${acc.lazy ? '[⚡ ЛЕНИВЫЙ] ' : ''}
                    </div>
                </div>
                <div style="display:flex; gap:5px;">
                    ${hasExtra ? `<button class="sys-modal-btn" style="padding:5px; font-size:0.6rem; margin:0;" onclick="Core.resetAccountAuthFlow('${acc.id}')">СБРОСИТЬ ВХОД</button>` : ''}
                    ${acc.id !== Core.activeIdentity ? 
                        `<button class="sys-modal-btn danger" style="padding:5px; font-size:0.6rem; margin:0;" onclick="Core.removeAccountFlow('${acc.id}')">УДАЛИТЬ</button>` 
                        : ''}
                </div>
            </div>`;
        }).join('');

        const h = `
            <div style="max-height:350px; overflow-y:auto; margin-bottom:15px;">${listHtml || "РЕЕСТР ПУСТ"}</div>
            <button class="sys-modal-btn primary" onclick="Core.openSettings()">НАЗАД</button>
        `;
        Core.openModal("УПРАВЛЕНИЕ КВАРТИРАНТАМИ", h);
    },

   /**
     * СБРОС БИОМЕТРИИ И ЛЕНИВОГО ВХОДА
     */
    resetAccountAuthFlow: function(id) {
        Core.customPrompt("ОБНУЛЕНИЕ", `Введите "СБРОС" для ${id}:`, async (val) => {
            if (val === "СБРОС") {
                await Storage.updateAccountAuth(id, {
                    bio: false, bio_key: null, cred_id: null,
                    lazy: false, lazy_key: null
                });
                Core.customAlert("ГОТОВО", "Ключи Knox и ленивый вход удалены из памяти приложения.");
                Core.openAccountManager();
            }
        });
    },
    
    /**
     * ПОЛНОЕ УДАЛЕНИЕ АККАУНТА (И базы, и реестра)
     */
    removeAccountFlow: function(id) {
        Core.customPrompt("УДАЛЕНИЕ", `Введите "УДАЛИТЬ" для аккаунта ${id}. Вся история будет стерта!`, async (val) => {
            if (val === "УДАЛИТЬ") {
                // 1. Удаляем из реестра (уведомления и биометрия)
                await Storage.removeAccountFromRegistry(id);
                // 2. Удаляем саму базу сообщений этого пацана
                const dbName = `dm_v6_${await Core.fastHash(id + "SALT_V11")}`.substring(0, 24); // Пример генерации имени
                indexedDB.deleteDatabase(dbName); 
                
                Core.customAlert("ГОТОВО", `Аккаунт ${id} и его ключи полностью ликвидированы.`);
                Core.openAccountManager();
            }
        });
    },

    changePinFlow: function(type) {
        Core.customPrompt(type === 'M' ? "MASTER-КОД" : "WIPE-КОД", "Введите новый цифровой код:", async (v) => {
            if (v && !isNaN(v)) { 
                if (type === 'M') await sys.changeMasterPin(v); else await sys.changeWipePin(v);
                Core.customAlert("УСПЕХ", "Код изменен");
            }
        });
    },


deleteMessageFlow(msgId, peerId = this.activePeerId) {
        this.customConfirm("ЗАЧИСТКА", "Стереть маляву?", async () => {
            await Storage.deleteMessageGamma(peerId, msgId);
            
            // ФИКС: Удаляем элемент из лога по ID
            const msgEl = document.getElementById(`msg-box-${msgId}`);
            if (msgEl) {
                msgEl.style.transition = "opacity 0.3s";
                msgEl.style.opacity = "0";
                setTimeout(() => msgEl.remove(), 300);
            }
            this.shmon("INFO", `Малява ${msgId} удалена.`);
        });
    },
    copyPeerId(id) {
        navigator.clipboard.writeText(id).then(() => {
            this.customAlert("УСПЕХ", "Полный ID кента скопирован.");
        }).catch(() => {
            this.customPrompt("ID", "Скопируй вручную:", () => {}, id);
        });
    },

    /**
     * СНОС ЧАТА (V79 - Быстрый сброс)
     */
    deleteChatFlow: function(id, name) {
        Core.customConfirm("СНОС ЧАТА", `Ликвидировать всю переписку с ${name}?`, async () => {
            await Storage.deleteChatGamma(id);
            if (Core.activePeerId === id) Core.closeChat();
            await Core.renderPeers();
            Core.customAlert("ГОТОВО", "Хата зачищена.");
        });
    },

    // В buildMsgHtml и renderPeers оставляем вызовы как были, 
    // только кнопки в HTML сделаем поудобнее (см. CSS ниже)
   /**
     * ПАЦАНСКИЙ ВЫБОР: ДА ИЛИ НЕТ
     */
    customConfirm: function(t, tx, onYes) {
        const h = `
            <div style="margin-bottom:20px; font-size:1rem; color:#ccc;">${tx}</div>
            <div style="display:flex; gap:15px;">
                <button class="sys-modal-btn" style="flex:1;" onclick="Core.closeModal()">НЕТ</button>
                <button class="sys-modal-btn primary" style="flex:1;" id="confirm-yes">ДА</button>
            </div>`;
        Core.openModal(t, h);
        document.getElementById('confirm-yes').onclick = () => {
            Core.closeModal();
            onYes();
        };
    },


closeChat: function(manual = true) {
        if(Core.activeAudio) Core.activeAudio.pause();
        
        // Если закрыли кнопкой в интерфейсе — убираем якорь из истории
        if (manual && window.history.state?.view === 'chat') {
            window.history.back();
        }

        Core.activePeerId = null;
        document.getElementById('main-grid').classList.remove('chat-active');
        document.getElementById('input-area').style.display = 'none';
        document.getElementById('voip-btn').style.display = 'none';
        Core.renderPeers();
    },
     
    /**
     * АКСЕЛЕРОМЕТР (V58 - Call-Aware)
     */
    initAccelerometer: function() {
        if (window.ACC_INITED) return;
        window.ACC_INITED = true;
        
        window.addEventListener('deviceorientation', (event) => {
            // ЕСЛИ МЫ В ЗВОНКЕ — ФЛИПЛОК НЕ РАБОТАЕТ!
            if (Core.callState !== 'idle') return;

            const tilt = event.beta;
            if (tilt !== null && Math.abs(tilt) > 110) { 
                window.location.reload();
            }
        }, true);
    },

 
/**
     * РЕНДЕР ЗАГЛУШКИ (V81)
     */
    renderStub: function(data, id) {
        if (data.type === 'video_note') {
            // КРУЖОК
            return `
                <div class="media-stub" id="stub-${id}">
                    <div class="circle-note-container">
                        <video src=""></video>
                    </div>
                    <button class="sys-modal-btn primary" style="padding:5px; font-size:0.6rem; margin-top:8px;" 
                        onclick='Core.decryptMedia("${id}", ${JSON.stringify(data).replace(/"/g, '&quot;')})'>РАСШИФРОВАТЬ КРУЖОК</button>
                </div>`;
        }
        
        // ОБЫЧНОЕ ВИДЕО ИЛИ КАРТИНКА
        const label = data.type === 'video' ? 'ВИДЕО' : (data.type === 'image' ? 'ФОТО' : 'ФАЙЛ');
        return `
            <div class="media-stub" id="stub-${id}">
                <div style="color:var(--main); font-size:0.7rem; margin-bottom:5px;">[ ${label}: ${Core.escapeHtml(data.name || 'file')} ]</div>
                <button class="sys-modal-btn primary" style="padding:5px; font-size:0.6rem;" 
                    onclick='Core.decryptMedia("${id}", ${JSON.stringify(data).replace(/"/g, '&quot;')})'>РАСШИФРОВАТЬ</button>
            </div>`;
    },


// --- 1. ВОЗВРАЩАЕМ КРЕСТИКИ В СПИСОК КЕНТОВ ---
    async renderPeers() {
        const peers = await Storage.loadPeersGamma();
        const list = document.getElementById('contact-list');
        if (!list) return;
        if (peers.length === 0) { list.innerHTML = '<div style="text-align:center; color:#444; margin-top:30px;">НЕТ СВЯЗЕЙ</div>'; return; }
        
        list.innerHTML = peers.map(p => {
            const act = this.activePeerId === p.id ? 'active' : '';
            const unr = p.unread ? 'has-unread' : '';
            return `
                <div class="peer-item ${act} ${unr}" onclick="Core.selectPeer('${p.id}')">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                        <div>
                            <b>${p.name}</b><br>
                            <small>${p.id.substring(0, 8)}...</small>
                        </div>
                        <span class="chat-del-btn" onclick="event.stopPropagation(); Core.deleteChatFlow('${p.id}', '${p.name}')">×</span>
                    </div>
                    ${p.unread ? '<span class="unread-dot"></span>' : ''}
                </div>`;
        }).join('');
    },

    // --- 2. ВОЗВРАЩАЕМ КРЕСТИКИ И СТАБЫ В МАЛЯВЫ ---
    buildMsgHtml(msg, ts, id) {
        const side = msg.inbound ? 'in' : 'out';
        const time = new Date(ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
        let data = msg.text;
        
        try { if (typeof data === 'string' && data.startsWith('{')) data = JSON.parse(data); } catch(e) {}
        
        // Если это объект (медиа) - рисуем красивую заглушку, иначе - текст
        const content = (typeof data === 'object') ? this.renderStub(data, id || ts) : this.escapeHtml(data);
        
        return `
            <div class="msg ${side}" id="msg-box-${id || ts}">
                <div class="m-txt">
                    ${content}
                    <span class="msg-del-btn" onclick="Core.deleteMessageFlow('${id || ts}')">×</span>
                </div>
                <small class="m-ts">${time}</small>
            </div>`;
    },

    // --- 3. ОРИГИНАЛЬНЫЕ ФУНКЦИИ ДЛЯ МЕДИА ---
    renderStub(data, id) {
        if (data.type === 'video_note') {
            return `
                <div class="media-stub" id="stub-${id}">
                    <div class="circle-note-container"><video src=""></video></div>
                    <button class="sys-modal-btn primary" style="padding:5px; font-size:0.6rem; margin-top:8px;" 
                        onclick='Core.decryptMedia("${id}", ${JSON.stringify(data).replace(/"/g, '&quot;')})'>РАСШИФРОВАТЬ КРУЖОК</button>
                </div>`;
        }
        const label = data.type === 'video' ? 'ВИДЕО' : (data.type === 'image' ? 'ФОТО' : (data.type === 'voice' ? 'ГОЛОСОВОЕ' : 'ФАЙЛ'));
        return `
            <div class="media-stub" id="stub-${id}">
                <div style="color:var(--main); font-size:0.7rem; margin-bottom:5px;">[ ${label}: ${this.escapeHtml(data.name || 'file')} ]</div>
                <button class="sys-modal-btn primary" style="padding:5px; font-size:0.6rem;" 
                    onclick='Core.decryptMedia("${id}", ${JSON.stringify(data).replace(/"/g, '&quot;')})'>РАСШИФРОВАТЬ</button>
            </div>`;
    },

    async decryptMedia(id, rawData) {
        const stub = document.getElementById(`stub-${id}`);
        if (!stub) return;
        stub.innerHTML = '<span style="color:var(--op); font-size:0.7rem;">РАСШИФРОВКА...</span>';
        
        try {
            const parts = rawData.data.split(',');
            const byteString = atob(parts[1]);
            const mimeString = parts[0].split(':')[1].split(';')[0];
            const ia = new Uint8Array(byteString.length);
            for (let i = 0; i < byteString.length; i++) ia[i] = byteString.charCodeAt(i);
            const url = URL.createObjectURL(new Blob([ia], {type: mimeString}));
            
            if (!this.blobURLs) this.blobURLs = [];
            this.blobURLs.push(url);

            if (rawData.type === 'video_note') {
                stub.innerHTML = `<div class="circle-note-container"><video src="${url}" controls autoplay></video></div>`;
            } else if (rawData.type === 'video') {
                stub.innerHTML = `<div class="video-attachment"><video src="${url}" controls autoplay style="width:100%; border-radius:8px;"></video></div>`;
            } else if (rawData.type === 'image') {
                stub.innerHTML = `<img src="${url}" class="img-attachment" onclick="window.open('${url}')">`;
            } else if (rawData.type === 'voice') {
                stub.innerHTML = `<audio src="${url}" class="voice-player" controls preload="metadata"></audio>`;
            } else {
                stub.innerHTML = `<a href="${url}" download="${rawData.name}" class="file-attachment">СКАЧАТЬ ${rawData.name}</a>`;
            }
        } catch (e) { stub.innerHTML = '<span style="color:var(--accent)">ОШИБКА</span>'; }
    },
/**
     * ПОДГОТОВКА ТРУБКИ (V69 - Полный контроль потоков)
     */
setupPC: async function(targetId, withVideo = true) {
        const pc = new RTCPeerConnection(iceConfig);
        Core.peerConnection = pc;

        // СЛЕДИМ ЗА СОСТОЯНИЕМ КАНАЛА
        pc.oniceconnectionstatechange = () => {
            const s = pc.iceConnectionState;
            console.log("[*] Состояние линии: " + s);
            // Если собеседник отвалился или закрыл вкладку без сигнала
            if (s === 'disconnected' || s === 'failed' || s === 'closed') {
                console.log("[!] Линия мертва, гасим приборы...");
                Core.endCall(false); 
            }
        };

        pc.onicecandidate = ({ candidate }) => {
            if (candidate) Core.sendVoipSignal({ type: "voip_ice", candidate });
        };

        pc.ontrack = (event) => {
            Core.remoteStream = event.streams[0];
            const rv = document.getElementById('remoteVideo');
            const ra = document.getElementById('remoteAudio');
            if (rv) rv.srcObject = Core.remoteStream;
            if (ra) ra.srcObject = Core.remoteStream;
            Core.applyAudioRoute();

            if (Core.callState !== 'connected') {
                Core.callState = 'connected';
                Core.updateCallUI('connected');
                Core.playSound('start');
                Core.startTimer();
            }
        };

        try {
            const stream = await navigator.mediaDevices.getUserMedia({ 
                audio: true, 
                video: { width: 640, height: 480, facingMode: Core.currentCamera } 
            });
            Core.localStream = stream;
            const lv = document.getElementById('localVideo');
            if (lv) {
                lv.srcObject = stream;
                lv.classList.toggle('mirrored', Core.currentCamera === 'user');
            }
            if (!withVideo) stream.getVideoTracks().forEach(t => t.enabled = false);
            stream.getTracks().forEach(track => pc.addTrack(track, stream));
        } catch (e) { Core.endCall(false); throw e; }

        return pc;
    },

/**
     * СМЕНА КАМЕРЫ В ЗВОНКЕ (V77)
     */
    switchCamera: async function() {
        if (Core.callState === 'idle') return; // В чате больше не переключаем заранее
        
        Core.currentCamera = (Core.currentCamera === 'user') ? 'environment' : 'user';
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ 
                video: { facingMode: Core.currentCamera, width: 640, height: 480 } 
            });
            const newTrack = stream.getVideoTracks()[0];

            if (Core.peerConnection) {
                const sender = Core.peerConnection.getSenders().find(s => s.track?.kind === 'video');
                if (sender) await sender.replaceTrack(newTrack);
            }

            const lv = document.getElementById('localVideo');
            if (lv) {
                lv.srcObject = stream;
                lv.classList.toggle('mirrored', Core.currentCamera === 'user');
            }
            
            if (Core.localStream) {
                Core.localStream.getVideoTracks().forEach(t => t.stop());
                const audioTrack = Core.localStream.getAudioTracks()[0];
                Core.localStream = new MediaStream([audioTrack, newTrack]);
            }
        } catch (e) { console.error("[!] Сбой смены", e); }
    },
    
/**
     * НАЧАЛО ЗВОНКА (CALLER)
     */
    async initVoip() {
        if (this.callState !== 'idle') return;
        this.callPeerId = this.activePeerId;
        this.callState = 'calling';
        this.updateCallUI('calling');
        
        try {
            const callPSK = this.bytesToHex(window.nacl.randomBytes(32));
            this.activeCallPSK = callPSK;

            this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
            this.localStream.getVideoTracks().forEach(t => t.enabled = false);
            document.getElementById('localVideo').srcObject = this.localStream;
            
            this.peerConnection = new RTCPeerConnection(iceConfig);
            this.localStream.getTracks().forEach(track => this.peerConnection.addTrack(track, this.localStream));
            
            this.peerConnection.onicecandidate = (e) => {
                if (e.candidate) this.sendMessage({ type: "voip_ice", candidate: e.candidate });
            };

            this.peerConnection.ontrack = (e) => {
                document.getElementById('remoteVideo').srcObject = e.streams[0];
                if (this.callState !== 'connected') {
                    this.callState = 'connected';
                    this.updateCallUI('connected');
                    this.startTimer();
                }
            };

            const offer = await this.peerConnection.createOffer();
            await this.peerConnection.setLocalDescription(offer);

            // Шлем оффер через sendMessage (он сам решит: 0x01 или 0x00)
            this.sendMessage({ 
                type: "voip_offer", 
                sdp: this.peerConnection.localDescription,
                call_psk: callPSK
            });
        } catch (e) { this.shmon("ERR", "VoIP Init Fail", e); this.endCall(false); }
    },

    /**
     * ОБРАБОТКА СИГНАЛОВ (RECEIVER)
     */
    async handleVoipSignal(data, fromId) {
        this.shmon("INFO", `Сигнал VoIP: ${data.type} от ${fromId.substring(0,8)}`);
        
        if (data.type === 'voip_offer') {
            if (this.callState !== 'idle') return;
            this.callPeerId = fromId;
            this.activeCallPSK = data.call_psk;
            
            this.showIncomingCall(fromId, async () => {
                this.callState = 'connecting';
                this.updateCallUI('connecting');
                try {
                    this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
                    document.getElementById('localVideo').srcObject = this.localStream;
                    
                    this.peerConnection = new RTCPeerConnection(iceConfig);
                    this.localStream.getTracks().forEach(track => this.peerConnection.addTrack(track, this.localStream));
                    
                    this.peerConnection.onicecandidate = (e) => {
                        if (e.candidate) this.sendMessage({ type: "voip_ice", candidate: e.candidate });
                    };

                    this.peerConnection.ontrack = (e) => {
                        document.getElementById('remoteVideo').srcObject = e.streams[0];
                        if (this.callState !== 'connected') {
                            this.callState = 'connected';
                            this.updateCallUI('connected');
                            this.startTimer();
                        }
                    };

                    await this.peerConnection.setRemoteDescription(new RTCSessionDescription(data.sdp));
                    const answer = await this.peerConnection.createAnswer();
                    await this.peerConnection.setLocalDescription(answer);
                    
                    this.sendMessage({ type: "voip_answer", sdp: this.peerConnection.localDescription });
                    
                    // Обрабатываем ICE-кандидатов, если они пришли раньше оффера
                    while (this.iceQueue.length > 0) {
                        const cand = this.iceQueue.shift();
                        await this.peerConnection.addIceCandidate(new RTCIceCandidate(cand));
                    }
                } catch (e) { this.shmon("ERR", "Answer Fail", e); this.endCall(false); }
            });

        } else if (data.type === 'voip_answer') {
            if (this.peerConnection) {
                await this.peerConnection.setRemoteDescription(new RTCSessionDescription(data.sdp));
            }
        } else if (data.type === 'voip_ice') {
            if (this.peerConnection && this.peerConnection.remoteDescription) {
                await this.peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate)).catch(e => {});
            } else {
                this.iceQueue.push(data.candidate);
            }
        } else if (data.type === 'voip_hangup') {
            // Реагируем на отбой только если он от текущего собеседника
            if (fromId === this.callPeerId) {
                this.shmon("INFO", "Собеседник повесил трубку");
                this.endCall(false);
            }
            return;
        }
    },
/**
     * ЗАПИСЬ КРУЖКА (V66 - С отменой и переворотом)
     */
/**
     * НАЖАТИЕ НА КРУЖОК (V77 - Выбор камеры и старт)
     */
    uiCircle: async function() {
        const cBtn = document.getElementById('circle-btn');
        
        // Если уже пишем — кнопка работает как ОТМЕНА
        if (Core.isRecording) {
            Core.cancelRecording = true;
            if (Core.mediaRecorder && Core.mediaRecorder.state !== 'inactive') Core.mediaRecorder.stop();
            return;
        }

        try {
            // 1. Получаем список всех камер
            const devices = await navigator.mediaDevices.enumerateDevices();
            const cameras = devices.filter(d => d.kind === 'videoinput');

            if (cameras.length > 1) {
                // 2. Если камер много — выводим список
                let listHtml = cameras.map((cam, idx) => {
                    let label = cam.label || `Камера ${idx + 1}`;
                    // Упрощаем названия для пацанов
                    if (label.toLowerCase().includes('front') || label.toLowerCase().includes('user')) label = "ФРОНТАЛЬНАЯ";
                    if (label.toLowerCase().includes('back') || label.toLowerCase().includes('env')) label = "ОСНОВНАЯ";
                    
                    return `<button class="sys-modal-btn primary" style="margin-bottom:10px;" 
                        onclick="Core.startCircleRecording('${cam.deviceId}')">${label}</button>`;
                }).join('');

                Core.openModal("ВЫБЕРИ ГЛАЗ", `<div style="display:flex; flex-direction:column;">${listHtml}<button class="sys-modal-btn" onclick="Core.closeModal()">ОТМЕНА</button></div>`);
            } else {
                // 3. Если камера одна — стартуем сразу
                Core.startCircleRecording(cameras[0]?.deviceId || null);
            }
        } catch (e) { Core.customAlert("ОШИБКА", "Нет доступа к камерам."); }
    },

    /**
     * РЕАЛЬНЫЙ СТАРТ ЗАПИСИ
     */
    startCircleRecording: async function(deviceId) {
        Core.closeModal(); // Закрываем выбор камер
        const cBtn = document.getElementById('circle-btn');
        
        try {
            Core.isRecordingCircle = true;
            Core.cancelRecording = false;
            
            const constraints = {
                audio: true,
                video: deviceId ? { deviceId: { exact: deviceId }, width: 400, height: 400 } : { facingMode: 'user', width: 400, height: 400 }
            };

            Core.localStream = await navigator.mediaDevices.getUserMedia(constraints);
            Core.mediaRecorder = new MediaRecorder(Core.localStream, { mimeType: 'video/webm;codecs=vp8,opus' });
            Core.audioChunks = [];
            
            const preview = document.createElement('video');
            preview.id = "circle-preview";
            // Зеркалим только если это фронталка (обычно первая в списке или по метке)
            const tracks = Core.localStream.getVideoTracks();
            if (tracks[0] && tracks[0].getSettings().facingMode === 'user') preview.className = "mirrored";
            
            preview.style = "position:fixed; bottom:120px; right:20px; width:160px; height:160px; border-radius:50%; object-fit:cover; border:3px solid var(--main); z-index:10000; background:#000;";
            preview.autoplay = true; preview.muted = true; preview.srcObject = Core.localStream;
            document.body.appendChild(preview);

            Core.mediaRecorder.ondataavailable = e => { if (e.data.size > 0) Core.audioChunks.push(e.data); };
            
            Core.mediaRecorder.onstop = () => {
                if (!Core.cancelRecording && Core.audioChunks.length > 0) {
                    const reader = new FileReader();
                    reader.onload = (e) => Core.sendMessage({ type: 'video_note', name: 'circle', data: e.target.result });
                    reader.readAsDataURL(new Blob(Core.audioChunks, { type: 'video/webm' }));
                }
                Core.killAllMedia();
                document.getElementById('circle-preview')?.remove();
                Core.resetCircleUI();
            };

            Core.mediaRecorder.start();
            Core.isRecording = true;
            cBtn.innerText = "❌"; // Кнопка кружка теперь отмена
        } catch (e) { 
            console.error(e);
            Core.killAllMedia(); Core.resetCircleUI();
            Core.customAlert("ОШИБКА", "Не удалось запустить камеру."); 
        }
    },

    resetCircleUI: function() {
        Core.isRecording = false;
        Core.isRecordingCircle = false;
        const cBtn = document.getElementById('circle-btn');
        const sBtn = document.getElementById('cam-switch-btn');
        if (cBtn) cBtn.innerText = "⭕";
        if (sBtn) sBtn.style.display = "flex"; // Возвращаем свитч
    },

    resetCircleUI: function() {
        Core.isRecording = false;
        Core.isRecordingCircle = false;
        const cBtn = document.getElementById('circle-btn');
        const vBtn = document.getElementById('voice-btn');
        if (cBtn) cBtn.innerText = "⭕";
        if (vBtn) { vBtn.innerText = "🎤"; vBtn.onclick = () => Core.uiVoice(); }
    },

    /**
     * СБРОС ИНТЕРФЕЙСА КРУЖКА
     */
    resetCircleUI: function() {
        Core.isRecording = false;
        Core.isRecordingCircle = false;
        Core.localStream = null;
        
        const cBtn = document.getElementById('circle-btn');
        const vBtn = document.getElementById('voice-btn');
        
        if (cBtn) cBtn.innerText = "⭕";
        if (vBtn) {
            vBtn.innerText = "🎤";
            vBtn.onclick = () => Core.uiVoice(); // Возвращаем микрофон
        }
        console.log("[*] UI кружка сброшен.");
    },
/**
     * ЯДЕРНЫЙ СТОП ВСЕГО ЖЕЛЕЗА
     */
/**
     * ТОТАЛЬНАЯ ЛИКВИДАЦИЯ МЕДИА-ПОТОКОВ
     */
    killAllMedia: function() {
        console.log("[*] Система: Полная зачистка ресурсов...");
        
        // 1. Останавливаем всё, что живет в Core.localStream
        if (Core.localStream) {
            Core.localStream.getTracks().forEach(track => {
                track.stop();
                track.enabled = false;
                console.log("[*] Трек убит: " + track.kind);
            });
            Core.localStream = null;
        }

        // 2. Дополнительный шмон: ищем залетные треки в PeerConnection
        if (Core.peerConnection) {
            Core.peerConnection.getSenders().forEach(sender => {
                if (sender.track) {
                    sender.track.stop();
                    console.log("[*] Трек в сендере остановлен");
                }
            });
        }

        // 3. Гасим все окна видео-трансляции
        ['localVideo', 'remoteVideo', 'circle-preview'].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.srcObject = null;
                el.pause();
                el.removeAttribute('src'); 
                el.load();
            }
        });
    },
stopCircleUI: function() {
        if (Core.mediaRecorder && Core.mediaRecorder.state !== 'inactive') {
            Core.mediaRecorder.stop();
        }
        Core.isRecording = false;
        
        // ГАСИМ ЖЕЛЕЗО
        if (Core.localStream) {
            Core.localStream.getTracks().forEach(t => t.stop());
            Core.localStream = null;
        }

        const cBtn = document.getElementById('circle-btn');
        const vBtn = document.getElementById('voice-btn');
        cBtn.innerText = "⭕";
        vBtn.innerText = "🎤";
        vBtn.onclick = () => Core.uiVoice();
        document.getElementById('circle-preview')?.remove();
    },


    processIceQueue: function() {
        while (Core.iceQueue.length > 0) {
            const candidate = Core.iceQueue.shift();
            if (Core.peerConnection && Core.peerConnection.remoteDescription) {
                Core.peerConnection.addIceCandidate(new RTCIceCandidate(candidate)).catch(e=> {
                    console.log("ICE Error during queue processing");
                });
            }
        }
    },
    /**
     * ЗВУКОВЫЕ СИГНАЛЫ (Old School - генерация на лету)
     */
    playSound: function(type) {
        if (!Core.audioCtx) Core.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = Core.audioCtx.createOscillator();
        const gain = Core.audioCtx.createGain();
        osc.connect(gain); gain.connect(Core.audioCtx.destination);
        
        if (type === 'start') { // Гудок начала
            osc.frequency.setValueAtTime(440, Core.audioCtx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(880, Core.audioCtx.currentTime + 0.1);
            gain.gain.setValueAtTime(0.1, Core.audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, Core.audioCtx.currentTime + 0.2);
            osc.start(); osc.stop(Core.audioCtx.currentTime + 0.2);
        }
        if (type === 'end') { // Сброс
            osc.frequency.setValueAtTime(300, Core.audioCtx.currentTime);
            osc.frequency.linearRampToValueAtTime(100, Core.audioCtx.currentTime + 0.3);
            gain.gain.setValueAtTime(0.1, Core.audioCtx.currentTime);
            gain.gain.linearRampToValueAtTime(0.01, Core.audioCtx.currentTime + 0.3);
            osc.start(); osc.stop(Core.audioCtx.currentTime + 0.3);
        }
    },

    startTimer: function() {
        if (Core.callTimer) clearInterval(Core.callTimer);
        Core.callSeconds = 0;
        const el = document.getElementById('call-timer');
        el.style.display = 'block';
        Core.callTimer = setInterval(() => {
            Core.callSeconds++;
            const m = Math.floor(Core.callSeconds / 60), s = Core.callSeconds % 60;
            el.innerText = `${m < 10 ? '0' : ''}${m}:${s < 10 ? '0' : ''}${s}`;
        }, 1000);
    },
    

async updateCallUI(state) {
        const overlay = document.getElementById('call-overlay');
        const status = document.getElementById('call-status');
        const name = document.getElementById('call-name');
        const timer = document.getElementById('call-timer');
        
        if (state === 'idle') {
            overlay.style.display = 'none';
            clearInterval(this.callTimer);
            timer.style.display = 'none';
            timer.innerText = "00:00";
        } else {
            overlay.style.display = 'flex';
            
            // ФИКС: Берем имя из слепой базы, а не из массива
            let peerName = "СВЯЗЬ...";
            if (this.callPeerId) {
                const aliasL1 = await Storage.getAlias(this.callPeerId, "L1");
                const peerInfo = await Storage.getBox('blind_peers', aliasL1);
                if (peerInfo && peerInfo.name) peerName = peerInfo.name.toUpperCase();
            }
            name.innerText = peerName;

            if (state === 'calling') status.innerText = "ВЫЗОВ...";
            if (state === 'connecting') status.innerText = "ПОДКЛЮЧЕНИЕ...";
            if (state === 'connected') {
                status.innerText = "В ЭФИРЕ";
                timer.style.display = 'block';
            }
        }
    },

    async showIncomingCall(fromId, onAccept) {
        // ФИКС: Берем имя из слепой базы
        let peerName = "Неизвестный";
        const aliasL1 = await Storage.getAlias(fromId, "L1");
        const peerInfo = await Storage.getBox('blind_peers', aliasL1);
        if (peerInfo && peerInfo.name) peerName = peerInfo.name;

        const h = `
            <div style="font-size:1.2rem; margin-bottom:20px;">ВХОДЯЩИЙ ВЫЗОВ</div>
            <div style="display:flex; gap:10px; margin-top:20px;">
                <button class="sys-modal-btn" id="decline-call">ОТКЛОНИТЬ</button>
                <button class="sys-modal-btn primary" id="accept-call">ПРИНЯТЬ</button>
            </div>`;
        this.openModal(`ОТ: ${peerName}`, h);
        
        document.getElementById('accept-call').onclick = () => {
            this.closeModal();
            onAccept();
        };
        
        document.getElementById('decline-call').onclick = () => {
            this.sendVoipSignal({ type: "voip_hangup" });
            this.closeModal();
            this.endCall(false);
        };
    },

    uiAttach: () => document.getElementById('file-input').click(),
    handleFileSelect: (ev) => {
        const f = ev.target.files[0]; if (!f) return;
        const r = new FileReader(); r.onload = (e) => {
            let t = f.type.startsWith('image/') ? 'image' : (f.type.startsWith('video/') ? 'video' : 'file');
            Core.sendMessage({ type: t, name: f.name, data: e.target.result });
        }; r.readAsDataURL(f);
    },
    uiVoice: async function() {
        const btn = document.getElementById('voice-btn');
        if (!Core.isRecording) {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                Core.mediaRecorder = new MediaRecorder(stream); Core.audioChunks = [];
                Core.mediaRecorder.ondataavailable = e => Core.audioChunks.push(e.data);
                Core.mediaRecorder.onstop = () => {
                    const r = new FileReader(); r.onload = (e) => Core.sendMessage({ type: 'voice', name: 'voice_msg', data: e.target.result });
                    r.readAsDataURL(new Blob(Core.audioChunks)); stream.getTracks().forEach(t => t.stop());
                };
                Core.mediaRecorder.start(); Core.isRecording = true; btn.classList.add('recording'); btn.innerText = '⬛';
            } catch (e) { Core.customAlert("МИКРОФОН", "ОТКАЗАНО"); }
        } else { Core.mediaRecorder.stop(); Core.isRecording = false; btn.classList.remove('recording'); btn.innerText = '🎤'; }
    },





    /**
     * АДРЕСНЫЙ ОТБОЙ
     */
    endCall(sendSignal = true) {
        this.shmon("INFO", "Завершение звонка...");
        this.playSound('end');
        
        // Шлем отбой ТОЛЬКО тому, с кем базарили
        if (sendSignal && this.callPeerId) {
            const oldActive = this.activePeerId;
            this.activePeerId = this.callPeerId;
            this.sendMessage({ type: "voip_hangup" });
            this.activePeerId = oldActive;
        }
        
        if (this.peerConnection) { this.peerConnection.close(); this.peerConnection = null; }
        this.killAllMedia();
        clearInterval(this.callTimer);
        this.callState = 'idle';
        this.callPeerId = null;
        this.updateCallUI('idle');
    },

    /**
     * ГРОМКАЯ СВЯЗЬ (Динамик/Ухо)
     */
toggleSpeaker: function() {
        const rv = document.getElementById('remoteVideo');
        Core.isSpeakerOn = !Core.isSpeakerOn;
        
        if (rv) {
            // Хак: на мобилах переключение идет через аудио-фокус
            if (Core.isSpeakerOn) {
                rv.volume = 1.0;
                // Пытаемся форсировать через setSinkId если есть
                if (rv.setSinkId) rv.setSinkId(""); 
            } else {
                rv.volume = 0.2; // Приглушаем, чтоб не орало в ухо
                // В идеале тут надо переключать на 'earpiece', но в PWA это лотерея
            }
        }
        
        document.getElementById('btn-speaker-toggle').classList.toggle('off', !Core.isSpeakerOn);
    },

    applyAudioRoute: function() {
        const rv = document.getElementById('remoteVideo');
        const ra = document.getElementById('remoteAudio');
        
        if (Core.isSpeakerOn) {
            // Громкий динамик: включаем видео-звук, гасим аудио-элемент
            if (ra) ra.muted = true;
            if (rv) {
                rv.muted = false;
                rv.style.display = "block";
            }
        } else {
            // Ушной динамик: гасим видео-звук, включаем аудио-элемент
            if (rv) {
                rv.muted = true;
                // Если никто не светит камерой — можно скрыть видео-окно
                // Но пока оставим для стабильности
            }
            if (ra) {
                ra.muted = false;
                ra.play().catch(e => console.log("Audio play blocked"));
            }
        }
    },

        /**
     * ДЕМОНСТРАЦИЯ ЭКРАНА
     */
    shareScreen: async function() {
        try {
            Core.screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
            const screenTrack = Core.screenStream.getVideoTracks()[0];
            const sender = Core.peerConnection.getSenders().find(s => s.track.kind === 'video');
            sender.replaceTrack(screenTrack);
            screenTrack.onended = () => { /* Вернуть камеру обратно */ };
        } catch (e) { console.log("Screen share cancelled"); }
    },
       /**
     * ТУМБЛЕР ФЛИППЕРА В НАСТРОЙКАХ
     */
    toggleFlipper: function() {
        const cur = localStorage.getItem('cfg_flip_off') === 'true';
        localStorage.setItem('cfg_flip_off', !cur);
        Core.openSettings();
    },
    deriveSharedKey: async (pid) => Core.hexToBytes(await Core.fastHash([Core.keys.pub_hex, pid].sort().join('') + "STATIC_SHARED_SECRET_V11")),

/**
     * ЗАПУСК СКАНЕРА
     */
    openScanner() {
        const c = `
            <div id="reader" style="width:100%; min-height:250px; background:#000; overflow:hidden; border:1px solid #333;"></div>
            <button class="sys-modal-btn" onclick="Core.closeScanner()">ОТМЕНА</button>
        `;
        this.openModal("СКАНЕР QR", c);

        setTimeout(async () => {
            try {
                this.scanner = new Html5Qrcode("reader");
                await this.scanner.start(
                    { facingMode: "environment" }, 
                    { fps: 10, qrbox: 250 },
                    (decodedText) => {
                        this.shmon("INFO", "QR пойман!");
                        this.closeScanner(); // Сначала гасим камеру
                        // Микро-пауза, чтоб модалка успела уйти
                        setTimeout(() => this.addPeerFlow(decodedText), 300);
                    }
                );
            } catch (err) {
                this.customAlert("КАМЕРА", "Глаз не открывается. Проверь разрешения.");
            }
        }, 150);
    },

    closeScanner() {
        if (this.scanner) {
            this.scanner.stop().then(() => {
                this.scanner.clear();
                this.closeModal();
            }).catch(() => this.closeModal());
        } else {
            this.closeModal();
        }
    },

 async addPeerFlow(fullId) {
        const cleanId = fullId.replace(/[^a-f0-9]/gi, '');
        if (cleanId.length !== 128) return this.customAlert("ОШИБКА", "ID не по масти (нужно 128 HEX).");
        
        const edPub = cleanId.substring(0, 64);
        const curvePub = cleanId.substring(64, 128);

        // ФИКС 3: Проверяем на дубли
        const aliasL1 = await Storage.getAlias(edPub, "L1");
        const existing = await Storage.getBox('blind_peers', aliasL1);
        if (existing) return this.customAlert("ИНФО", "Этот пацан уже прописан в хате.");

        this.customPrompt("ПСЕВДОНИМ", "Как назовем?", async (name) => {
            const alias = name || `Peer-${edPub.substring(0, 4)}`;
            await Storage.putBox('blind_peers', { 
                alias: aliasL1, 
                data: { id: edPub, curvePub: curvePub, name: alias, last_ts: Date.now(), unread: false, securityAlert: false } 
            });
            await this.renderPeers();
        });
    },
    
    bytesToHex: (b) => Array.from(b).map(x => Core.hex_lut[x]).join(''),
    hexToBytes: (h) => new Uint8Array(h.match(/.{1,2}/g).map(byte => parseInt(byte, 16))),
    escapeHtml: t => t ? String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\n/g,'<br>') : "",
    fastHash: async (m) => {
        const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(m));
        return Array.from(new Uint8Array(b)).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    renameCurrent: () => {
        const p = Core.peers.find(x => x.id === Core.activePeerId);
        Core.customPrompt("ИМЯ", `НОВОЕ ИМЯ ДЛЯ ${p.name}:`, async (n) => {
            if (n && n.trim()) { await Storage.savePeerGamma(p.id, n.trim(), false); await Core.renderPeers(); document.getElementById('chat-title').innerText = n.trim().toUpperCase(); }
        });
    },
    showMyQR: () => {
        const c = `<div id="qr-target" style="background:#fff; padding:10px; margin:10px auto; display:inline-block;"></div><div style="font-size:0.55rem; color:#888; margin-bottom:15px; word-break:break-all;">${Core.keys.pub_hex}</div><button class="sys-modal-btn primary" onclick="Core.copyMyId()">КОПИРОВАТЬ ID</button><button class="sys-modal-btn" onclick="Core.closeModal()">ЗАКРЫТЬ</button>`;
        Core.openModal("МОЙ ID", c); setTimeout(() => new QRCode(document.getElementById("qr-target"), { text: Core.keys.pub_hex, width: 220, height: 220 }), 50);
    },
    copyMyId: () => { navigator.clipboard.writeText(Core.keys.pub_hex); Core.customAlert("УСПЕХ", "КОПИРОВАНО"); },

    /**
     * ДОБАВЛЕНИЕ КОНТАКТА
     */
    addPeerPrompt: function() {
        Core.customPrompt("ДОБАВИТЬ ВРУЧНУЮ", "Вставь ID (HEX, 64 знака):", (id) => {
            if (id) Core.addPeerFlow(id.trim());
        });
    },


    openModal: (t, h) => { const m = document.getElementById('sys-modal'); m.innerHTML = `<div class="sys-modal-box"><h4>${t}</h4>${h}</div>`; m.style.display = 'flex'; },
closeModal: function() {
        const m = document.getElementById('sys-modal');
        if (m) {
            m.style.display = 'none';
            m.innerHTML = "";
        }
        // ВЫЗЫВАЕМ ФИКСАТОР
    },
    customAlert: (t, tx) => Core.openModal(t, `<div>${tx}</div><button class="sys-modal-btn primary" onclick="Core.closeModal()">OK</button>`),
    customPrompt: (t, tx, cb) => {
        Core.openModal(t, `<div>${tx}</div><input type="text" id="p-in" class="sys-modal-input"><button class="sys-modal-btn primary" id="p-ok">OK</button><button class="sys-modal-btn" onclick="Core.closeModal()">ОТМЕНА</button>`);
        document.getElementById('p-ok').onclick = () => { const v = document.getElementById('p-in').value; Core.closeModal(); cb(v); };
    }
};
// Запускаем датчик при старте
Core.initProximity();
    
window.boot_sequence = (id, pwd) => Core.boot(id, pwd);
// Слушаем, когда юзер пытается "сдать назад" через систему
window.addEventListener('popstate', (event) => {
    if (Core.activePeerId) {
        // Если мы в чате — закрываем его и остаемся в приложении
        Core.closeChat(false); // передаем false, чтоб не зациклить историю
    }
});
