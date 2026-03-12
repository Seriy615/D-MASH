// D-MASH SILENT // CORE ENGINE // SMOOTH UI, PAGINATION & ACCOUNT MGR
"use strict";

/*
================================================================
1. МОДУЛЬ ПОСТКВАНТОВОЙ КРИПТОГРАФИИ (WASM KYBER-768)
================================================================
Функции взаимодействия с С-библиотекой через WebAssembly.
*/

const KyberWasm = {
    // KyberWasm.init          - Привязка WASM-функций к JS-объекту
    init() {
        const M = window.KyberModule;
        if (!M) return false;
        // Принудительно вытягиваем функции в глобальный скоуп объекта
        this.f_keypair = M._wasm_keypair || M["_wasm_keypair"];
        this.f_enc = M._wasm_encapsulate || M["_wasm_encapsulate"];
        this.f_dec = M._wasm_decapsulate || M["_wasm_decapsulate"];
        
        if (!this.f_keypair || !this.f_enc || !this.f_dec) {
            console.error("[!] KyberWasm: Функции Си не найдены в модуле!");
            return false;
        }
        return true;
    },
    // KyberWasm.generateKeys  - Генерация пары ключей Kyber-768
    generateKeys() {
        const M = window.KyberModule;
        if (!this.f_keypair) this.init(); // Самодиагностика

        const pkPtr = M._malloc(1184);
        const skPtr = M._malloc(2400);
        const res = this.f_keypair(pkPtr, skPtr);
        
        const pk = new Uint8Array(M.HEAPU8.buffer, pkPtr, 1184).slice();
        const sk = new Uint8Array(M.HEAPU8.buffer, skPtr, 2400).slice();
        
        M._free(pkPtr); M._free(skPtr);
        return { pk, sk, success: res === 0 };
    },
    // KyberWasm.encapsulate   - Создание общего секрета (SS) для чужого PK
    encapsulate(peerPkBytes) {
        const M = window.KyberModule;
        // Юзаем ПРЯМОЙ вызов через M, а не через this
        const func = M._wasm_encapsulate || M["_wasm_encapsulate"];
        if (!func) throw new Error("WASM f_enc missing");

        const ctPtr = M._malloc(1088);
        const ssPtr = M._malloc(32);
        const pkPtr = M._malloc(1184);
        
        M.HEAPU8.set(peerPkBytes, pkPtr);
        const res = func(ctPtr, ssPtr, pkPtr);
        
        const ct = new Uint8Array(M.HEAPU8.buffer, ctPtr, 1088).slice();
        const ss = new Uint8Array(M.HEAPU8.buffer, ssPtr, 32).slice();
        
        M._free(ctPtr); M._free(ssPtr); M._free(pkPtr);
        return { ct, ss, success: res === 0 };
    },
    // KyberWasm.decapsulate   - Извлечение секрета из капсулы своим SK
    decapsulate(ctBytes, mySkBytes) {
        const M = window.KyberModule;
        const func = M._wasm_decapsulate || M["_wasm_decapsulate"];
        if (!func) throw new Error("WASM f_dec missing");

        const ssPtr = M._malloc(32);
        const ctPtr = M._malloc(1088);
        const skPtr = M._malloc(2400);
        
        M.HEAPU8.set(ctBytes, ctPtr);
        M.HEAPU8.set(mySkBytes, skPtr);
        const res = func(ssPtr, ctPtr, skPtr);
        
        const ss = new Uint8Array(M.HEAPU8.buffer, ssPtr, 32).slice();
        
        M._free(ssPtr); M._free(ctPtr); M._free(skPtr);
        return { ss, success: res === 0 };
    },
    // KyberWasm.shmon         - Локальное логирование модуля
    shmon: (t, m) => console.log(`%c[KyberWasm][${t}] %c${m}`, "color:cyan;font-weight:bold;", "color:white;")
};

// iceConfig               - Настройки STUN/TURN для обхода NAT
const iceConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { 
            urls: 'turn:85.198.64.183:3478', 
            username: 'dmash_turn', 
            credential: '&fV+CJ2_0l7Ji^EzWPf^#nRvbkIqe6' 
        }
    ],
    iceCandidatePoolSize: 10
};


const Core = {
    /*
    ================================================================
    2. КОНФИГУРАЦИЯ СЕТИ И СОСТОЯНИЯ (CORE STATE)
    ================================================================
    Объект Core и системные переменные.
    */
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
    gammaKeys: { master: null, sign: null, box: null },
    keys: { sign: null, box: null, pub_hex: null },
    isSyncing: false, chatOffset: 0, chatLimit: 50, isLoadingHistory: false,
    hex_lut: Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0')),
    peerConnection: null,
    callState: 'idle', // idle, calling, receiving, connected
    iceQueue: [],
    activeCallId: null,
    callTimer: null,
    callPeerId: null,
    callSeconds: 0,
    localStream: null,
    audioCtx: null, 
    currentCamera: 'user',
    isSpeakerOn: false,
    screenStream: null,

    /*
    ================================================================
    3. ЯДРО СИСТЕМЫ И АВТОРИЗАЦИЯ (BOOT & SESSION)
    ================================================================
    Запуск приложения, генерация мастер-ключей и выход.
    */
    // Core.boot               - Главная функция входа: Argon2id, генерация ключей и запуск
    async boot(identity, passphrase) {
        const statusEl = document.getElementById('gate-status-text');
        try {
            if (statusEl) statusEl.innerText = "КУЗНИЦА КЛЮЧЕЙ (1024 bit)...";
            
            // 1. Выжимаем 128 байт энтропии через Argon2id
            const result = await window.argon2.hash({
                pass: passphrase, salt: identity + "D_MASH_GAMMA_V1_STABLE",
                time: 3, mem: 65536, hashLen: 128, type: window.argon2.argon2id
            });
            const fullHash = result.hash;

            // 2. Распил 128-байтного выхлопа
            this.gammaKeys.master = fullHash.slice(0, 32);
            this.blindSalt = fullHash.slice(32, 64);
            const seedSign = fullHash.slice(64, 96);
            const seedBox = fullHash.slice(96, 128);

            // --- 3. ГЕНЕРАЦИЯ КЛЮЧЕЙ ---
            this.keys.sign = window.nacl.sign.keyPair.fromSeed(seedSign);
            this.keys.box = window.nacl.box.keyPair.fromSecretKey(seedBox);
            
    KyberWasm.init();
    const quantum = KyberWasm.generateKeys();

    if (quantum.success) {
        this.keys.kyber = { publicKey: quantum.pk, secretKey: quantum.sk };
        this.shmon("INFO", "WASM Kyber-768 пара готова.");
    } else {
        throw new Error("WASM Квантовая кузница выдала брак!");
    }

    // Формируем ID (1312 знаков)
    const edPubHex = this.bytesToHex(this.keys.sign.publicKey);
    const curvePubHex = this.bytesToHex(this.keys.box.publicKey);
    const kyberPubHex = this.bytesToHex(this.keys.kyber.publicKey);
    this.keys.pub_hex = edPubHex + curvePubHex + kyberPubHex;
            
            this.keys.server_id = edPubHex;
            this.activeIdentity = identity;
            this.shmon("INFO", `Система готова. ID: ${this.keys.server_id.substring(0,8)}`);

            // 5. Инициализация хранилища и запуск
            await Storage.initGamma(this.gammaKeys.master);
            await Storage.registerAccount(identity, this.keys.pub_hex);
            
            this.launchWorkspace();

        } catch (e) { 
            console.error(e);
            if (statusEl) statusEl.innerText = "ОШИБКА ЯДРА: " + e.message; 
        }
    },
    // Core.deriveRootKey      - (Удален повтор/Legacy) Генерация хеша пароля
    deriveRootKey: (id, pwd) => new Promise((res, rej) => {
        if (typeof window.argon2 === 'undefined') return rej(new Error("Argon2 missing"));
        window.argon2.hash({
            pass: `${id}::[SILENT_v11]_${pwd}`, salt: "D_MASH_SALT_STABLE_V11",
            time: 3, mem: 65536, hashLen: 64, parallelism: 2, type: window.argon2.argon2id
        }).then(r => res(r.hashHex)).catch(e => rej(e));
    }),
    // Core.launchWorkspace    - Отрисовка основного интерфейса после логина
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
    // Core.terminateSession   - Экстренное затирание ключей в RAM и выход в "калькулятор"
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
    // Core.initRyvokDetector  - Детектор физического рывка телефона (акселерометр)
    initRyvokDetector() {
        if (window.RYVOK_INITED) return;
        window.RYVOK_INITED = true;
        this.shmon("INFO", "Датчик на рывок активирован.");

        let lastX, lastY, lastZ;
        // Порог чувствительности (подбирается экспериментально, 18 - довольно резкий рывок)
        const THRESHOLD = 18; 

        window.addEventListener('devicemotion', (e) => {
            // Если флиплок вырублен в настройках или мы в звонке — не дергаемся
            if (localStorage.getItem('cfg_flip_off') === 'true' || this.callState !== 'idle') return;

            let accel = e.accelerationIncludingGravity;
            if (accel && lastX !== undefined) {
                let delta = Math.abs(lastX - accel.x) + Math.abs(lastY - accel.y) + Math.abs(lastZ - accel.z);

                if (delta > THRESHOLD) {
                    this.shmon("ERR", `[!!!] РЫВОК ОБНАРУЖЕН! ВЕКТОР: ${delta.toFixed(2)}. ЛИКВИДАЦИЯ!`);
                    this.terminateSession(); // Гасим приборы
                }
            }
            if (accel) {
                lastX = accel.x; lastY = accel.y; lastZ = accel.z;
            }
        }, { passive: true }); // Для производительности
    },
    // Core.initProximity      - Детектор переворота экрана вниз (Flip-Lock)
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
    /*
    ================================================================
    4. КРИПТОГРАФИЧЕСКИЙ ПРОТОКОЛ (GAMMA-V1 SILENT)
    ================================================================
    Многослойное шифрование: T-Ratchet, Kyber и подписи Ed25519.
    */
/**
     * АТОМНАЯ КУЗНИЦА КЛЮЧЕЙ (T-RATCHET MS EDITION)
     * Дискретность — 1 миллисекунда. Shift до 2^32.
     */
    async deriveFinalKey(staticShared, psk, epochShift, packetTS_MS) {
        // Применяем гигантский сдвиг к точному времени пакета
        const warpedTime = BigInt(packetTS_MS) + BigInt(epochShift);
        
        // Argon2id перемалывает точную миллисекунду
        const timeEntropy = await window.argon2.hash({
            pass: warpedTime.toString(),
            salt: psk.slice(0, 16), // Кусок PSK как соль
            time: 2, mem: 16384, hashLen: 32,
            type: window.argon2.argon2id
        });

        // Смешиваем каскад: SS + PSK + Argon2(ms + shift)
        const finalMaterial = new Uint8Array(staticShared.length + psk.length + 32);
        finalMaterial.set(staticShared);
        finalMaterial.set(psk, staticShared.length);
        finalMaterial.set(timeEntropy.hash, staticShared.length + psk.length);

        const digest = await crypto.subtle.digest('SHA-256', finalMaterial);
        return new Uint8Array(digest);
    },

    /**
     * ШИФРОВАНИЕ (V19.0 - АТОМНЫЙ БРОНЕКОНВЕРТ)
     */
    async encrypt(data, pid, forceHandshake = false) {
        const aliasL1 = await Storage.getAlias(pid, "L1");
        let secrets = await Storage.getBox('blind_secrets', aliasL1);
        let peerInfo = await Storage.getBox('blind_peers', aliasL1);

        if (!peerInfo) return null;

        // --- СТУПЕНЬ 1: SOS (Если нет Curve или форсируем) ---
        if (!peerInfo.curvePub || forceHandshake === "SOS") {
            this.shmon("WARN", "Шлю SOS (0x02)...");
            const sos = new Uint8Array(1 + 32 + 1184);
            sos[0] = 0x02;
            sos.set(this.keys.box.publicKey, 1);
            sos.set(this.keys.kyber.publicKey, 33);
            return this.bytesToHex(sos);
        }

        // --- СТУПЕНЬ 2: ECDH (Обмен Kyber-ключами) ---
        if (!secrets || !secrets.staticShared || forceHandshake === true) {
            this.shmon("CRYPTO", "Запуск ECDH-передачи...");
            const eph = window.nacl.box.keyPair();
            const nonce = window.nacl.randomBytes(24);
            const payload = {
                t: "pqc_init",
                k_pub: this.bytesToHex(this.keys.kyber.publicKey),
                c_pub: this.bytesToHex(this.keys.box.publicKey),
                data: data
            };
            const msgUint8 = new TextEncoder().encode(JSON.stringify(payload));
            const encrypted = window.nacl.box(msgUint8, nonce, this.hexToBytes(peerInfo.curvePub), eph.secretKey);
            const res = new Uint8Array(1 + 24 + 32 + encrypted.length);
            res[0] = 0x01; res.set(nonce, 1); res.set(eph.publicKey, 25); res.set(encrypted, 57);
            return this.bytesToHex(res);
        }

        // --- СТУПЕНЬ 3: АТОМНЫЙ T-RATCHET (0x00) ---
        this.shmon("CRYPTO", `Атомная упаковка малявы (1ms) для ${pid.substring(0,8)}`);
        
        const ts = Date.now(); // Точные миллисекунды
        const ss = this.hexToBytes(secrets.staticShared);
        const psk = this.hexToBytes(secrets.psk);

        // 1. Вычисляем уникальный ключ на эту миллисекунду
        const finalKey = await this.deriveFinalKey(ss, psk, secrets.epochShift, ts);

        // 2. Внутренний слой
        const innerNonce = window.nacl.randomBytes(24);
        const msgStr = typeof data === 'object' ? JSON.stringify(data) : data;
        const innerCiphertext = window.nacl.secretbox(new TextEncoder().encode(msgStr), innerNonce, finalKey);

        // 3. Подпись Ed25519 (TS + InnerNonce + InnerCipher)
        const signMaterial = new Uint8Array(8 + innerNonce.length + innerCiphertext.length);
        const signView = new DataView(signMaterial.buffer);
        const low = ts % 4294967296; const high = Math.floor(ts / 4294967296);
        signView.setUint32(0, low, true); signView.setUint32(4, high, true);
        signMaterial.set(innerNonce, 8);
        signMaterial.set(innerCiphertext, 32);
        const signature = window.nacl.sign.detached(signMaterial, this.keys.sign.secretKey);

        // 4. Внешний конверт
        const envelope = new Uint8Array(8 + 64 + 24 + innerCiphertext.length);
        const envView = new DataView(envelope.buffer);
        envView.setUint32(0, low, true); envView.setUint32(4, high, true);
        envelope.set(signature, 8);
        envelope.set(innerNonce, 72);
        envelope.set(innerCiphertext, 96);

        // 5. Внешний шифр KDF(SS + PSK)
        const outerKeyMat = new Uint8Array(ss.length + psk.length);
        outerKeyMat.set(ss); outerKeyMat.set(psk, ss.length);
        const outerKey = new Uint8Array(await crypto.subtle.digest('SHA-256', outerKeyMat));
        const outerNonce = window.nacl.randomBytes(24);
        const outerCiphertext = window.nacl.secretbox(envelope, outerNonce, outerKey);

        const pkt = new Uint8Array(1 + 24 + outerCiphertext.length);
        pkt[0] = 0x00; pkt.set(outerNonce, 1); pkt.set(outerCiphertext, 25);
        return this.bytesToHex(pkt);
    },

    /**
     * ДЕШИФРОВАНИЕ (V19.0 - АТОМНЫЙ ПРИЕМ)
     */
    async decrypt(hb, pid) {
        const raw = this.hexToBytes(hb);
        const type = raw[0];
        const aliasL1 = await Storage.getAlias(pid, "L1");
        let secrets = await Storage.getBox('blind_secrets', aliasL1);

        if (type === 0x02) { // Принят SOS
            this.shmon("WARN", `Тихая ротация: SOS от ${pid.substring(0,8)}`);
            const hisCurve = this.bytesToHex(raw.slice(1, 33));
            const hisKyber = this.bytesToHex(raw.slice(33, 1217));
            let peer = await Storage.getBox('blind_peers', aliasL1) || { id: pid, name: `Peer-${pid.substring(0,4)}` };
            peer.curvePub = hisCurve; peer.kyberPub = hisKyber;
            await Storage.putBox('blind_peers', { alias: aliasL1, data: peer });
            await this.sendMessage({ type: "sys", content: "sync" }, true, pid);
            return null;
        }

        if (type === 0x01) { // Принят ECDH
            this.shmon("CRYPTO", "Вскрытие 0x01 оболочки...");
            const nonce = raw.slice(1, 25); const ephPub = raw.slice(25, 57);
            const opened = window.nacl.box.open(raw.slice(57), nonce, ephPub, this.keys.box.secretKey);
            if (opened) {
                const payload = JSON.parse(new TextDecoder().decode(opened));
                let peer = await Storage.getBox('blind_peers', aliasL1) || { id: pid, name: `Peer-${pid.substring(0,4)}` };
                peer.curvePub = payload.c_pub; peer.kyberPub = payload.k_pub;
                await Storage.putBox('blind_peers', { alias: aliasL1, data: peer });
                KyberWasm.init();
                const k = KyberWasm.encapsulate(this.hexToBytes(payload.k_pub));
                // НОВЫЙ ШИФТ: в миллисекундах до +-2^32
                const newPSK = window.nacl.randomBytes(32);
                const newShift = Math.floor(Math.random() * 4294967296) - 2147483648; 
                await Storage.putBox('blind_secrets', { 
                    alias: aliasL1, 
                    data: { staticShared: this.bytesToHex(k.ss), psk: this.bytesToHex(newPSK), epochShift: newShift, msgCount: 0 } 
                });
                await this.sendKyberFinal(pid, k.ct, newPSK, newShift);
                if (this.activePeerId === pid) this.selectPeer(pid);
                return null;
            }
        }

        if (type === 0x03) { // Финал квантового моста
            this.shmon("CRYPTO", "Финализация квантового моста...");
            const encapsulated = raw.slice(1, 1089); const ss = (KyberWasm.decapsulate(encapsulated, this.keys.kyber.secretKey)).ss;
            const opened = window.nacl.secretbox.open(raw.slice(1113), raw.slice(1089, 1113), ss);
            if (opened) {
                const final = JSON.parse(new TextDecoder().decode(opened));
                await Storage.putBox('blind_secrets', {
                    alias: aliasL1,
                    data: { staticShared: this.bytesToHex(ss), psk: final.psk, epochShift: final.shift, msgCount: 0 }
                });
                this.shmon("INFO", "КВАНТОВЫЙ КАНАЛ УСТАНОВЛЕН!");
                if (this.activePeerId === pid) this.selectPeer(pid);
                setTimeout(() => this.sendMessage("🤝 Квантовый мост наведен. Базар открыт.", false, pid), 500);
                return null;
            }
        }

        if (type === 0x00) { // Атомный T-Ratchet
            if (!secrets || !secrets.staticShared) { await this.sendEmergencyHandshake(pid); return null; }
            const ss = this.hexToBytes(secrets.staticShared); const psk = this.hexToBytes(secrets.psk);

            // 1. Внешний слой
            const outerKeyMat = new Uint8Array(ss.length + psk.length);
            outerKeyMat.set(ss); outerKeyMat.set(psk, ss.length);
            const outerKey = new Uint8Array(await crypto.subtle.digest('SHA-256', outerKeyMat));
            const envelope = window.nacl.secretbox.open(raw.slice(25), raw.slice(1, 25), outerKey);
            if (!envelope) return null;

            // 2. Разбор (читаем прибитые миллисекунды)
            const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
            const low = view.getUint32(0, true); const high = view.getUint32(4, true);
            const ts = high * 4294967296 + low;

            // 3. Проверка подписи
            const signature = envelope.slice(8, 72);
            const innerNonce = envelope.slice(72, 96);
            const innerCipher = envelope.slice(96);
            const signMat = new Uint8Array(8 + innerNonce.length + innerCipher.length);
            const signView = new DataView(signMat.buffer);
            signView.setUint32(0, low, true); signView.setUint32(4, high, true);
            signMat.set(innerNonce, 8); signMat.set(innerCipher, 32);
            
            if (!window.nacl.sign.detached.verify(signMat, signature, this.hexToBytes(pid))) {
                this.shmon("ERR", "Подпись Ed25519 не сошлась!"); return null;
            }

            // 4. Внутренний слой (Argon2 на ts из пакета)
            const finalKey = await this.deriveFinalKey(ss, psk, secrets.epochShift, ts);
            const decrypted = window.nacl.secretbox.open(innerCipher, innerNonce, finalKey);
            if (decrypted) return new TextDecoder().decode(decrypted);
        }
        return null;
    },
    // Core.sendKyberFinal     - Завершение квантового рукопожатия (Тип 0x03)
    async sendKyberFinal(pid, capsule, psk, shift) {
        const nonce = window.nacl.randomBytes(24);
        const aliasL1 = await Storage.getAlias(pid, "L1");
        const secrets = await Storage.getBox('blind_secrets', aliasL1);
        
        const payload = { psk: this.bytesToHex(psk), shift: shift, data: "🤝 Квантовый мост наведен" };
        const ss = this.hexToBytes(secrets.staticShared);
        const encrypted = window.nacl.secretbox(new TextEncoder().encode(JSON.stringify(payload)), nonce, ss);

        const pkt = new Uint8Array(1 + 1088 + 24 + encrypted.length);
        pkt[0] = 0x03;
        pkt.set(capsule, 1);
        pkt.set(nonce, 1089);
        pkt.set(encrypted, 1113);
        
        const blob = this.bytesToHex(pkt);
        const sig = window.nacl.sign.detached(this.hexToBytes(blob), this.keys.sign.secretKey);
        
        this.shmon("INFO", `Сброс квантового финала для ${pid.substring(0,8)}...`);
        await fetch('../api/pidorskiy_api.php', {
            method: 'POST', 
            headers: { 'X-DMASH-AGENT': 'V1Silent-Node', 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                r_hash: await this.fastHash(pid), // СТРОГО pid из аргументов!
                s_pub: this.keys.server_id,
                sig: this.bytesToHex(sig), 
                blob: blob
            })
        });
        
        setTimeout(() => this.syncNetwork(), 500);
    },
    // Core.sendEmergencyHandshake - Отправка SOS-пакета при потере синхронизации
    async sendEmergencyHandshake(pid) {
        if (this._lastHandshakeTime && Date.now() - this._lastHandshakeTime < 5000) return;
        this._lastHandshakeTime = Date.now();
    
        // Просто шлем SOS в фоне, юзер не должен видеть паники
        this.shmon("WARN", "Тихий перезапуск линии...");
        await this.sendMessage({ type: "sys", content: "re-sync" }, "SOS");
    },
    // Core.fastHash           - Обертка над SHA-256
    fastHash: async (m) => {
            const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(m));
            return Array.from(new Uint8Array(b)).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    // Core.deriveSharedKey       - Генерация статического ключа между двумя ID (Legacy/Fallback)
    deriveSharedKey: async (pid) => Core.hexToBytes(await Core.fastHash([Core.keys.pub_hex, pid].sort().join('') + "STATIC_SHARED_SECRET_V11")),
    // Core.initHandshake         - Принудительное обновление PSK и временного сдвига (Epoch Shift) 
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
    //                              через воип-канал, если база поплыла.
    /*
    ================================================================
    5. ТРАНСПОРТНЫЙ СЛОЙ И СЕТЬ (NETWORKING)
    ================================================================
    Взаимодействие с API и доставка данных.
    */    
    // Core.sendMessage        - Отправка данных на сервер (с поддержкой VOIP и Silent режимов)
    async sendMessage(c = null, forceHandshake = false, targetPid = null) {
        if (this.isRecordingCircle && !c) { this.cancelRecording = false; this.stopCircleUI(); return; }
        
        // ВАЖНО: Определяем, кому реально летит малява
        const pid = targetPid || this.activePeerId;
        if (!pid) return;

        let p = c; 
        const inp = document.getElementById('msgInput');
        if (!p) { p = inp.value.trim(); if (!p) return; }

        const isVoip = typeof p === 'object' && p.type?.startsWith('voip_');
        const isSilent = isVoip && (p.type === 'voip_ice' || p.type === 'voip_answer' || p.type === 'voip_hangup');

        try {
            const dataToEncrypt = (typeof p === 'object') ? JSON.stringify(p) : p;
            
            // Передаем pid в encrypt, чтобы он взял правильные ключи из базы
            const blob = await this.encrypt(dataToEncrypt, pid, forceHandshake);
            if (!blob) return;

            const sig = window.nacl.sign.detached(this.hexToBytes(blob), this.keys.sign.secretKey);
            
            await fetch('../api/pidorskiy_api.php', {
                method: 'POST', 
                headers: { 'X-DMASH-AGENT': 'V1Silent-Node', 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    r_hash: await this.fastHash(pid), // Хешируем именно получателя!
                    s_pub: this.keys.server_id,
                    sig: this.bytesToHex(sig),
                    blob: blob,
                    is_voip: isVoip,
                    silent: isSilent 
                })
            });

            // Сохраняем и обновляем UI только если это не системный сигнал и это текущий открытый чат
            if (!isVoip && pid === this.activePeerId) {
                const seqId = await Storage.saveMessageGamma(pid, p, false, true);
                const log = document.getElementById('log');
                if (log) {
                    if (log.innerHTML.includes("НЕТ СООБЩЕНИЙ") || log.innerHTML.includes("КАНАЛ НЕ ПОДГОТОВЛЕН")) log.innerHTML = "";
                    log.insertAdjacentHTML('beforeend', this.buildMsgHtml({ text: p, inbound: false }, Date.now(), seqId));
                    log.scrollTop = log.scrollHeight;
                }
                if (inp && !c) { inp.value = ""; inp.style.height = '45px'; }
            }
        } catch (e) { this.shmon("ERR", "Send fail", e); }
    },
    // Core.syncNetwork        - Опрос сервера (PULL), получение и сортировка новых маляв
    async syncNetwork() {
        if (this.isSyncing) return; 
        this.isSyncing = true;
        try {
            const myServerId = this.keys.server_id; // Это наши 64 знака Ed
            const h = await this.fastHash(myServerId);
            const ts = Math.floor(Date.now() / 1000).toString();
            
            // Подпись для PULL-запроса
            const mts = new Uint8Array(this.hexToBytes(myServerId).length + new TextEncoder().encode(ts).length);
            mts.set(this.hexToBytes(myServerId));
            mts.set(new TextEncoder().encode(ts), this.hexToBytes(myServerId).length);
            const sig = window.nacl.sign.detached(mts, this.keys.sign.secretKey);
            
            const rnd = Math.random().toString(36).substring(7);
            const res = await fetch(`../api/pidorskiy_api.php?h=${h}&pub=${myServerId}&ts=${ts}&sig=${this.bytesToHex(sig)}&_=${rnd}`, { 
                headers: { 'X-DMASH-AGENT': 'V1Silent-Node' }, cache: 'no-store'
            });

            const data = await res.json();
            
            // --- ВОТ ТУТ МЫ ЛЕЧИМ ПАДЕНИЕ ---
            if (data && data.length > 0) {
                let needRefresh = false;
                for (let env of data) {
                    const sid = env.s_pub; // ID отправителя (64 знака)
                    
                    // Проверяем, знаем ли мы этого пацана
                    const aliasL1 = await Storage.getAlias(sid, "L1");
                    let peer = await Storage.getBox('blind_peers', aliasL1);
                    
                    if (!peer) {
                        this.shmon("WARN", `Малява от незнакомца: ${sid.substring(0,8)}. Создаю запись...`);
                        await Storage.savePeerGamma(sid, `New-${sid.substring(0,4)}`);
                        needRefresh = true;
                    }

                    // ВАЖНО: Дешифруем блоб. Если тут упадет — весь sync ляжет.
                    // Оборачиваем в try-catch внутри цикла!
                    try {
                        const dec = await this.decrypt(env.blob, sid);
                        if (dec) {
                            this.shmon("INFO", `Малява от ${sid.substring(0,8)} вскрыта успешно.`);
                            
                            let msgData;
                            try { msgData = JSON.parse(dec); } catch(e) { msgData = dec; }

                            if (typeof msgData === 'object' && msgData.type?.startsWith('voip_')) {
                                this.handleVoipSignal(msgData, sid);
                            } else {
                                const isCurrent = (this.activePeerId === sid);
                                await Storage.saveMessageGamma(sid, dec, true, isCurrent);
                                if (isCurrent) {
                                    // Прямой впрыск в лог, если хата открыта
                                    const log = document.getElementById('log');
                                    if (log) {
                                        log.insertAdjacentHTML('beforeend', this.buildMsgHtml({ text: dec, inbound: true }, Date.now()));
                                        log.scrollTop = log.scrollHeight;
                                    }
                                } else {
                                    needRefresh = true;
                                }
                            }
                        }
                    } catch (e) {
                        this.shmon("ERR", `Не удалось вскрыть пакет от ${sid.substring(0,8)}:`, e);
                    }
                }
                if (needRefresh) await this.renderPeers();
            }
        } catch (e) { 
            this.shmon("WARN", "Sync failed: " + e.message); 
        }
        this.isSyncing = false;
    },
    /*
    ================================================================
    6. МЕНЕДЖЕР КОНТАКТОВ И ЧАТОВ (PEER MANAGEMENT)
    ================================================================
    Работа со списком собеседников и историей.
    */
    // Core.renderPeers        - Отрисовка списка контактов в сайдбаре
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
    // Core.selectPeer         - Открытие чата, проверка готовности квантового канала
    async selectPeer(id) {
        this.shmon("INFO", `Открываю хату: ${id.substring(0,8)}`);
        try {
            this.activePeerId = id;
            const aliasL1 = await Storage.getAlias(id, "L1");
            const peer = await Storage.getBox('blind_peers', aliasL1);
            const secrets = await Storage.getBox('blind_secrets', aliasL1);

            // 1. Гасим маяк непрочитанных
            if (peer && peer.unread) {
                peer.unread = false;
                await Storage.putBox('blind_peers', { alias: aliasL1, data: peer });
            }

            // 3. РИСУЕМ ХЕДЕР (С копированием ID)
            const fullIdToCopy = peer ? (peer.id + (peer.curvePub || '') + (peer.kyberPub || '')) : id;
            document.getElementById('chat-header').innerHTML = `
                <button id="back-btn" class="action-btn" onclick="Core.closeChat()">←</button>
                <div style="flex-grow:1; margin-left:10px; cursor:pointer;" onclick="Core.copyPeerId('${fullIdToCopy}')">
                    <b id="chat-title">${peer ? peer.name.toUpperCase() : id.substring(0,8)}</b><br>
                    <small style="font-size:0.6rem; color:#555;">ID: ${id.substring(0,8)}... (КОПИРОВАТЬ)</small>
                </div>
                <div style="display:flex; gap:10px;">
                    <button class="action-btn" id="voip-btn" onclick="Core.initVoip()" style="${secrets ? '' : 'display:none'}">📞</button>
                    <button class="action-btn" onclick="Core.renameCurrent()">✎</button>
                </div>
            `;
            
            if (document.getElementById('main-grid')) document.getElementById('main-grid').classList.add('chat-active');
            
            const log = document.getElementById('log');
            log.innerHTML = "";
            const inputArea = document.getElementById('input-area');

            // 4. ЗАГРУЗКА ИСТОРИИ И ПРОВЕРКА КЛЮЧЕЙ
            const msgs = await Storage.loadMessagesGamma(id, 50, 0);
            
            if (!secrets || !secrets.staticShared) {
                // КЛЮЧЕЙ НЕТ — ПОКАЗЫВАЕМ КНОПКУ ХЕНДШЕЙКА
                log.innerHTML = `
                    <div id="init-zone" style="text-align:center; margin-top:100px; padding:20px;">
                        <div style="color:var(--main); font-size:2rem; margin-bottom:10px;">⚛️</div>
                        <div style="color:#555; margin-bottom:20px; font-size:0.8rem;">КВАНТОВЫЙ КАНАЛ НЕ НАСТРОЕН</div>
                        <button class="sys-modal-btn primary" style="width:220px; padding:15px;" onclick="Core.sendMessage('🤝 Запрос на квантовый мост', 'SOS')">
                            ОБМЕНЯТЬСЯ КЛЮЧАМИ
                        </button>
                    </div>`;
                if (inputArea) inputArea.style.display = 'none';
            } else {
                // КЛЮЧИ ЕСТЬ — ВКЛЮЧАЕМ ОБЫЧНЫЙ ВВОД
                if (inputArea) inputArea.style.display = 'flex';
                if (msgs.length > 0) {
                    msgs.forEach(m => {
                        const html = this.buildMsgHtml(m, m.ts, m.id);
                        if (html) log.insertAdjacentHTML('beforeend', html);
                    });
                } else {
                    log.innerHTML = '<div style="text-align:center; color:#333; margin-top:50px;">БАЗАР ПУСТ</div>';
                }
            }

            await this.renderPeers();
            setTimeout(() => { log.scrollTop = log.scrollHeight; }, 100);
            if (window.history.state?.view !== 'chat') window.history.pushState({ view: 'chat' }, "");

        } catch (e) { this.shmon("ERR", "Сбой открытия чата", e); }
    },
    // Core.loadChat           - Пагинация истории из IndexedDB (Gamma Storage)
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
    // Core.addPeerFlow        - Логика добавления нового кента в базу
    async addPeerFlow(id) {
        // 1. ЧИСТИМ СТРОКУ (убираем пробелы, переносы и всё кроме HEX)
        const cleanId = id.trim().replace(/[^a-f0-9]/gi, '');
        
        this.shmon("INFO", `Попытка добавить ID. Длина: ${cleanId.length}`);

        // 2. ЖЕСТКАЯ ПРОВЕРКА НА 64 ЗНАКА
        if (cleanId.length !== 64) {
            return this.customAlert("ОШИБКА", `ID не по масти. Получено ${cleanId.length} знаков, а надо ровно 64.`);
        }

        const aliasL1 = await Storage.getAlias(cleanId, "L1");
        
        // Проверка на дубли
        const existing = await Storage.getBox('blind_peers', aliasL1);
        if (existing) {
            return this.customAlert("ИНФО", "Этот пацан уже прописан в хате.");
        }

        this.customPrompt("ПСЕВДОНИМ", "Как назовем кента?", async (name) => {
            const alias = name || `Peer-${cleanId.substring(0, 4)}`;
            
            await Storage.putBox('blind_peers', { 
                alias: aliasL1, 
                data: { 
                    id: cleanId, 
                    curvePub: null, 
                    kyberPub: null, 
                    name: alias, 
                    last_ts: Date.now(), 
                    unread: false, 
                    securityAlert: false 
                } 
            });
            
            this.shmon("INFO", `Кент ${alias} добавлен в базу.`);
            await this.renderPeers();
        });
    },
    // Core.addPeerPrompt      - Вызов окна для ручного ввода ID
    addPeerPrompt: function() {
        Core.customPrompt("ДОБАВИТЬ ВРУЧНУЮ", "Вставь ID (HEX, 64 знака):", (id) => {
            if (id) Core.addPeerFlow(id.trim());
        });
    },
    // Core.renameCurrent      - Смена псевдонима собеседника
    renameCurrent: async function() {
        if (!this.activePeerId) return;
        const aliasL1 = await Storage.getAlias(this.activePeerId, "L1");
        const peer = await Storage.getBox('blind_peers', aliasL1);
        if (!peer) return;

        this.customPrompt("ПСЕВДОНИМ", `НОВОЕ ИМЯ ДЛЯ ${peer.name}:`, async (n) => {
            if (n && n.trim()) { 
                peer.name = n.trim();
                await Storage.putBox('blind_peers', { alias: aliasL1, data: peer }); 
                await this.renderPeers(); 
                document.getElementById('chat-title').innerText = n.trim().toUpperCase(); 
            }
        });
    },
    // Core.deleteChatFlow     - Полное удаление переписки и ключей кента
    deleteChatFlow: function(id, name) {
        Core.customConfirm("СНОС ЧАТА", `Ликвидировать всю переписку с ${name}?`, async () => {
            await Storage.deleteChatGamma(id);
            if (Core.activePeerId === id) Core.closeChat();
            await Core.renderPeers();
            Core.customAlert("ГОТОВО", "Хата зачищена.");
        });
    },
    // Core.deleteMessageFlow  - Удаление конкретной малявы (локально)
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
    // Core.closeChat          - Закрытие окна чата
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
    /*
    ================================================================
    7. МУЛЬТИМЕДИА И ФАЙЛЫ (MEDIA ENGINE)
    ================================================================
    Голосовые, кружки, фото и шифрованные файлы.
    */
    // Core.uiAttach           - Вызов диалога выбора файла
    uiAttach: () => document.getElementById('file-input').click(),
    // Core.handleFileSelect   - Чтение файла и отправка в шифратор
    handleFileSelect: (ev) => {
        const f = ev.target.files[0]; if (!f) return;
        const r = new FileReader(); r.onload = (e) => {
            let t = f.type.startsWith('image/') ? 'image' : (f.type.startsWith('video/') ? 'video' : 'file');
            Core.sendMessage({ type: t, name: f.name, data: e.target.result });
        }; r.readAsDataURL(f);
    },
    // Core.uiVoice            - Запись и отправка голосового сообщения
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
    // Core.uiCircle           - Логика записи видео-кружка (с выбором камеры)
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
    // Core.startCircleRecording - Инициализация захвата видео 400x400
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
    // Core.stopCircleUI       - Остановка превью и записи кружка
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
    // Core.killAllMedia       - Жесткая остановка всех камер и микрофонов (освобождение ресурсов)
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
    // Core.decryptMedia       - Ленивая расшифровка медиа-контента при клике
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
    // Core.renderStub         - Отрисовка заглушки для еще не расшифрованного файла
    renderStub(data, id) {
        const label = {
            'video_note': 'КРУЖОК',
            'video': 'ВИДЕО',
            'image': 'ФОТО',
            'voice': 'ГОЛОСОВОЕ',
            'file': 'ФАЙЛ'
        }[data.type] || 'ДАННЫЕ';

        if (data.type === 'video_note') {
            return `
                <div class="media-stub" id="stub-${id}">
                    <div class="circle-note-container"><video src=""></video></div>
                    <button class="sys-modal-btn primary" style="padding:5px; font-size:0.6rem; margin-top:8px;" 
                        onclick='Core.decryptMedia("${id}", ${JSON.stringify(data).replace(/"/g, '&quot;')})'>РАСШИФРОВАТЬ КРУЖОК</button>
                </div>`;
        }

        return `
            <div class="media-stub" id="stub-${id}">
                <div style="color:var(--main); font-size:0.7rem; margin-bottom:5px;">[ ${label}: ${this.escapeHtml(data.name || 'file')} ]</div>
                <button class="sys-modal-btn primary" style="padding:5px; font-size:0.6rem;" 
                    onclick='Core.decryptMedia("${id}", ${JSON.stringify(data).replace(/"/g, '&quot;')})'>РАСШИФРОВАТЬ</button>
            </div>`;
    },
    // Core.resetCircleUI         - Сброс интерфейса записи кружка (возврат кнопок в дефолт)
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
    /*
    ================================================================
    8. VOIP: ЗВОНКИ И ТРАНСЛЯЦИИ (WEBRTC)
    ================================================================
    Защищенная аудио/видео связь.
    */
    // Core.initVoip           - Инициализация исходящего вызова (Offer)
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
    // Core.handleVoipSignal   - Роутер сигналов (Offer/Answer/ICE/Hangup)
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
    // Core.setupPC            - Создание PeerConnection и настройка треков
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
    // Core.endCall            - Завершение звонка и очистка UI
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
    // Core.showIncomingCall   - Модальное окно входящего вызова
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
    // Core.updateCallUI       - Смена состояний звонка на экране (Таймер, Статус)
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
    // Core.startTimer         - Секундомер звонка
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
    // Core.sendVoipSignal     - Хелпер отправки сигнальных данных
    sendVoipSignal: async function(data) {
        if (!Core.callPeerId) return;
        // Юзаем стандартный sendMessage, но подменяем временный ID, если надо
        const oldActive = Core.activePeerId;
        Core.activePeerId = Core.callPeerId;
        await Core.sendMessage(data);
        Core.activePeerId = oldActive;
    },    
    // Core.switchCamera       - Переключение между фронталкой и основой во время боя
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
    // Core.toggleMic/Video    - Мут микрофона или камеры
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
    // Core.toggleSpeaker      - Переключение звука (динамик / ухо)
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
    // Core.applyAudioRoute    - Техническая реализация вывода звука
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
    // Core.shareScreen        - Демонстрация экрана
    shareScreen: async function() {
        try {
            Core.screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
            const screenTrack = Core.screenStream.getVideoTracks()[0];
            const sender = Core.peerConnection.getSenders().find(s => s.track.kind === 'video');
            sender.replaceTrack(screenTrack);
            screenTrack.onended = () => { /* Вернуть камеру обратно */ };
        } catch (e) { console.log("Screen share cancelled"); }
    },
    // Core.playSound          - Звуковая индикация событий звонка
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
    // Core.processIceQueue       - Прокачка очереди ICE-кандидатов (важно, если сеть тупит и кандидаты прилетели раньше, чем создался)
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
    /*
    ================================================================
    9. БЕЗОПАСНОСТЬ И HARDWARE LOCK (KNOX/BIOMETRICS)
    ================================================================
    Привязка к биометрии и аппаратным ключам Knox.
    */
    // Core.setupBiometrics    - Привязка аккаунта к WebAuthn/Passkeys (Knox PRF)
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
    // Core.biometricLogin     - Вход в аккаунт через палец/лицо без ввода пароля
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
    // Core.encryptWithHardware - Шифрование данных ключом, вытянутым из железа Knox
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
    // Core.decryptWithHardware - Дешифрование через аппаратный ключ
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
    // Core.setupLazyLogin     - Сохранение зашифрованного пароля для быстрого входа
    setupLazyLogin: function() {
        Core.customPrompt("БЕСПАРОЛЬНЫЙ ВХОД", "Введи КЛЮЧ ДОСТУПА для сохранения:", async (key) => {
            if (!key) return;
            const encryptedKey = await Core.encryptForBio(key); // Тоже шифруем Мастер-кодом
            await Storage.updateAccountAuth(Core.activeIdentity, { lazy: true, lazy_key: encryptedKey });
            Core.customAlert("ГОТОВО", "Теперь вход для этого акка — в один тап.");
        });
    },
    // Core.lazyLogin          - Вход в один тап через Master PIN
    lazyLogin: async function(id) {
        const acc = await Storage.getRegistryAccount(id);
        if (!acc || !acc.lazy_key) return false;
        const key = await Core.decryptFromBio(acc.lazy_key);
        if (key) { await Core.boot(id, key); return true; }
        return false;
    },
    // Core.encryptForBio      - Шифрование пароля для "ленивого" входа
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
    // Core.toggleFlipper         - Переключатель Flip-Lock (блокировка при перевороте экрана)
    toggleFlipper: function() {
        const cur = localStorage.getItem('cfg_flip_off') === 'true';
        localStorage.setItem('cfg_flip_off', !cur);
        Core.openSettings();
    },
    // Core.toggleAccountList     - Скрытие/показ списка аккаунтов на стартовом экране
    toggleAccountList: function() {
        const cur = localStorage.getItem('cfg_hide_list') === 'true';
        localStorage.setItem('cfg_hide_list', !cur);
        Core.openSettings();
    },
    // Core.changePinFlow         - Интерфейс смены Master-кода или Wipe-кода (самоликвидация)
    changePinFlow: function(type) {
        Core.customPrompt(type === 'M' ? "MASTER-КОД" : "WIPE-КОД", "Введите новый цифровой код:", async (v) => {
            if (v && !isNaN(v)) { 
                if (type === 'M') await sys.changeMasterPin(v); else await sys.changeWipePin(v);
                Core.customAlert("УСПЕХ", "Код изменен");
            }
        });
    },
    // Core.removeAccountFlow     - Полная очистка: удаление акка из реестра + физический снос БД сообщений
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
    /*
    ================================================================
    10. СЕРВИСНЫЕ ФУНКЦИИ И QR (HELPERS)
    ================================================================
    Вспомогательные инструменты и UI-компоненты.
    */
    // Core.openSettings       - Главное меню настроек
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
    // Core.openAccountManager - Реестр всех аккаунтов на устройстве
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
    //resetAccountAuthFlow     - Удаление аккаунта из реестра
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
    // Core.setupTelegram      - Привязка уведомлений через бота
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
    // Core.openScanner        - Запуск сканера QR-кодов
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
    // Core.closeScanner       - Остановка камеры сканера
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
    // Core.showMyQR           - Показ своего ID в виде QR
    showMyQR: function() {
        // 1. ПРОВЕРКА КЛЮЧЕЙ
        // Убедимся, что у нас есть ServerID (Ed25519)
        const myId = this.keys.server_id || (this.keys.sign ? this.bytesToHex(this.keys.sign.publicKey) : null);
        
        if (!myId) {
            this.shmon("ERR", "Ключи не найдены. QR невозможен.");
            this.customAlert("ОШИБКА", "Система не инициализирована. Перезайди в хату.");
            return;
        }

        this.shmon("INFO", "Генерация QR для ID: " + myId.substring(0,8));

        const c = `
            <div style="text-align:center;">
                <div id="qr-target" style="background:#fff; padding:15px; margin:10px auto; display:inline-block; border-radius:8px; box-shadow: 0 0 20px rgba(0,255,65,0.3);"></div>
                <div style="font-size:0.65rem; color:#0f0; margin-bottom:15px; word-break:break-all; font-family:monospace; background:#111; padding:10px; border:1px solid #333;">
                    ${myId.substring(0,32)}<br>${myId.substring(32)}
                </div>
                <div style="display:flex; gap:10px;">
                    <button class="sys-modal-btn primary" style="flex:1;" onclick="Core.copyMyId()">КОПИРОВАТЬ</button>
                    <button class="sys-modal-btn" style="flex:1;" onclick="Core.closeModal()">ЗАКРЫТЬ</button>
                </div>
            </div>
        `;
        
        this.openModal("МОЙ ПУБЛИЧНЫЙ ID", c); 
        
        // 2. РЕНДЕР С ЗАДЕРЖКОЙ
    setTimeout(() => {
        const container = document.getElementById("qr-target");
        if (!container) return;

        try {
            if (typeof QRCode !== 'undefined') {
                new QRCode(container, { 
                    text: myId, 
                    width: 200, 
                    height: 200,
                    colorDark : "#000000",
                    colorLight : "#ffffff",
                    correctLevel : QRCode.CorrectLevel.M 
                    });
                } else {
                    container.innerHTML = "<b style='color:red;'>ОШИБКА: ЛИБА QR НЕ ЗАГРУЖЕНА</b>";
                }
            } catch (e) {
                this.shmon("ERR", "QR Render Fail", e);
            }
        }, 200); // Даем модалке время открыться
    },
    // Core.copyMyId           - Копирование своего 64-значного ID
    copyMyId: function() {
        // Берем строго ServerID (64 знака Ed25519)
        const myPublicId = this.keys.server_id; 
        
        if (!myPublicId) {
            this.shmon("ERR", "Ксива не готова!");
            return;
        }

        navigator.clipboard.writeText(myPublicId).then(() => {
            this.customAlert("УСПЕХ", "Твой публичный ID (64 знака) скопирован.");
        }).catch(() => {
            // Fallback если браузер запретил буфер обмена
            this.customPrompt("ТВОЙ ID", "Скопируй вручную:", () => {}, myPublicId);
        });
    },
    // Core.copyPeerId         - Копирование ID собеседника
    copyPeerId: function(fullId) {
        // Нам нужно только начало (Ed25519), остальное — для внутреннего пользования
        const shortId = fullId.substring(0, 64);
        
        if (!shortId || shortId.length !== 64) {
            this.shmon("ERR", "Попытка копирования кривого ID");
            return;
        }

        navigator.clipboard.writeText(shortId).then(() => {
            this.customAlert("УСПЕХ", "Публичный ID кента (64 знака) скопирован.");
        }).catch(() => {
            // Если браузер залупился на буфер обмена — выводим в промпт
            this.customPrompt("ID КЕНТА", "Копируй вручную:", () => {}, shortId);
        });
    },
    // Core.openModal/closeModal - Базовый движок модальных окон
    openModal: (t, h) => { const m = document.getElementById('sys-modal'); m.innerHTML = `<div class="sys-modal-box"><h4>${t}</h4>${h}</div>`; m.style.display = 'flex'; },
    
    closeModal: function() {
        const m = document.getElementById('sys-modal');
        if (m) {
            m.style.display = 'none';
            m.innerHTML = "";
        }
        // ВЫЗЫВАЕМ ФИКСАТОР
    },
    // Core.customAlert/Prompt/Confirm - Кастомные диалоги в стиле системы
    customAlert: (t, tx) => Core.openModal(t, `<div>${tx}</div><button class="sys-modal-btn primary" onclick="Core.closeModal()">OK</button>`),
    
    customPrompt: (t, tx, cb) => {
        Core.openModal(t, `<div>${tx}</div><input type="text" id="p-in" class="sys-modal-input"><button class="sys-modal-btn primary" id="p-ok">OK</button><button class="sys-modal-btn" onclick="Core.closeModal()">ОТМЕНА</button>`);
        document.getElementById('p-ok').onclick = () => { const v = document.getElementById('p-in').value; Core.closeModal(); cb(v); };
    },

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
    // Core.buildMsgHtml       - Генератор HTML-кода сообщения
    buildMsgHtml(msg, ts, id) {
        let data = msg.text;
        
        // 1. ПАРСИМ, ЕСЛИ ЭТО СТРОКА-JSON
        let isObject = false;
        let parsed = null;
        try {
            if (typeof data === 'object') {
                parsed = data;
                isObject = true;
            } else if (typeof data === 'string' && data.trim().startsWith('{')) {
                parsed = JSON.parse(data);
                isObject = true;
            }
        } catch(e) { isObject = false; }

        // 2. ФИЛЬТРУЕМ ТЕХНИЧЕСКИЙ МУСОР (Хендшейки)
        if (isObject && parsed) {
            // Если в пакете ключи или системные метки - гасим его
            if (parsed.t === "pqc_init" || parsed.psk || parsed.type === "sys" || parsed.shift !== undefined) {
                return ""; 
            }
            
            // 3. ПРОВЕРЯЕМ, НЕ МЕДИА ЛИ ЭТО (Кружок, Фото, Голос)
            // Наши медиа всегда имеют поле 'type' (image, video, video_note, voice) и 'data'
            if (parsed.type && parsed.data) {
                const side = msg.inbound ? 'in' : 'out';
                const time = new Date(ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
                const content = this.renderStub(parsed, id || ts);
                
                return `
                    <div class="msg ${side}" id="msg-box-${id || ts}">
                        <div class="m-txt">
                            ${content}
                            <span class="msg-del-btn" onclick="Core.deleteMessageFlow('${id || ts}')">×</span>
                        </div>
                        <small class="m-ts">${time}</small>
                    </div>`;
            }
        }

        // 4. ОБЫЧНЫЙ ТЕКСТОВЫЙ РЕНДЕР
        const side = msg.inbound ? 'in' : 'out';
        const time = new Date(ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
        const content = this.escapeHtml(typeof data === 'object' ? JSON.stringify(data) : data);
        
        if (!content || content.trim() === "") return "";

        return `
            <div class="msg ${side}" id="msg-box-${id || ts}">
                <div class="m-txt">
                    ${content}
                    <span class="msg-del-btn" onclick="Core.deleteMessageFlow('${id || ts}')">×</span>
                </div>
                <small class="m-ts">${time}</small>
            </div>`;
    },
    // Core.bytesToHex/hexToBytes - Конвертеры форматов данных
    bytesToHex: (b) => Array.from(b).map(x => Core.hex_lut[x]).join(''),
    hexToBytes: (h) => new Uint8Array(h.match(/.{1,2}/g).map(byte => parseInt(byte, 16))),
    // Core.escapeHtml         - Защита от XSS в сообщениях
    escapeHtml: t => t ? String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\n/g,'<br>') : "",
    //Core.shmon       - Логгирование
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

};

Core.initProximity();    
window.boot_sequence = (id, pwd) => Core.boot(id, pwd);
window.addEventListener('popstate', (event) => {
    if (Core.activePeerId) {
        // Если мы в чате — закрываем его и остаемся в приложении
        Core.closeChat(false); // передаем false, чтоб не зациклить историю
    }
});
