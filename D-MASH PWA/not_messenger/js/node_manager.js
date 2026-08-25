"use strict";

class NodeEndpoint {
    constructor(url, label = "") {
        const parsed = new URL(url, window.location.href);
        if (!['wss:', 'ws:'].includes(parsed.protocol)) throw new Error('Node endpoint must use WSS/WS');
        if (parsed.protocol === 'ws:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
            throw new Error('Insecure WS is allowed only on localhost');
        }
        this.url = parsed.href;
        this.label = label || parsed.host;
    }
}

const NodeManager = {
    storageKey: 'dmash_node_endpoints_v1',
    activeKey: 'dmash_active_node_v1',
    originKey: 'dmash_origin_notifications_v1',
    endpoints: [], active: null, socket: null,
    state: 'disconnected', error: null, reconnectAttempt: 0, reconnectTimer: null,

    load() {
        try {
            this.endpoints = JSON.parse(localStorage.getItem(this.storageKey) || '[]')
                .map(item => new NodeEndpoint(item.url, item.label));
        } catch (_) { this.endpoints = []; }
        const activeUrl = localStorage.getItem(this.activeKey);
        this.active = this.endpoints.find(item => item.url === activeUrl) || null;
    },
    save() {
        localStorage.setItem(this.storageKey, JSON.stringify(this.endpoints));
        if (this.active) localStorage.setItem(this.activeKey, this.active.url);
        else localStorage.removeItem(this.activeKey);
    },
    add(url, label = '') {
        const endpoint = new NodeEndpoint(url, label);
        if (!this.endpoints.some(item => item.url === endpoint.url)) this.endpoints.push(endpoint);
        this.save(); return endpoint;
    },
    remove(url) {
        this.endpoints = this.endpoints.filter(item => item.url !== url);
        if (this.active?.url === url) { this.disconnect(false); this.active = null; }
        this.save();
    },
    async loadOriginList(path = 'nodes.json') {
        const response = await fetch(path, { cache: 'no-store' });
        if (!response.ok) throw new Error(`Node list HTTP ${response.status}`);
        const data = await response.json();
        for (const item of (data.nodes || [])) this.add(item.url, item.label);
        return this.endpoints;
    },
    select(url) {
        const endpoint = this.endpoints.find(item => item.url === url);
        if (!endpoint) throw new Error('Unknown node endpoint');
        this.disconnect(false); this.active = endpoint; this.save();
    },
    setState(state, error = null) {
        this.state = state; this.error = error;
        window.dispatchEvent(new CustomEvent('dmash-node-state', { detail: { state, error, active: this.active } }));
    },
    async connect() {
        if (!this.active) throw new Error('Select a node first');
        if (!window.Core?.keys?.sign) throw new Error('User identity is not unlocked');
        clearTimeout(this.reconnectTimer); this.setState('connecting');
        const socket = new WebSocket(this.active.url); this.socket = socket;
        socket.onmessage = event => this.onMessage(event);
        socket.onclose = () => { if (this.socket === socket) { this.socket = null; this.setState('disconnected'); this.scheduleReconnect(); } };
        socket.onerror = () => this.setState('error', 'connection failed');
    },
    onMessage(event) {
        const message = JSON.parse(event.data);
        if (message.type === 'CHALLENGE') {
            const transcript = new TextEncoder().encode(`DMP-C|1|AUTH|${message.session_id}|${message.nonce}`);
            const signature = window.nacl.sign.detached(transcript, window.Core.keys.sign.secretKey);
            this.socket.send(JSON.stringify({
                type: 'AUTH', public_key: window.Core.bytesToHex(window.Core.keys.sign.publicKey),
                signature: this.toBase64(signature)
            }));
        } else if (message.type === 'AUTH_OK') {
            this.reconnectAttempt = 0; this.setState('connected');
            this.socket.send(JSON.stringify({ type: 'STATUS', request_id: crypto.randomUUID() }));
        } else if (message.type === 'ERROR') this.setState('error', message.code || 'node error');
    },
    toBase64(bytes) {
        let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
        return btoa(binary);
    },
    originUrl() {
        const configured = window.DMASH_RUNTIME_CONFIG?.originNotificationUrl || localStorage.getItem(this.originKey);
        if (!configured) throw new Error('Configure HTTPS Origin notification URL first');
        const url = new URL(configured, window.location.href);
        if (url.protocol !== 'https:') throw new Error('Origin notification URL must use HTTPS');
        return url.href.replace(/\/$/, '');
    },
    async signedOriginRequest(action, path, payload = {}) {
        if (!window.Core?.keys?.sign) throw new Error('User identity is not unlocked');
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid Origin payload');
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        const signedPayload = { ...payload };
        const canonical = new TextEncoder().encode(`DMP-ORIGIN|1|${action}|${timestamp}|${nonce}|${JSON.stringify(signedPayload)}`);
        signedPayload.auth = {
            public_key: window.Core.bytesToHex(window.Core.keys.sign.publicKey), timestamp, nonce,
            signature: this.toBase64(window.nacl.sign.detached(canonical, window.Core.keys.sign.secretKey))
        };
        const response = await fetch(`${this.originUrl()}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(signedPayload) });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.detail || `Origin HTTP ${response.status}`);
        return data;
    },
    async enrollPersonalBot(botToken) {
        return this.signedOriginRequest('PERSONAL_BOT_ENROLL', '/v1/personal-bots/enroll', { bot_token: botToken });
    },
    async personalBotStatus() {
        return this.signedOriginRequest('PERSONAL_BOT_STATUS', '/v1/personal-bots/status');
    },
    async testPersonalBot() {
        return this.signedOriginRequest('PERSONAL_BOT_TEST', '/v1/personal-bots/test');
    },
    async disablePersonalBot() {
        return this.signedOriginRequest('PERSONAL_BOT_DISABLE', '/v1/personal-bots/disable');
    },
    async removePersonalBot() {
        return this.signedOriginRequest('PERSONAL_BOT_REMOVE', '/v1/personal-bots/remove');
    },
    disconnect(reconnect = false) {
        clearTimeout(this.reconnectTimer); this.reconnectTimer = null;
        const socket = this.socket; this.socket = null;
        if (socket) socket.close(1000, 'client disconnect');
        this.setState('disconnected');
        if (reconnect) this.scheduleReconnect();
    },
    scheduleReconnect() {
        if (!this.active || this.reconnectTimer) return;
        const delay = Math.min(30000, 1000 * (2 ** this.reconnectAttempt++));
        this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; this.connect().catch(e => this.setState('error', e.message)); }, delay);
    },
    renderSettings() {
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const title = document.createElement('h4'); title.textContent = `D-MASH NODES: ${this.state.toUpperCase()}`; box.appendChild(title);
        for (const endpoint of this.endpoints) {
            const row = document.createElement('div'); row.style.marginBottom = '8px';
            const choose = document.createElement('button'); choose.className = 'sys-modal-btn';
            choose.textContent = `${this.active?.url === endpoint.url ? '● ' : ''}${endpoint.label} (${endpoint.url})`;
            choose.onclick = () => { this.select(endpoint.url); this.renderSettings(); }; row.appendChild(choose);
            box.appendChild(row);
        }
        const add = document.createElement('button'); add.className = 'sys-modal-btn'; add.textContent = 'ДОБАВИТЬ NODE';
        add.onclick = () => Core.customPrompt('NODE ENDPOINT', 'WSS URL:', value => { try { this.add(value); this.renderSettings(); } catch (e) { Core.customAlert('ОШИБКА', e.message); } });
        const connect = document.createElement('button'); connect.className = 'sys-modal-btn primary'; connect.textContent = 'ПОДКЛЮЧИТЬСЯ'; connect.onclick = () => this.connect().catch(e => Core.customAlert('ОШИБКА', e.message));
        const origin = document.createElement('button'); origin.className = 'sys-modal-btn'; origin.textContent = 'ORIGIN УВЕДОМЛЕНИЙ'; origin.onclick = () => Core.customPrompt('ORIGIN', 'HTTPS URL:', value => { try { const url = new URL(value); if (url.protocol !== 'https:') throw new Error('HTTPS required'); localStorage.setItem(this.originKey, url.href.replace(/\/$/, '')); this.renderSettings(); } catch (e) { Core.customAlert('ОШИБКА', e.message); } });
        const personalBot = document.createElement('button'); personalBot.className = 'sys-modal-btn'; personalBot.textContent = 'ПОДКЛЮЧИТЬ ЛИЧНЫЙ TELEGRAM BOT'; personalBot.onclick = () => Core.customPrompt('TELEGRAM BOT', 'Bot Token:', token => this.enrollPersonalBot(token).then(result => Core.customAlert('ПРИВЯЗКА', `Откройте: ${result.start_link}`)).catch(e => Core.customAlert('ОШИБКА', e.message)));
        const botStatus = document.createElement('button'); botStatus.className = 'sys-modal-btn'; botStatus.textContent = 'СТАТУС TELEGRAM BOT'; botStatus.onclick = () => this.personalBotStatus().then(result => Core.customAlert('TELEGRAM BOT', result.configured ? `Сохранён: ••••${result.token_suffix}\n${result.enabled ? 'Уведомления включены' : 'Уведомления выключены'}\n${result.chat_bound ? 'Telegram привязан' : 'Откройте start-ссылку'}` : 'Личный bot не подключён')).catch(e => Core.customAlert('ОШИБКА', e.message));
        const testBot = document.createElement('button'); testBot.className = 'sys-modal-btn'; testBot.textContent = 'ТЕСТ УВЕДОМЛЕНИЯ'; testBot.onclick = () => this.testPersonalBot().then(() => Core.customAlert('TELEGRAM BOT', 'Тестовое уведомление отправлено')).catch(e => Core.customAlert('ОШИБКА', e.message));
        const disableBot = document.createElement('button'); disableBot.className = 'sys-modal-btn'; disableBot.textContent = 'ОТКЛЮЧИТЬ УВЕДОМЛЕНИЯ'; disableBot.onclick = () => Core.customConfirm('TELEGRAM BOT', 'Отключить личные Telegram-уведомления?', () => this.disablePersonalBot().then(() => Core.customAlert('TELEGRAM BOT', 'Уведомления отключены')).catch(e => Core.customAlert('ОШИБКА', e.message)));
        const removeBot = document.createElement('button'); removeBot.className = 'sys-modal-btn'; removeBot.textContent = 'УДАЛИТЬ ЛИЧНЫЙ BOT'; removeBot.onclick = () => Core.customConfirm('TELEGRAM BOT', 'Удалить сохранённый token и привязку? Это действие необратимо.', () => this.removePersonalBot().then(() => Core.customAlert('TELEGRAM BOT', 'Личный bot удалён')).catch(e => Core.customAlert('ОШИБКА', e.message)));
        const close = document.createElement('button'); close.className = 'sys-modal-btn'; close.textContent = 'НАЗАД'; close.onclick = () => Core.openSettings();
        box.append(add, connect, origin, personalBot, botStatus, testBot, disableBot, removeBot, close); modal.appendChild(box);
    }
};
NodeManager.load();
window.NodeEndpoint = NodeEndpoint;
window.NodeManager = NodeManager;
