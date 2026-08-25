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
    pingTimer: null, pendingPings: new Map(), lastLatencyMs: null, lastConnectedAt: null,

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
        const panel = document.getElementById('dmash-node-panel-status');
        if (panel) {
            const labels = {
                connected: 'Подключено',
                connecting: 'Подключение…',
                reconnecting: 'Восстанавливаем соединение…',
                disconnected: 'Не подключено',
                error: 'Не удалось подключиться'
            };
            panel.textContent = error ? `${labels[state] || 'Ошибка'}: ${error}` : (labels[state] || 'Не подключено');
            panel.style.color = error ? '#ff7b7b' : '#b8ffca';
        }
        window.dispatchEvent(new CustomEvent('dmash-node-state', { detail: { state, error, active: this.active } }));
    },
    async connect() {
        if (!this.active) throw new Error('Select a node first');
        if (!window.Core?.keys?.sign) throw new Error('User identity is not unlocked');
        clearTimeout(this.reconnectTimer); this.setState('connecting');
        const socket = new WebSocket(this.active.url); this.socket = socket;
        socket.onmessage = event => this.onMessage(event);
        socket.onclose = () => {
            if (this.socket !== socket) return;
            this.socket = null;
            this.stopPings();
            if (this.active) {
                this.setState('reconnecting');
                this.scheduleReconnect();
            } else this.setState('disconnected');
        };
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
            this.reconnectAttempt = 0;
            this.lastConnectedAt = Date.now();
            this.setState('connected');
            this.socket.send(JSON.stringify({ type: 'STATUS', request_id: crypto.randomUUID() }));
            this.startPings();
        } else if (message.type === 'PONG') {
            const started = this.pendingPings.get(message.request_id);
            if (started) {
                this.pendingPings.delete(message.request_id);
                this.lastLatencyMs = Math.round(performance.now() - started);
                this.setState('connected');
            }
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
    ping() {
        if (this.state !== 'connected' || this.socket?.readyState !== WebSocket.OPEN) return;
        const requestId = crypto.randomUUID();
        this.pendingPings.set(requestId, performance.now());
        this.socket.send(JSON.stringify({ type: 'PING', request_id: requestId }));
    },
    startPings() {
        this.stopPings();
        this.ping();
        this.pingTimer = setInterval(() => this.ping(), 15000);
    },
    stopPings() {
        clearInterval(this.pingTimer);
        this.pingTimer = null;
        this.pendingPings.clear();
    },
    disconnect(reconnect = false) {
        clearTimeout(this.reconnectTimer); this.reconnectTimer = null;
        this.stopPings();
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
    showMessage(value, isError = false) {
        const message = value instanceof Error ? value.message : String(value);
        const status = document.getElementById('dmash-node-panel-status');
        if (status) { status.textContent = `${isError ? 'ERROR' : 'INFO'}: ${message}`; status.style.color = isError ? '#ff7b7b' : '#b8ffca'; }
        else window.alert(message);
    },
    openPrompt(titleText, placeholder, onSubmit) {
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const title = document.createElement('h4'); title.textContent = titleText;
        const input = document.createElement('input'); input.className = 'sys-modal-input'; input.placeholder = placeholder;
        const submit = document.createElement('button'); submit.className = 'sys-modal-btn primary'; submit.textContent = 'SAVE';
        const cancel = document.createElement('button'); cancel.className = 'sys-modal-btn'; cancel.textContent = 'BACK';
        submit.onclick = () => { try { Promise.resolve(onSubmit(input.value.trim())).catch(error => this.showMessage(error, true)); } catch (error) { this.showMessage(error, true); } };
        cancel.onclick = () => this.renderSettings();
        box.append(title, input, submit, cancel); modal.appendChild(box); input.focus();
    },
    makeButton(label, handler, primary = false) {
        const button = document.createElement('button'); button.className = `sys-modal-btn${primary ? ' primary' : ''}`;
        button.textContent = label;
        button.onclick = handler;
        return button;
    },
    async renderDiagnostics() {
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const title = document.createElement('h4'); title.textContent = 'D-MASH RUNTIME DIAGNOSTICS';
        const details = document.createElement('pre'); details.style.cssText = 'white-space:pre-wrap;word-break:break-all;text-align:left;font-size:10px;color:#b8ffca;max-height:48vh;overflow:auto';
        details.textContent = 'Collecting runtime state…';
        const back = this.makeButton('BACK TO NODES', () => this.renderSettings());
        box.append(title, details, back); modal.appendChild(box);
        const scriptUrls = performance.getEntriesByType('resource')
            .map(entry => entry.name).filter(url => /\/(ui_logic|core_engine|node_manager|release)\.js(?:\?|$)/.test(url));
        let cacheKeys = [];
        try { cacheKeys = await caches.keys(); } catch (_) { cacheKeys = ['CacheStorage unavailable']; }
        details.textContent = [
            `release=${window.DMASH_RELEASE?.id || 'missing'}`,
            `href=${location.href}`,
            `origin=${location.origin}`,
            `serviceWorker=${navigator.serviceWorker.controller?.scriptURL || 'none'}`,
            `nodeManager=${Boolean(window.NodeManager)}`,
            `nodeState=${this.state}`,
            `activeNode=${this.active?.url || 'none'}`,
            `caches=${cacheKeys.join(', ') || 'none'}`,
            'scripts=', ...scriptUrls
        ].join('\n');
    },
    renderSettings() {
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const title = document.createElement('h4'); title.textContent = 'ПОДКЛЮЧЕНИЕ К УЗЛУ'; box.appendChild(title);
        const status = document.createElement('div'); status.id = 'dmash-node-panel-status';
        status.style.cssText = 'margin:0 0 14px;text-align:center;color:#b8ffca';
        const labels = { connected: 'Подключено', connecting: 'Подключение…', reconnecting: 'Восстанавливаем соединение…', disconnected: 'Не подключено', error: 'Не удалось подключиться' };
        status.textContent = this.error ? `${labels[this.state] || 'Ошибка'}: ${this.error}` : (labels[this.state] || 'Не подключено');
        box.appendChild(status);
        const endpoint = document.createElement('p');
        endpoint.style.cssText = 'margin:0 0 18px;color:#ccc;word-break:break-word;text-align:left;font-size:0.8rem';
        endpoint.textContent = this.active ? `${this.active.label}: ${this.active.url}` : 'Узел пока не выбран.';
        box.appendChild(endpoint);
        const connect = this.makeButton('ПОДКЛЮЧИТЬСЯ', async () => {
            try { await this.connect(); } catch (error) {
                this.showMessage(error.message === 'User identity is not unlocked' ? 'Сессия не готова. Выйдите и войдите с ключом доступа.' : error, true);
            }
        }, true);
        const disconnect = this.makeButton('ОТКЛЮЧИТЬСЯ', () => { this.disconnect(false); this.renderSettings(); });
        const close = this.makeButton('НАЗАД', () => { if (window.Core?.openSettings) Core.openSettings(); else modal.style.display = 'none'; });
        box.append(connect, disconnect, close); modal.appendChild(box);
    },
    openStartLink(url) {
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const title = document.createElement('h4'); title.textContent = 'TELEGRAM START REQUIRED';
        const text = document.createElement('p'); text.textContent = 'Open this one-time link in Telegram, press Start, then return here for status.';
        const link = document.createElement('a'); link.href = url; link.target = '_blank'; link.rel = 'noopener'; link.className = 'sys-modal-btn primary'; link.textContent = 'OPEN TELEGRAM';
        const back = this.makeButton('BACK TO NODES', () => this.renderSettings());
        box.append(title, text, link, back); modal.appendChild(box);
    },
    showPersonalStatus(result) {
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const title = document.createElement('h4'); title.textContent = 'PERSONAL TELEGRAM BOT';
        const value = document.createElement('p');
        value.textContent = result.configured ? `TOKEN: ••••${result.token_suffix}\nSTATE: ${result.enabled ? 'ENABLED' : 'DISABLED'}\nTELEGRAM: ${result.chat_bound ? 'BOUND' : 'START REQUIRED'}` : 'NOT CONFIGURED';
        value.style.whiteSpace = 'pre-line'; box.append(title, value, this.makeButton('BACK TO NODES', () => this.renderSettings())); modal.appendChild(box);
    }
};
NodeManager.load();
window.NodeEndpoint = NodeEndpoint;
window.NodeManager = NodeManager;
