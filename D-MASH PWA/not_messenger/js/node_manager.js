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
    transportModeKey: 'dmash_transport_mode_v1',
    inboundHandleKey: 'dmash_mesh_inbound_handle_v1',
    routeConfigKey: 'dmash_mesh_route_config_v1',
    endpoints: [], active: null, socket: null,
    transportMode: 'mesh',
    state: 'disconnected', error: null, reconnectAttempt: 0, reconnectTimer: null,
    pingTimer: null, pendingPings: new Map(), pendingRequests: new Map(), lastLatencyMs: null, lastConnectedAt: null,

    load() {
        try {
            this.endpoints = JSON.parse(localStorage.getItem(this.storageKey) || '[]')
                .map(item => new NodeEndpoint(item.url, item.label));
        } catch (_) { this.endpoints = []; }
        const activeUrl = localStorage.getItem(this.activeKey);
        this.active = this.endpoints.find(item => item.url === activeUrl) || null;
        this.transportMode = localStorage.getItem(this.transportModeKey) === 'legacy' ? 'legacy' : 'mesh';
    },
    setTransportMode(mode) {
        if (!['mesh', 'legacy'].includes(mode)) throw new Error('Unknown transport mode');
        this.transportMode = mode;
        localStorage.setItem(this.transportModeKey, mode);
        window.dispatchEvent(new CustomEvent('dmash-transport-mode', { detail: { mode } }));
    },
    getInboundLocatorHandle() {
        return this.getInboundLocatorHandles()[0] || null;
    },
    getInboundLocatorHandles() {
        const handles = Object.values(this.getRouteConfig())
            .map(route => route?.locatorHandle)
            .filter(Boolean);
        const legacyHandle = sessionStorage.getItem(this.inboundHandleKey) || localStorage.getItem(this.inboundHandleKey);
        if (legacyHandle && !handles.includes(legacyHandle)) handles.push(legacyHandle);
        return handles;
    },
    getRouteConfig() {
        try { return JSON.parse(sessionStorage.getItem(this.routeConfigKey) || '{}'); } catch (_) { return {}; }
    },
    getMeshRoute(peerId) {
        return this.getRouteConfig()[peerId] || null;
    },
    setMeshRoute(peerId, routeLocator, backRouteLocator) {
        const routes = this.getRouteConfig();
        routes[peerId] = { ...routes[peerId], routeLocator, backRouteLocator };
        sessionStorage.setItem(this.routeConfigKey, JSON.stringify(routes));
    },
    setLocatorHandle(peerId, locatorHandle) {
        const routes = this.getRouteConfig();
        if (!routes[peerId]) return;
        routes[peerId] = { ...routes[peerId], locatorHandle };
        sessionStorage.setItem(this.routeConfigKey, JSON.stringify(routes));
        sessionStorage.setItem(this.inboundHandleKey, locatorHandle);
    },
    async armMeshRoute(peerId, routeLocator, backRouteLocator) {
        this.setMeshRoute(peerId, routeLocator, backRouteLocator);
        if (this.state !== 'connected') return { armed: false, state: 'NODE_NOT_CONNECTED' };
        const result = await this.registerInboundLocator(backRouteLocator);
        this.setLocatorHandle(peerId, result.locator_handle);
        return { armed: true, locator_handle: result.locator_handle };
    },
    async armStoredRoutes() {
        if (this.state !== 'connected') return;
        const routes = this.getRouteConfig();
        for (const [peerId, route] of Object.entries(routes)) {
            if (!route?.backRouteLocator) continue;
            try {
                const result = await this.registerInboundLocator(route.backRouteLocator);
                this.setLocatorHandle(peerId, result.locator_handle);
            } catch (error) { this.showMessage(`Mesh locator arm failed: ${error.message}`, true); }
        }
    },
    async removeMeshRoute(peerId) {
        const routes = this.getRouteConfig();
        const route = routes[peerId];
        if (!route) return { removed: false, nodeRemoved: false };
        delete routes[peerId];
        sessionStorage.setItem(this.routeConfigKey, JSON.stringify(routes));
        const remainingHandles = Object.values(routes).map(item => item?.locatorHandle).filter(Boolean);
        if (remainingHandles[0]) sessionStorage.setItem(this.inboundHandleKey, remainingHandles[0]);
        else sessionStorage.removeItem(this.inboundHandleKey);

        if (!route.backRouteLocator || this.state !== 'connected') {
            return { removed: true, nodeRemoved: false, state: 'NODE_NOT_CONNECTED' };
        }
        await this.request('UNREGISTER_INBOUND_LOCATOR', { locator: route.backRouteLocator });
        return { removed: true, nodeRemoved: true };
    },
    async configureInboundLocator() {
        this.openPrompt('ARM MESH LOCATOR', 'opaque locator from mutual offline pairing', async locator => {
            if (!locator) throw new Error('Locator is required');
            const result = await this.registerInboundLocator(locator);
            sessionStorage.setItem(this.inboundHandleKey, result.locator_handle);
            this.showMessage('Inbound locator armed on this Entry Node.');
        });
    },
    configurePeerRoute() {
        this.openPrompt('MESH ROUTE: PEER ID', 'local contact ID (not sent to Node)', peerId => {
            if (!peerId) throw new Error('Peer ID is required for local contact lookup');
            this.openPrompt('MESH ROUTE: FORWARD LOCATOR', 'opaque route locator A→B', routeLocator => {
                if (!routeLocator) throw new Error('Forward locator is required');
                this.openPrompt('MESH ROUTE: BACK LOCATOR', 'opaque route locator B→A', backRouteLocator => {
                    if (!backRouteLocator) throw new Error('Back locator is required');
                    this.setMeshRoute(peerId, routeLocator, backRouteLocator);
                    this.showMessage('Opaque Mesh route saved for this browser session. Start PROBE before sending.');
                });
            });
        });
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
    async autoConnect() {
        if (!this.endpoints.length) await this.loadOriginList();
        if (!this.active && this.endpoints.length) this.select(this.endpoints[0].url);
        if (this.active && this.state === 'disconnected') await this.connect();
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
        if (!window.Core?.device?.signing || !window.DeviceRoot?.state?.root) throw new Error('Device identity is not unlocked');
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
            if (message.protocol !== 'DMP-C' || message.version !== 2 || message.auth_mode !== 'DEVICE_AUTH_V1' ||
                !/^[0-9a-f]{64}$/i.test(message.node_id || '') || !message.session_id || !message.nonce ||
                !Number.isInteger(message.expires_at) || message.expires_at <= Math.floor(Date.now() / 1000)) {
                this.socket.close(1008, 'invalid device auth challenge');
                this.setState('error', 'invalid device-auth challenge');
                return;
            }
            window.DeviceRoot.transportIdentity(message.node_id).then(transport => {
                const clientNonce = this.toBase64(crypto.getRandomValues(new Uint8Array(32)));
                const transcript = new TextEncoder().encode(
                    `DMP-C|2|DEVICE_AUTH_V1|${transport.nodeId}|${message.session_id}|${message.nonce}|${clientNonce}|${message.expires_at}`
                );
                const signature = window.nacl.sign.detached(transcript, transport.signing.secretKey);
                this.socket.send(JSON.stringify({
                    type: 'AUTH', auth_mode: 'DEVICE_AUTH_V1',
                    public_key: window.Core.bytesToHex(transport.signing.publicKey), client_nonce: clientNonce,
                    signature: this.toBase64(signature)
                }));
            }).catch(error => {
                this.socket.close(1008, 'device auth unavailable');
                this.setState('error', error.message);
            });
        } else if (message.type === 'AUTH_OK') {
            if (message.auth_mode !== 'DEVICE_AUTH_V1' || message.version !== 2) {
                this.socket.close(1008, 'unexpected auth mode'); this.setState('error', 'unexpected auth mode'); return;
            }
            this.reconnectAttempt = 0;
            this.lastConnectedAt = Date.now();
            this.setState('connected');
            this.socket.send(JSON.stringify({ type: 'STATUS', request_id: crypto.randomUUID() }));
            this.armStoredRoutes();
            this.startPings();
        } else if (message.type === 'DELIVERY_AVAILABLE') {
            // The ciphertext stays in the Node mailbox until ACK. This signal
            // merely wakes the authenticated local PWA to perform PULL.
            window.dispatchEvent(new CustomEvent('dmash-delivery-available', { detail: message }));
        } else if (message.type === 'PONG') {
            const started = this.pendingPings.get(message.request_id);
            if (started) {
                this.pendingPings.delete(message.request_id);
                this.lastLatencyMs = Math.round(performance.now() - started);
                this.setState('connected');
            }
        } else if (message.request_id && this.pendingRequests.has(message.request_id)) {
            const pending = this.pendingRequests.get(message.request_id);
            this.pendingRequests.delete(message.request_id);
            if (message.type === 'ERROR') pending.reject(new Error(message.code || 'node error'));
            else pending.resolve(message);
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
    request(type, payload = {}) {
        if (this.state !== 'connected' || this.socket?.readyState !== WebSocket.OPEN) {
            return Promise.reject(new Error('D-MASH node is not connected'));
        }
        const requestId = crypto.randomUUID();
        const message = { ...payload, type, request_id: requestId };
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.pendingRequests.delete(requestId);
                reject(new Error(`${type} timed out`));
            }, 15000);
            this.pendingRequests.set(requestId, {
                resolve: value => { clearTimeout(timeout); resolve(value); },
                reject: error => { clearTimeout(timeout); reject(error); }
            });
            try { this.socket.send(JSON.stringify(message)); }
            catch (error) {
                clearTimeout(timeout); this.pendingRequests.delete(requestId); reject(error);
            }
        });
    },
    registerInboundLocator(locator) {
        return this.request('REGISTER_INBOUND_LOCATOR', { locator });
    },
    unregisterInboundLocator(locator) {
        return this.request('UNREGISTER_INBOUND_LOCATOR', { locator });
    },
    startProbe(routeLocator, backRouteLocator, options = {}) {
        return this.request('START_PROBE', {
            route_locator: routeLocator, back_route_locator: backRouteLocator, ...options
        });
    },
    submitEnvelope(routeLocator, envelope) {
        return this.request('SUBMIT_ENVELOPE', { route_locator: routeLocator, envelope });
    },
    pull(locatorHandle) {
        return this.request('PULL', { locator_handle: locatorHandle });
    },
    ack(deliveryId) {
        return this.request('ACK', { delivery_id: deliveryId });
    },
    disconnect(reconnect = false) {
        clearTimeout(this.reconnectTimer); this.reconnectTimer = null;
        this.stopPings();
        const socket = this.socket; this.socket = null;
        for (const pending of this.pendingRequests.values()) pending.reject(new Error('D-MASH node disconnected'));
        this.pendingRequests.clear();
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
        const submit = document.createElement('button'); submit.className = 'sys-modal-btn primary'; submit.textContent = 'ДОБАВИТЬ';
        const cancel = document.createElement('button'); cancel.className = 'sys-modal-btn'; cancel.textContent = 'НАЗАД';
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
        const add = this.makeButton('ДОБАВИТЬ УЗЕЛ', () => {
            this.openPrompt('ДОБАВИТЬ УЗЕЛ', 'wss://node.example/dmp-c/v1', (url) => {
                const endpoint = this.add(url);
                this.select(endpoint.url);
                this.renderSettings();
            });
        });
        const connect = this.makeButton('ПОДКЛЮЧИТЬСЯ', async () => {
            try { await this.connect(); } catch (error) {
                this.showMessage(error.message === 'User identity is not unlocked' ? 'Сессия не готова. Выйдите и войдите с ключом доступа.' : error, true);
            }
        }, true);
        const disconnect = this.makeButton('ОТКЛЮЧИТЬСЯ', () => { this.disconnect(false); this.renderSettings(); });
        const arm = this.makeButton('ARM MESH LOCATOR', () => this.configureInboundLocator());
        const route = this.makeButton('CONFIGURE MESH ROUTE', () => this.configurePeerRoute());
        const close = this.makeButton('НАЗАД', () => { if (window.Core?.openSettings) Core.openSettings(); else modal.style.display = 'none'; });
        box.append(add, connect, disconnect, arm, route, close); modal.appendChild(box);
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
