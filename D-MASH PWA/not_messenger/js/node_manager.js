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
        const close = document.createElement('button'); close.className = 'sys-modal-btn'; close.textContent = 'НАЗАД'; close.onclick = () => Core.openSettings();
        box.append(add, connect, close); modal.appendChild(box);
    }
};
NodeManager.load();
window.NodeEndpoint = NodeEndpoint;
window.NodeManager = NodeManager;
