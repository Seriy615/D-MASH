"use strict";

class NodeEndpoint {
    constructor(url, label = "", options = {}) {
        const parsed = new URL(url, window.location.href);
        if (!['wss:', 'ws:'].includes(parsed.protocol)) throw new Error('Node endpoint must use WSS/WS');
        if (parsed.protocol === 'ws:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
            throw new Error('Insecure WS is allowed only on localhost');
        }
        this.url = parsed.href;
        this.label = label || parsed.host;
        this.public = options.public === true;
        // Provisioning metadata is retained locally only. Password-based node
        // authentication is not claimed until the DMP-C server supports it.
        this.password = typeof options.password === 'string' ? options.password : null;
        this.autoConnect = options.autoConnect !== false;
        // Notification delivery is an explicit, per-node opt-in.  Do not turn
        // every Entry Node into a notification relay just because Telegram was
        // linked on this device.
        this.notificationEnabled = options.notificationEnabled === true;
    }
}

const NodeManager = {
    storageKey: 'dmash_node_endpoints_v1',
    activeKey: 'dmash_active_node_v1',
    originKey: 'dmash_origin_notifications_v1',
    transportModeKey: 'dmash_transport_mode_v1',
    inboundHandleKey: 'dmash_mesh_inbound_handle_v1',
    routeConfigKey: 'dmash_mesh_route_config_v1',
    notificationBeaconEnabledKey: 'dmash_notification_beacon_enabled_v1',
    endpoints: [], active: null, socket: null, capabilities: new Set(), connections: new Map(),
    transportMode: 'mesh',
    state: 'disconnected', error: null, reconnectAttempt: 0, reconnectTimer: null,
    pingTimer: null, pendingPings: new Map(), pendingRequests: new Map(), lastLatencyMs: null, lastConnectedAt: null,

    load() {
        try {
            this.endpoints = JSON.parse(localStorage.getItem(this.storageKey) || '[]')
                .map(item => new NodeEndpoint(item.url, item.label, item));
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
        if (!this.connectedConnections().length) return { armed: false, state: 'NODE_NOT_CONNECTED' };
        if (!this.supports('REGISTER_INBOUND_LOCATOR') || !this.supports('START_PROBE')) {
            return { armed: false, state: 'NODE_DISCOVERY_UNAVAILABLE' };
        }
        const result = await this.registerInboundLocator(backRouteLocator);
        this.setLocatorHandle(peerId, result.locator_handle);
        await this.bindNotificationBeacon(backRouteLocator);
        await this.startProbe(routeLocator, backRouteLocator);
        return { armed: true, locator_handle: result.locator_handle };
    },
    async armStoredRoutes() {
        if (!this.connectedConnections().length) return;
        if (!this.supports('REGISTER_INBOUND_LOCATOR') || !this.supports('START_PROBE')) return;
        const routes = this.getRouteConfig();
        for (const [peerId, route] of Object.entries(routes)) {
            if (!route?.backRouteLocator) continue;
            try {
                const result = await this.registerInboundLocator(route.backRouteLocator);
                this.setLocatorHandle(peerId, result.locator_handle);
                await this.bindNotificationBeacon(route.backRouteLocator);
                await this.startProbe(route.routeLocator, route.backRouteLocator);
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

        if (!route.backRouteLocator || !this.connectedConnections().length) {
            return { removed: true, nodeRemoved: false, state: 'NODE_NOT_CONNECTED' };
        }
        await this.request('UNREGISTER_INBOUND_LOCATOR', { locator: route.backRouteLocator });
        return { removed: true, nodeRemoved: true };
    },
    save() {
        localStorage.setItem(this.storageKey, JSON.stringify(this.endpoints));
        if (this.active) localStorage.setItem(this.activeKey, this.active.url);
        else localStorage.removeItem(this.activeKey);
    },
    add(url, label = '', options = {}) {
        const endpoint = new NodeEndpoint(url, label, options);
        const existing = this.endpoints.find(item => item.url === endpoint.url);
        if (existing) Object.assign(existing, { label: endpoint.label, public: endpoint.public, password: endpoint.password });
        if (existing) existing.autoConnect = endpoint.autoConnect;
        else this.endpoints.push(endpoint);
        this.save(); return endpoint;
    },
    remove(url) {
        this.endpoints = this.endpoints.filter(item => item.url !== url);
        const connection = this.connections.get(url);
        if (connection) {
            clearTimeout(connection.reconnectTimer); this.stopPings(connection);
            this.rejectPending(connection, new Error('D-MASH node removed'));
            this.connections.delete(url); connection.socket?.close(1000, 'node removed');
        }
        if (this.active?.url === url) this.active = this.endpoints[0] || null;
        this.save();
        this.updateState();
    },
    async loadOriginList(path = 'nodes.json') {
        const response = await fetch(path, { cache: 'no-store' });
        if (!response.ok) throw new Error(`Node list HTTP ${response.status}`);
        const data = await response.json();
        for (const item of (data.nodes || [])) this.add(item.url, item.label, { public: true });
        return this.endpoints;
    },
    async autoConnect() {
        if (!this.endpoints.length) await this.loadOriginList();
        // Default policy: exactly one randomly selected prepared public node.
        // A manually selected/personal node always wins and is never replaced.
        if (!this.active) {
            const publicNodes = this.endpoints.filter(endpoint => endpoint.public);
            const candidates = publicNodes.length ? publicNodes : this.endpoints;
            if (candidates.length) this.select(candidates[Math.floor(Math.random() * candidates.length)].url);
        }
        if (this.active && this.active.autoConnect !== false && !this.connectedConnections().length) await this.connect(this.active.url);
    },
    select(url) {
        const endpoint = this.endpoints.find(item => item.url === url);
        if (!endpoint) throw new Error('Unknown node endpoint');
        this.active = endpoint; this.save(); this.syncFacade();
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
        const nodeList = document.getElementById('dmash-node-list');
        if (nodeList) this.renderNodeList(nodeList);
        window.dispatchEvent(new CustomEvent('dmash-node-state', { detail: { state, error, active: this.active, connections: this.connections } }));
    },
    renderNodeList(nodeList) {
        nodeList.replaceChildren();
        for (const endpoint of this.endpoints) {
            const connection = this.connections.get(endpoint.url);
            const item = document.createElement('div');
            item.style.cssText = 'margin:6px 0;padding:9px 10px;text-align:left;border:1px solid #333;font-size:.75rem;word-break:break-word';
            const state = connection?.state || 'disconnected';
            const marker = state === 'connected' ? '●' : (state === 'error' ? '×' : '○');
            const latency = connection?.lastLatencyMs != null ? ` · ${connection.lastLatencyMs} ms` : '';
            item.style.color = state === 'connected' ? '#b8ffca' : (connection?.error ? '#ff7b7b' : '#ccc');
            const identity = document.createElement('div');
            identity.style.cssText = 'line-height:1.25';
            const name = document.createElement('div');
            name.style.fontWeight = '700';
            name.textContent = `${marker} ${endpoint.label}: ${state}${latency}`;
            const url = document.createElement('div');
            url.style.cssText = 'margin-top:2px;font-size:.72rem';
            url.textContent = endpoint.url;
            identity.append(name, url);
            const controls = document.createElement('div'); controls.style.cssText = 'display:flex;gap:6px;margin-top:8px';
            const square = button => {
                button.style.cssText = 'margin:0;padding:0;width:44px;height:38px;min-width:44px;font-size:.65rem;line-height:1;font-weight:bold;flex:0 0 44px';
                return button;
            };
            const connect = square(this.makeButton(connection?.state === 'connected' ? 'OFF' : 'ON', () => {
                if (connection?.state === 'connected') this.disconnectEndpoint(endpoint.url);
                else { this.select(endpoint.url); this.connect(endpoint.url).catch(error => this.showMessage(error, true)); }
            }, connection?.state !== 'connected'));
            connect.title = connection?.state === 'connected' ? 'Отключить узел' : 'Подключить узел';
            const qr = square(this.makeButton('QR', () => this.showNodeQR(endpoint), false));
            qr.title = 'Показать QR узла';
            const settings = square(this.makeButton('⚙', () => {
                this.select(endpoint.url);
                this.renderNodeSettings(endpoint);
            }, false));
            settings.style.fontSize = '1rem';
            settings.title = 'Настроить узел';
            controls.append(connect, qr, settings);
            item.append(identity, controls);
            nodeList.appendChild(item);
        }
    },
    connectedConnections() {
        return [...this.connections.values()].filter(connection => connection.state === 'connected' && connection.socket?.readyState === WebSocket.OPEN);
    },
    syncFacade() {
        const activeConnection = this.connections.get(this.active?.url);
        const connection = activeConnection?.state === 'connected' ? activeConnection : this.connectedConnections()[0] || activeConnection || null;
        this.socket = connection?.socket || null;
        this.capabilities = connection?.capabilities || new Set();
        this.lastLatencyMs = connection?.lastLatencyMs ?? null;
        this.lastConnectedAt = connection?.lastConnectedAt ?? null;
        const connected = this.connectedConnections();
        const connecting = [...this.connections.values()].some(item => ['connecting', 'reconnecting'].includes(item.state));
        const failed = [...this.connections.values()].find(item => item.error);
        this.state = connected.length ? 'connected' : (connecting ? 'connecting' : (failed ? 'error' : 'disconnected'));
        this.error = connected.length ? null : (failed?.error || null);
    },
    updateState() { this.syncFacade(); this.setState(this.state, this.error); },
    supports(operation) { return this.connectedConnections().some(connection => connection.capabilities.has(operation)); },
    async connect(url = this.active?.url) {
        if (!window.Core?.device?.signing || !window.DeviceRoot?.state?.root) throw new Error('Device identity is not unlocked');
        const endpoint = this.endpoints.find(item => item.url === url);
        if (!endpoint) throw new Error('Select a node first');
        clearTimeout(this.reconnectTimer);
        this.connectEndpoint(endpoint);
        this.updateState();
    },
    connectEndpoint(endpoint) {
        const existing = this.connections.get(endpoint.url);
        if (existing?.socket && [WebSocket.OPEN, WebSocket.CONNECTING].includes(existing.socket.readyState)) return;
        const connection = { endpoint, socket: new WebSocket(endpoint.url), capabilities: new Set(), state: 'connecting', error: null, pendingPings: new Map(), pendingRequests: new Map(), reconnectAttempt: existing?.reconnectAttempt || 0, reconnectTimer: null, pingTimer: null, lastLatencyMs: null, lastConnectedAt: null };
        this.connections.set(endpoint.url, connection);
        connection.socket.onmessage = event => this.onMessage(connection, event);
        connection.socket.onclose = () => {
            if (this.connections.get(endpoint.url) !== connection) return;
            connection.state = 'reconnecting'; connection.socket = null; this.stopPings(connection);
            this.rejectPending(connection, new Error('D-MASH node disconnected'));
            this.scheduleReconnect(connection); this.updateState();
        };
        connection.socket.onerror = () => { connection.error = 'connection failed'; this.updateState(); };
    },
    onMessage(connection, event) {
        const message = JSON.parse(event.data);
        if (message.type === 'CHALLENGE') {
            if (message.protocol !== 'DMP-C' || message.version !== 2 || message.auth_mode !== 'DEVICE_AUTH_V1' ||
                !/^[0-9a-f]{64}$/i.test(message.node_id || '') || !message.session_id || !message.nonce ||
                !Number.isInteger(message.expires_at) || message.expires_at <= Math.floor(Date.now() / 1000)) {
                connection.socket.close(1008, 'invalid device auth challenge');
                connection.error = 'invalid device-auth challenge'; this.updateState();
                return;
            }
            window.DeviceRoot.transportIdentity(message.node_id).then(transport => {
                const clientNonce = this.toBase64(crypto.getRandomValues(new Uint8Array(32)));
                const transcript = new TextEncoder().encode(
                    `DMP-C|2|DEVICE_AUTH_V1|${transport.nodeId}|${message.session_id}|${message.nonce}|${clientNonce}|${message.expires_at}`
                );
                const signature = window.nacl.sign.detached(transcript, transport.signing.secretKey);
                connection.socket.send(JSON.stringify({
                    type: 'AUTH', auth_mode: 'DEVICE_AUTH_V1',
                    public_key: window.Core.bytesToHex(transport.signing.publicKey), client_nonce: clientNonce,
                    signature: this.toBase64(signature)
                }));
            }).catch(error => {
                connection.socket.close(1008, 'device auth unavailable');
                connection.error = error.message; this.updateState();
            });
        } else if (message.type === 'AUTH_OK') {
            if (message.auth_mode !== 'DEVICE_AUTH_V1' || message.version !== 2) {
                connection.socket.close(1008, 'unexpected auth mode'); connection.error = 'unexpected auth mode'; this.updateState(); return;
            }
            connection.reconnectAttempt = 0; connection.error = null; connection.state = 'connected';
            connection.capabilities = new Set(Array.isArray(message.capabilities) ? message.capabilities : []);
            connection.lastConnectedAt = Date.now(); this.updateState();
            connection.socket.send(JSON.stringify({ type: 'STATUS', request_id: crypto.randomUUID() }));
            this.syncNotificationBeacon().catch(error => this.showMessage(`Beacon registration failed: ${error.message}`, true));
            this.armStoredRoutes();
            this.startPings(connection);
        } else if (message.type === 'DELIVERY_AVAILABLE') {
            // The ciphertext stays in the Node mailbox until ACK. This signal
            // merely wakes the authenticated local PWA to perform PULL.
            window.dispatchEvent(new CustomEvent('dmash-delivery-available', { detail: message }));
        } else if (message.type === 'PONG') {
            const started = connection.pendingPings.get(message.request_id);
            if (started) {
                connection.pendingPings.delete(message.request_id);
                connection.lastLatencyMs = Math.round(performance.now() - started); this.updateState();
            }
        } else if (message.request_id && connection.pendingRequests.has(message.request_id)) {
            const pending = connection.pendingRequests.get(message.request_id);
            connection.pendingRequests.delete(message.request_id);
            if (message.type === 'ERROR') pending.reject(new Error(message.code || 'node error'));
            else pending.resolve(message);
        } else if (message.type === 'ERROR') { connection.error = message.code || 'node error'; this.updateState(); }
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
    async removeNotificationBeacon(beaconHandle) {
        return this.signedOriginRequest('BEACON_REMOVE', '/v1/beacon/remove', { beacon_handle: beaconHandle });
    },
    ping(connection) {
        if (connection?.state !== 'connected' || connection.socket?.readyState !== WebSocket.OPEN) return;
        const requestId = crypto.randomUUID();
        connection.pendingPings.set(requestId, performance.now());
        connection.socket.send(JSON.stringify({ type: 'PING', request_id: requestId }));
    },
    startPings(connection) {
        this.stopPings(connection);
        this.ping(connection);
        connection.pingTimer = setInterval(() => this.ping(connection), 15000);
    },
    stopPings(connection) {
        if (!connection) return this.connections.forEach(item => this.stopPings(item));
        clearInterval(connection.pingTimer);
        connection.pingTimer = null;
        connection.pendingPings.clear();
    },
    requestOn(connection, type, payload = {}) {
        if (!connection || connection.state !== 'connected' || connection.socket?.readyState !== WebSocket.OPEN) {
            return Promise.reject(new Error('D-MASH node is not connected'));
        }
        const requestId = crypto.randomUUID();
        const message = { ...payload, type, request_id: requestId };
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                connection.pendingRequests.delete(requestId);
                reject(new Error(`${type} timed out`));
            }, 15000);
            connection.pendingRequests.set(requestId, {
                resolve: value => { clearTimeout(timeout); resolve(value); },
                reject: error => { clearTimeout(timeout); reject(error); }
            });
            try { connection.socket.send(JSON.stringify(message)); }
            catch (error) {
                clearTimeout(timeout); connection.pendingRequests.delete(requestId); reject(error);
            }
        });
    },
    request(type, payload = {}) {
        const preferred = this.connections.get(this.active?.url);
        const connection = preferred?.state === 'connected' && preferred.capabilities.has(type)
            ? preferred : this.connectedConnections().find(item => item.capabilities.has(type));
        return this.requestOn(connection, type, payload);
    },
    async requestAll(type, payload = {}) {
        const connections = this.connectedConnections().filter(connection => connection.capabilities.has(type));
        if (!connections.length) throw new Error('No connected D-MASH node supports this operation');
        const results = await Promise.allSettled(connections.map(connection => this.requestOn(connection, type, payload)));
        const successes = results.filter(result => result.status === 'fulfilled').map(result => result.value);
        if (!successes.length) throw results[0].reason;
        return successes;
    },
    registerInboundLocator(locator) {
        return this.requestAll('REGISTER_INBOUND_LOCATOR', { locator }).then(results => results[0]);
    },
    unregisterInboundLocator(locator) {
        return this.requestAll('UNREGISTER_INBOUND_LOCATOR', { locator }).then(results => results[0]);
    },
    registerNotificationBeacon(beaconHandle) {
        return this.requestAll('REGISTER_NOTIFICATION_BEACON', { beacon_handle: beaconHandle });
    },
    unregisterNotificationBeacon(beaconHandle) {
        return this.requestAll('UNREGISTER_NOTIFICATION_BEACON', { beacon_handle: beaconHandle });
    },
    async bindNotificationBeacon(locator) {
        if (!locator || !window.DeviceRoot?.notificationBeaconHandle) return [];
        const beaconHandle = await window.DeviceRoot.notificationBeaconHandle();
        const eligible = this.connectedConnections().filter(connection =>
            connection.endpoint.notificationEnabled === true && connection.capabilities.has('BIND_LOCATOR_NOTIFICATION_BEACON')
        );
        if (!eligible.length) return [];
        await Promise.all(eligible.map(connection => this.requestOn(connection, 'REGISTER_NOTIFICATION_BEACON', { beacon_handle: beaconHandle })));
        return Promise.all(eligible.map(connection => this.requestOn(connection, 'BIND_LOCATOR_NOTIFICATION_BEACON', { locator, beacon_handle: beaconHandle })));
    },
    notificationBeaconEnabled(endpoint = this.active) {
        return endpoint?.notificationEnabled === true;
    },
    setNotificationBeaconEnabled(enabled, endpoint = this.active) {
        if (!endpoint) throw new Error('Select a node first');
        endpoint.notificationEnabled = enabled === true;
        this.save();
    },
    async syncNotificationBeacon(connection = null) {
        if (!window.DeviceRoot?.notificationBeaconHandle) return [];
        const eligible = (connection ? [connection] : this.connectedConnections()).filter(item =>
            item?.endpoint?.notificationEnabled === true && item.capabilities.has('REGISTER_NOTIFICATION_BEACON')
        );
        if (!eligible.length) return [];
        const beaconHandle = await window.DeviceRoot.notificationBeaconHandle();
        return Promise.all(eligible.map(item => this.requestOn(item, 'REGISTER_NOTIFICATION_BEACON', { beacon_handle: beaconHandle })));
    },
    startProbe(routeLocator, backRouteLocator, options = {}) {
        return this.requestAll('START_PROBE', {
            route_locator: routeLocator, back_route_locator: backRouteLocator, ...options
        }).then(results => results[0]);
    },
    async submitEnvelope(routeLocator, envelope) {
        const results = await this.requestAll('SUBMIT_ENVELOPE', { route_locator: routeLocator, envelope });
        return results[0];
    },
    async pull(locatorHandle) {
        const connections = this.connectedConnections().filter(connection => connection.capabilities.has('PULL'));
        if (!connections.length) throw new Error('No connected D-MASH node supports this operation');
        const results = await Promise.allSettled(connections.map(async connection => ({
            nodeUrl: connection.endpoint.url,
            result: await this.requestOn(connection, 'PULL', { locator_handle: locatorHandle })
        })));
        const successful = results.filter(item => item.status === 'fulfilled').map(item => item.value);
        if (!successful.length) throw results[0].reason;
        // Delivery IDs are node-local mailbox IDs.  Preserve their origin so
        // ACK is never broadcast to a different node's mailbox.
        return {
            ...successful[0].result,
            packets: successful.flatMap(({ nodeUrl, result }) => (result.packets || []).map(packet => ({ ...packet, _nodeUrl: nodeUrl })))
        };
    },
    async ack(deliveryId, nodeUrl = null) {
        const connection = nodeUrl ? this.connections.get(nodeUrl) : null;
        if (connection) return this.requestOn(connection, 'ACK', { delivery_id: deliveryId });
        const results = await this.requestAll('ACK', { delivery_id: deliveryId });
        return results[0];
    },
    rejectPending(connection, error) {
        for (const pending of connection.pendingRequests.values()) pending.reject(error);
        connection.pendingRequests.clear();
    },
    disconnect(reconnect = false) {
        clearTimeout(this.reconnectTimer); this.reconnectTimer = null;
        for (const connection of this.connections.values()) {
            clearTimeout(connection.reconnectTimer); this.stopPings(connection);
            this.rejectPending(connection, new Error('D-MASH node disconnected'));
            if (connection.socket) connection.socket.close(1000, 'client disconnect');
        }
        this.connections.clear(); this.socket = null;
        this.setState('disconnected');
        if (reconnect) this.scheduleReconnect();
    },
    disconnectEndpoint(url) {
        const connection = this.connections.get(url);
        if (!connection) return;
        clearTimeout(connection.reconnectTimer); this.stopPings(connection);
        this.rejectPending(connection, new Error('D-MASH node disconnected'));
        this.connections.delete(url); connection.socket?.close(1000, 'client disconnect');
        this.updateState();
    },
    scheduleReconnect(connection) {
        if (connection) {
            if (!this.connections.has(connection.endpoint.url) || connection.reconnectTimer) return;
            const delay = Math.min(30000, 1000 * (2 ** connection.reconnectAttempt++));
            connection.reconnectTimer = setTimeout(() => { connection.reconnectTimer = null; this.connectEndpoint(connection.endpoint); }, delay);
            return;
        }
        if (this.reconnectTimer) return;
        this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; this.connect().catch(error => this.setState('error', error.message)); }, 1000);
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
    importNodeProvisioning(value) {
        let packageData;
        try { packageData = JSON.parse(value); } catch (_) { throw new Error('Нужен QR пакета D-MASH NODE V1'); }
        if (packageData?.type !== 'DMASH_NODE_V1' || typeof packageData.url !== 'string') throw new Error('Некорректный QR узла');
        // A QR may carry a password only when its creator explicitly elected
        // that option. Current public DMP-C nodes use DEVICE_AUTH_V1 only;
        // password metadata is stored as provisioning data, never transmitted.
        const endpoint = this.add(packageData.url, packageData.label || '', { password: packageData.password || null });
        this.select(endpoint.url);
        return endpoint;
    },
    openNodeScanner() {
        if (window.Core) Core.flipLockSuppressed = true;
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        box.innerHTML = '<h4>СКАНИРОВАТЬ QR УЗЛА</h4><div id="node-qr-reader" style="min-height:240px;background:#000"></div>';
        const cancel = this.makeButton('ОТМЕНА', () => {
            this.nodeScanner?.stop().catch(() => {}).finally(() => { this.nodeScanner = null; if (window.Core) Core.flipLockSuppressed = false; this.renderSettings(); });
        });
        box.appendChild(cancel); modal.appendChild(box);
        setTimeout(async () => {
            try {
                this.nodeScanner = new Html5Qrcode('node-qr-reader');
                await this.nodeScanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: 220 }, async value => {
                    try {
                        const endpoint = this.importNodeProvisioning(value);
                        await this.nodeScanner.stop(); this.nodeScanner = null; if (window.Core) Core.flipLockSuppressed = false;
                        this.renderSettings(); this.showMessage(`Узел «${endpoint.label}» добавлен. Подключение — отдельной кнопкой.`);
                    } catch (error) { this.showMessage(error, true); }
                });
            } catch (_) { if (window.Core) Core.flipLockSuppressed = false; this.showMessage('Камера недоступна', true); }
        }, 100);
    },
    showNodeQR(endpoint) {
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const target = document.createElement('div'); target.id = 'node-qr-target'; target.style.cssText = 'background:#fff;padding:12px;margin:12px auto;width:max-content';
        const include = document.createElement('label'); include.style.cssText = 'display:block;text-align:left;font-size:.75rem;color:#ccc';
        const toggle = document.createElement('input'); toggle.type = 'checkbox'; toggle.disabled = !endpoint.password;
        include.append(toggle, document.createTextNode(endpoint.password ? ' ВКЛЮЧИТЬ ПАРОЛЬ В QR (небезопасно)' : ' Пароль для узла не задан'));
        const render = () => {
            target.replaceChildren();
            const payload = { type: 'DMASH_NODE_V1', version: 1, url: endpoint.url, label: endpoint.label };
            if (toggle.checked && endpoint.password) payload.password = endpoint.password;
            if (window.QRCode) new QRCode(target, { text: JSON.stringify(payload), width: 210, height: 210 });
        };
        toggle.onchange = render; render();
        const title = document.createElement('h4'); title.textContent = 'QR УЗЛА';
        box.append(title, target, include, this.makeButton('НАЗАД', () => this.renderSettings())); modal.appendChild(box);
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
    renderNodeSettings(endpoint = this.active) {
        if (!endpoint) return this.renderSettings();
        this.select(endpoint.url);
        const modal = document.getElementById('sys-modal'); modal.replaceChildren(); modal.style.display = 'flex';
        const box = document.createElement('div'); box.className = 'sys-modal-box';
        const title = document.createElement('h4'); title.textContent = 'НАСТРОЙКИ УЗЛА';
        const identity = document.createElement('p');
        identity.style.cssText = 'margin:0 0 14px;text-align:left;color:#ccc;font-size:.8rem;word-break:break-word;white-space:pre-line';
        identity.textContent = `${endpoint.label}\n${endpoint.url}`;
        const autoConnect = document.createElement('label');
        autoConnect.style.cssText = 'display:block;text-align:left;margin:0 0 10px;font-size:.78rem;color:#ccc';
        const autoToggle = document.createElement('input'); autoToggle.type = 'checkbox'; autoToggle.checked = endpoint.autoConnect !== false;
        autoToggle.onchange = () => { endpoint.autoConnect = autoToggle.checked; this.save(); };
        autoConnect.append(autoToggle, document.createTextNode(' АВТОПОДКЛЮЧЕНИЕ'));
        const notification = document.createElement('p');
        notification.style.cssText = 'margin:0 0 12px;text-align:left;font-size:.78rem;color:#aaa;line-height:1.35';
        notification.textContent = 'Если PWA отключена, узел отправляет на Origin только подписанный и зашифрованный сигнал типа события.';
        const notify = this.makeButton(endpoint.notificationEnabled ? 'ВЫКЛЮЧИТЬ УВЕДОМЛЕНИЯ' : 'РАЗРЕШИТЬ УВЕДОМЛЕНИЯ', async () => {
            try {
                const enabled = endpoint.notificationEnabled !== true;
                this.setNotificationBeaconEnabled(enabled, endpoint);
                const connection = this.connections.get(endpoint.url);
                if (enabled && connection?.state === 'connected') await this.syncNotificationBeacon(connection);
                if (!enabled && connection?.state === 'connected' && connection.capabilities.has('UNREGISTER_NOTIFICATION_BEACON')) {
                    await this.requestOn(connection, 'UNREGISTER_NOTIFICATION_BEACON', { beacon_handle: await window.DeviceRoot.notificationBeaconHandle() });
                }
                this.renderNodeSettings(endpoint);
            } catch (error) { this.setNotificationBeaconEnabled(endpoint.notificationEnabled !== true, endpoint); this.showMessage(error, true); }
        });
        const primary = this.makeButton('СДЕЛАТЬ ОСНОВНЫМ', () => { this.select(endpoint.url); this.renderSettings(); });
        const remove = this.makeButton('УДАЛИТЬ УЗЕЛ', () => {
            if (window.confirm(`Удалить узел «${endpoint.label}» только из этого устройства?`)) { this.remove(endpoint.url); this.renderSettings(); }
        });
        remove.style.cssText = 'color:#ff7b7b;border-color:#633';
        const back = this.makeButton('НАЗАД', () => this.renderSettings());
        box.append(title, identity, autoConnect, notification, primary, notify, remove, back); modal.appendChild(box);
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
        endpoint.style.cssText = 'margin:0 0 8px;color:#ccc;word-break:break-word;text-align:left;font-size:0.8rem';
        endpoint.textContent = this.active ? `Основной узел для одиночных запросов: ${this.active.label}` : 'Основной узел пока не выбран.';
        const nodeList = document.createElement('div'); nodeList.id = 'dmash-node-list';
        nodeList.style.cssText = 'margin:0 0 12px;max-height:28vh;overflow:auto';
        box.append(endpoint, nodeList); this.renderNodeList(nodeList);
        if (this.active) {
            const selected = this.active;
        }
        const add = this.makeButton('ДОБАВИТЬ УЗЕЛ', () => {
            this.openPrompt('ДОБАВИТЬ УЗЕЛ', 'wss://node.example/dmp-c/v1', (url) => {
                const endpoint = this.add(url);
                this.select(endpoint.url);
                this.renderSettings();
            });
        });
        const scan = this.makeButton('ДОБАВИТЬ ПО QR', () => this.openNodeScanner());
        const disconnect = this.makeButton('ОТКЛЮЧИТЬ ВСЕ', () => { this.disconnect(false); this.renderSettings(); });
        const close = this.makeButton('НАЗАД', () => { if (window.Core?.openSettings) Core.openSettings(); else modal.style.display = 'none'; });
        box.append(add, scan, disconnect, close); modal.appendChild(box);
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
