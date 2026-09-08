"use strict";

(function (global) {
    class DeviceClientV3 {
        constructor({ url, nodeId = null, identity, onEvent = () => {}, onClose = () => {}, socketFactory = url => new WebSocket(url) }) {
            this.url = url; this.nodeId = nodeId; this.identity = identity;
            this.onEvent = onEvent; this.onClose = onClose; this.socketFactory = socketFactory;
            this.pending = new Map(); this.session = null; this.handshake = null; this.capabilities = new Set();
            this.state = 'disconnected'; this.incoming = Promise.resolve(); this.socket = null;
        }
        connect() {
            if (this.state !== 'disconnected') throw new Error('Connection already started');
            this.state = 'welcome';
            const ready = new Promise((resolve, reject) => { this.resolveReady = resolve; this.rejectReady = reject; });
            this.deadline = setTimeout(() => this.fail(new Error('DMP-C v3 handshake timed out')), 15000);
            try { this.socket = this.socketFactory(this.url); }
            catch (error) { this.fail(error); return ready; }
            this.socket.onmessage = event => {
                // Handshake cryptography is async; serialize callbacks so AUTH_OK
                // and secure data cannot overtake key derivation/sequence checks.
                this.incoming = this.incoming.then(() => this.receive(event.data)).catch(error => this.fail(error));
            };
            this.socket.onerror = () => this.fail(new Error('DMP-C connection failed'));
            this.socket.onclose = () => this.fail(new Error('DMP-C disconnected'), false);
            return ready;
        }
        async receive(raw) {
            if (typeof raw !== 'string' || raw.length > 2 * 1024 * 1024) throw new Error('Invalid v3 frame size');
            const frame = JSON.parse(raw);
            if (this.state === 'welcome') {
                if (frame.type !== 'WELCOME' || frame.protocol !== 'DMP-C' || frame.version !== 3 || !/^[0-9a-f]{64}$/.test(frame.node_id || '')) throw new Error('Node does not support DMP-C v3');
                if (this.nodeId && this.nodeId !== frame.node_id) throw new Error('Node identity pin mismatch');
                this.nodeId = frame.node_id;
                this.state = 'identity';
                const identity = await this.identity(this.nodeId);
                if (this.state !== 'identity') { identity.signing?.secretKey?.fill(0); throw new Error('Connection closed during identity derivation'); }
                this.transportPublicKey = Array.from(identity.signing.publicKey, b => b.toString(16).padStart(2, '0')).join('');
                this.handshake = new global.DmashSecureSession.Initiator(identity.signing);
                this.transportSigning = identity.signing;
                this.state = 'challenge';
                this.socket.send(JSON.stringify(this.handshake.initiate()));
                return;
            }
            if (this.state === 'challenge') {
                this.state = 'deriving';
                const { auth, session } = await this.handshake.finish(frame, this.nodeId);
                if (this.state !== 'deriving') { session.close(); throw new Error('Connection closed during handshake'); }
                this.session = session;
                this.state = 'authorizing';
                this.socket.send(JSON.stringify(auth));
                this.transportSigning.secretKey.fill(0); this.transportSigning = null;
                return;
            }
            if (!this.session) throw new Error('Unexpected v3 handshake frame');
            const message = this.session.open(frame);
            if (this.state === 'authorizing') {
                if (message.type !== 'AUTH_OK' || message.version !== 3 || message.role !== 'DEVICE' || !Array.isArray(message.capabilities)) throw new Error('Invalid v3 authorization');
                this.capabilities = new Set(message.capabilities);
                this.state = 'connected'; clearTimeout(this.deadline);
                this.resolveReady(this); return;
            }
            if (this.state !== 'connected') throw new Error('Closed v3 session');
            const pending = this.pending.get(message.request_id);
            if (pending) {
                this.pending.delete(message.request_id); clearTimeout(pending.timer);
                if (message.type === 'ERROR') pending.reject(new Error(message.code || 'Node operation failed'));
                else pending.resolve(message);
            } else await this.onEvent(message);
        }
        request(type, payload = {}, requestId = global.crypto.randomUUID()) {
            if (this.state !== 'connected' || !this.capabilities.has(type)) return Promise.reject(new Error('Node operation unavailable: ' + type));
            if (this.pending.has(requestId)) return Promise.reject(new Error('Duplicate request id'));
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => { this.pending.delete(requestId); reject(new Error(type + ' timed out')); }, 15000);
                this.pending.set(requestId, { resolve, reject, timer });
                try { this.socket.send(JSON.stringify(this.session.seal({ ...payload, type, request_id: requestId }))); }
                catch (error) { this.fail(error); }
            });
        }
        fail(error, closeSocket = true) {
            if (this.state === 'disconnected') return;
            this.state = 'disconnected'; clearTimeout(this.deadline);
            this.handshake?.close(); this.session?.close();
            this.transportSigning?.secretKey?.fill(0); this.transportSigning = null;
            for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
            this.pending.clear(); this.rejectReady?.(error);
            if (closeSocket && this.socket) this.socket.close(1000, 'v3 session ended');
            this.onClose(error);
        }
        close() { this.fail(new Error('Device disconnected')); }
    }
    global.DeviceClientV3 = DeviceClientV3;
    if (typeof module !== 'undefined') module.exports = DeviceClientV3;
})(typeof window !== 'undefined' ? window : globalThis);
