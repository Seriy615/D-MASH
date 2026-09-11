"use strict";
(function (global) {
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    const digest = async text => new Uint8Array(await global.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    const validEndpoint = value => {
        const url = new URL(value);
        const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
        if ((url.protocol !== "wss:" && !(local && url.protocol === "ws:")) || url.username || url.password || url.hash || url.search) {
            throw new Error("Invalid signaling endpoint");
        }
        return url.href;
    };
    class WebSocketSignaling {
        constructor({endpoint, sessionId, ticket, WebSocket = global.WebSocket} = {}) {
            this.endpoint = validEndpoint(endpoint);
            this.sessionId = sessionId; this.ticket = ticket; this.WebSocket = WebSocket;
            this.queue = []; this.queueBytes = 0; this.waiter = null; this.closed = false; this.iceServers = [];
        }
        async connect() {
            if (this.closed) throw new Error("Signaling closed");
            if (this.socket) return;
            this.socket = new this.WebSocket(this.endpoint);
            this.socket.onmessage = event => {
                if (this.closed) return;
                try {
                    if (typeof event.data !== "string" || event.data.length > 512 * 1024) throw new Error("Signal size limit");
                    const value = JSON.parse(event.data);
                    if (this.waiter) { const waiter = this.waiter; this.waiter = null; waiter.resolve(value); }
                    else {
                        const bytes = new TextEncoder().encode(event.data).length;
                        if (this.queue.length >= 128 || this.queueBytes + bytes > 1024 * 1024) throw new Error("Signal queue limit");
                        this.queue.push({value, bytes}); this.queueBytes += bytes;
                    }
                } catch (_) { this.close(); }
            };
            await new Promise((resolve, reject) => {
                const timer = setTimeout(() => { this.close(); reject(new Error("Signaling connection timeout")); }, 10000);
                this.socket.onopen = () => { clearTimeout(timer); resolve(); };
                this.socket.onerror = () => { clearTimeout(timer); this.close(); reject(new Error("Signaling connection failed")); };
                this.socket.onclose = () => { clearTimeout(timer); this.close(); reject(new Error("Signaling connection closed")); };
            });
        }
        next(timeout = 10000) {
            if (this.queue.length) {
                const {value, bytes} = this.queue.shift(); this.queueBytes -= bytes;
                return Promise.resolve(value);
            }
            if (this.closed) return Promise.reject(new Error("Signaling closed"));
            if (this.waiter) return Promise.reject(new Error("Concurrent signaling reader"));
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => { this.waiter = null; reject(new Error("Signaling timeout")); }, timeout);
                this.waiter = {resolve: value => {clearTimeout(timer); resolve(value);}, reject: error => {clearTimeout(timer); reject(error);}};
            });
        }
        static async create(endpoint, options = {}) {
            const transport = new WebSocketSignaling({endpoint, ...options});
            try {
                await transport.connect();
                const callId = hex(global.crypto.getRandomValues(new Uint8Array(32)));
                const secret = global.crypto.getRandomValues(new Uint8Array(32));
                const verifier = hex(new Uint8Array(await global.crypto.subtle.digest("SHA-256", secret)));
                secret.fill(0);
                transport.socket.send(JSON.stringify({type: "CREATE", call_id: callId, secret_verifier: verifier}));
                const challenge = await transport.next();
                if (challenge.type !== "CHALLENGE" || !/^[0-9a-f]{64}$/.test(challenge.nonce) || !Number.isInteger(challenge.difficulty) || challenge.difficulty < 1 || challenge.difficulty > 20) throw new Error("Invalid admission challenge");
                let counter = 0;
                const deadline = Date.now() + 25000;
                for (; ; counter++) {
                    const hash = await digest(`${challenge.nonce}:${callId}:${verifier}:${counter}`);
                    let bits = challenge.difficulty, valid = true;
                    for (const byte of hash) { const take = Math.min(bits, 8); if ((byte >>> (8 - take)) !== 0) {valid = false; break;} bits -= take; if (!bits) break; }
                    if (valid) break;
                    if (Date.now() > deadline || transport.closed) throw new Error("Admission work timeout");
                }
                transport.socket.send(JSON.stringify({type: "PROOF", counter}));
                const created = await transport.next();
                if (created.type !== "CREATED" || ![created.session_id, created.caller_ticket, created.callee_ticket].every(v =>
                    typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v)) ||
                    !Number.isInteger(created.expires_at) || created.expires_at <= Date.now() / 1000) throw new Error("Session creation rejected");
                transport.sessionId = created.session_id; transport.ticket = created.caller_ticket;
                transport.invitation = {version: 2, call_id: callId, expires_at: created.expires_at,
                    signaling: {wss_endpoint: transport.endpoint, session_id: created.session_id, one_time_key: created.callee_ticket}};
                return transport;
            } catch (error) { transport.close(); throw error; }
        }
        async open(callId, role) {
            await this.connect(); this.callId = callId;
            this.socket.send(JSON.stringify({type: "JOIN", session_id: this.sessionId, ticket: this.ticket, role}));
            const reply = await this.next();
            if (reply.type !== "JOINED") throw new Error("Signaling join rejected");
            this.ticket = null; this.iceServers = reply.ice_servers || [];
            this.pump = (async () => {
                try {
                    while (!this.closed) {
                        const message = await this.next(3600000);
                        if (this.onmessage) await this.onmessage({...message, call_id: this.callId});
                    }
                } catch (_) { this.close(); }
            })();
        }
        async send(message) {
            if (this.closed || message.call_id !== this.callId || this.socket.readyState !== 1) throw new Error("Signaling unavailable");
            if (!["offer", "answer", "ice", "hangup"].includes(message.type) || typeof message.payload !== "string" ||
                new TextEncoder().encode(message.payload).length > 256 * 1024) throw new Error("Invalid signaling payload");
            if (this.socket.bufferedAmount > 1024 * 1024) throw new Error("Signaling backpressure");
            this.socket.send(JSON.stringify({type: message.type, payload: message.payload}));
        }
        close() {
            if (this.closed) return;
            this.closed = true;
            const waiter = this.waiter; this.waiter = null;
            if (waiter) waiter.reject(new Error("Signaling closed"));
            this.queue = []; this.queueBytes = 0; this.ticket = null;
            if (this.socket) this.socket.close();
            if (this.onclose) this.onclose();
        }
    }
    global.DmashCallSignaling = {WebSocketSignaling, validEndpoint};
})(typeof window !== "undefined" ? window : globalThis);
