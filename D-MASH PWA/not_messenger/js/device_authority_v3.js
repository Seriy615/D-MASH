'use strict';
(function (global) {
    const bytes = value => new TextEncoder().encode(value);
    const hex = value => Array.from(value, b => b.toString(16).padStart(2, '0')).join('');
    const codec = () => global.DmashSecureSession;
    class DeviceAuthorityV3 {
        #workFlights = new Map(); #issuedWork = new Map(); #epoch = 0; #closed = false;
        constructor(client, { deviceRoot = global.DeviceRoot, mine = args => global.DmashResourcePow.mineActivationPow(args) } = {}) {
            this.client = client; this.deviceRoot = deviceRoot; this.mine = mine;
            this.dnss = null; this.binding = null;
        }
        #check() { if (this.#closed) throw new Error('Device authority closed'); }
        async #mineUnique(args) {
            // Node consumes each proof digest globally when a route candidate
            // changes. Independent jobs need distinct nonce searches even when
            // they target the same route within one clock second.
            for (let attempt = 0; attempt < 4; attempt++) {
                this.#check();
                const now = Math.floor(Date.now() / 1000);
                for (const [digest, expiry] of this.#issuedWork) if (expiry <= now) this.#issuedWork.delete(digest);
                if (this.#issuedWork.size >= 4096) throw new Error('Route work quota');
                const random = global.crypto.getRandomValues(new Uint32Array(2));
                const startNonce = (random[0] & 0xfffff) * 0x100000000 + random[1];
                const proof = await this.mine({...args, startNonce});
                this.#check();
                if (!proof || !Number.isSafeInteger(proof.nonce) || proof.nonce < startNonce ||
                    !/^[0-9a-f]{64}$/.test(proof.digest) || proof.expires_at !== args.expiresAt) throw new Error('Invalid route work proof');
                if (this.#issuedWork.has(proof.digest)) continue;
                this.#issuedWork.set(proof.digest, proof.expires_at);
                return proof;
            }
            throw new Error('Route work digest collision');
        }
        async work(kind, resource, candidate = null) {
            this.#check();
            const difficulty = this.client.resourcePowDifficulty;
            if (!Number.isInteger(difficulty) || difficulty < 20 || difficulty > 24) throw new Error('Invalid Node resource work policy');
            const session = this.client.session?.transcriptHash;
            if (!(session instanceof Uint8Array) || session.length !== 32 ||
                typeof this.client.nodeId !== 'string' || typeof this.client.transportPublicKey !== 'string' ||
                !(typeof resource === 'string' || resource instanceof Uint8Array)) throw new Error('Route work context unavailable');
            const nodeId = this.client.nodeId, transportKey = this.client.transportPublicKey;
            const sessionHex = hex(session), material = resource instanceof Uint8Array ? resource.slice() : resource;
            // Backend RouteRegistration equality includes owner, generation,
            // expiry, kind and public key. Only that exact candidate may share
            // an in-flight proof; request IDs and signatures remain per call.
            const key = codec().canonical({nodeId, transportKey, session:sessionHex, kind,
                resource:typeof material === 'string' ? ['text',material] : ['bytes',hex(material)], difficulty, candidate});
            let flight = this.#workFlights.get(key);
            if (!flight) {
                if (this.#workFlights.size >= 64) throw new Error('Route work concurrency limit');
                flight = Promise.resolve().then(() => this.#mineUnique({nodeId, activationType:kind,
                    deviceTransportKey:transportKey, resource:material, difficulty,
                    expiresAt:Math.floor(Date.now() / 1000) + 900}));
                this.#workFlights.set(key, flight);
            }
            const epoch = this.#epoch;
            try {
                const proof = await flight;
                this.#check();
                if (this.#epoch !== epoch || this.client.nodeId !== nodeId ||
                    this.client.transportPublicKey !== transportKey ||
                    this.client.resourcePowDifficulty !== difficulty ||
                    !(this.client.session?.transcriptHash instanceof Uint8Array) ||
                    hex(this.client.session.transcriptHash) !== sessionHex) throw new Error('Route work owner changed');
                return structuredClone(proof);
            } finally { if (this.#workFlights.get(key) === flight) this.#workFlights.delete(key); }
        }
        bind() {
            this.#check();
            if (!this.binding) this.binding = this._bind().catch(error => { this.binding = null; throw error; });
            return this.binding;
        }
        async _bind() {
            const material = await this.deviceRoot.deviceMaterial('dnss/v1/' + this.client.nodeId,
                () => global.crypto.getRandomValues(new Uint8Array(16)));
            this.#check();
            if (!(material instanceof Uint8Array) || material.length !== 16) throw new Error('Invalid persisted DNSS');
            this.dnss = new Uint8Array(material);
            const payload = { dnss: hex(this.dnss) };
            try { await this.client.request('REGISTER_DNSS', payload); this.#check(); }
            catch (error) {
                this.#check();
                if (error.message !== 'DNSS_NOT_REGISTERED') throw error;
                // A Node restart discards its runtime registration. The saved
                // pairwise DNSS remains unchanged; only resource work repeats.
                payload.pow = await this.work('DNSS', this.dnss);
                this.#check();
                await this.client.request('REGISTER_DNSS', payload);
            }
            this.#check();
            return this;
        }
        async route(operation, { kind, routeId, signing, generation, expiresAt, entryGrant = null }, payload = {}) {
            this.#check();
            if (!['REGISTER_ROUTE', 'UNREGISTER_ROUTE', 'START_PROBE'].includes(operation)) throw new Error('Invalid route operation');
            await this.bind();
            this.#check();
            const requestId = global.crypto.randomUUID();
            const auth = { kind, route_id: routeId, public_key: codec().b64(signing.publicKey), generation, expires_at: expiresAt };
            const transcript = 'D-MASH|ROUTE-AUTH|V3\0' + codec().canonical({
                node_id: this.client.nodeId, session: hex(this.client.session.transcriptHash), dnss: hex(this.dnss),
                operation, request_id: requestId, ...auth
            });
            auth.signature = codec().b64(global.nacl.sign.detached(bytes(transcript), signing.secretKey));
            const request = { ...payload, authorization: auth };
            if (operation === 'REGISTER_ROUTE') {
                if (kind === 'PUBLIC') request.entry_grant = entryGrant;
            }
            if (operation === 'START_PROBE') request.back_route_locator = routeId;
            let result;
            try { result = await this.client.request(operation, request, requestId); }
            catch (error) {
                this.#check();
                if (operation !== 'REGISTER_ROUTE' || error.message !== 'INVALID_RESOURCE_POW') throw error;
                const candidate = {dnss:hex(this.dnss),kind,routeId,publicKey:auth.public_key,generation,expiresAt};
                for (let attempt = 0; attempt < 2; attempt++) {
                    request.pow = await this.work(kind === 'PUBLIC' ? 'ENTRY_GRANT' : 'PRIVATE_ROUTE', routeId, candidate);
                    this.#check();
                    try { result = await this.client.request(operation, request, requestId); break; }
                    catch (retryError) {
                        this.#check();
                        if (retryError.message !== 'REPLAYED_RESOURCE_POW' || attempt === 1) throw retryError;
                    }
                }
            }
            this.#check();
            return result;
        }
        close() { if (this.#closed) return; this.#closed = true; this.#epoch++; this.#workFlights.clear(); this.#issuedWork.clear(); this.dnss?.fill(0); this.dnss = null; this.binding = null; }
    }
    global.DeviceAuthorityV3 = DeviceAuthorityV3;
    if (typeof module !== 'undefined') module.exports = DeviceAuthorityV3;
})(typeof window !== 'undefined' ? window : globalThis);
