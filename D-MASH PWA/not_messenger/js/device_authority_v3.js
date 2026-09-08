'use strict';
(function (global) {
    const bytes = value => new TextEncoder().encode(value);
    const hex = value => Array.from(value, b => b.toString(16).padStart(2, '0')).join('');
    const codec = () => global.DmashSecureSession;
    class DeviceAuthorityV3 {
        constructor(client, { deviceRoot = global.DeviceRoot, mine = args => global.DmashResourcePow.mineActivationPow(args) } = {}) {
            this.client = client; this.deviceRoot = deviceRoot; this.mine = mine;
            this.dnss = null; this.binding = null;
        }
        async work(kind, resource) {
            const difficulty = this.client.resourcePowDifficulty;
            if (!Number.isInteger(difficulty) || difficulty < 20 || difficulty > 24) throw new Error('Invalid Node resource work policy');
            return this.mine({ nodeId: this.client.nodeId, activationType: kind,
                deviceTransportKey: this.client.transportPublicKey, resource,
                difficulty, expiresAt: Math.floor(Date.now() / 1000) + 900 });
        }
        bind() {
            if (!this.binding) this.binding = this._bind().catch(error => { this.binding = null; throw error; });
            return this.binding;
        }
        async _bind() {
            const material = await this.deviceRoot.deviceMaterial('dnss/v1/' + this.client.nodeId,
                () => global.crypto.getRandomValues(new Uint8Array(16)));
            if (!(material instanceof Uint8Array) || material.length !== 16) throw new Error('Invalid persisted DNSS');
            this.dnss = new Uint8Array(material);
            const payload = { dnss: hex(this.dnss) };
            try { await this.client.request('REGISTER_DNSS', payload); }
            catch (error) {
                if (error.message !== 'DNSS_NOT_REGISTERED') throw error;
                // A Node restart discards its runtime registration. The saved
                // pairwise DNSS remains unchanged; only resource work repeats.
                payload.pow = await this.work('DNSS', this.dnss);
                await this.client.request('REGISTER_DNSS', payload);
            }
            return this;
        }
        async route(operation, { kind, routeId, signing, generation, expiresAt, entryGrant = null }, payload = {}) {
            if (!['REGISTER_ROUTE', 'UNREGISTER_ROUTE', 'START_PROBE'].includes(operation)) throw new Error('Invalid route operation');
            await this.bind();
            const requestId = global.crypto.randomUUID();
            const auth = { kind, route_id: routeId, public_key: codec().b64(signing.publicKey), generation, expires_at: expiresAt };
            const transcript = 'D-MASH|ROUTE-AUTH|V3\0' + codec().canonical({
                node_id: this.client.nodeId, session: hex(this.client.session.transcriptHash), dnss: hex(this.dnss),
                operation, request_id: requestId, ...auth
            });
            auth.signature = codec().b64(global.nacl.sign.detached(bytes(transcript), signing.secretKey));
            const request = { ...payload, authorization: auth };
            if (operation === 'REGISTER_ROUTE') {
                request.pow = await this.work(kind === 'PUBLIC' ? 'ENTRY_GRANT' : 'PRIVATE_ROUTE', routeId);
                if (kind === 'PUBLIC') request.entry_grant = entryGrant;
            }
            if (operation === 'START_PROBE') request.back_route_locator = routeId;
            return this.client.request(operation, request, requestId);
        }
        close() { this.dnss?.fill(0); this.dnss = null; this.binding = null; }
    }
    global.DeviceAuthorityV3 = DeviceAuthorityV3;
    if (typeof module !== 'undefined') module.exports = DeviceAuthorityV3;
})(typeof window !== 'undefined' ? window : globalThis);
