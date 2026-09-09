'use strict';
(function (global) {
    // Account adapters create/verify account bootstrap; this coordinator only
    // persists transitions and sends opaque Device payloads. A failed send
    // leaves the exact signed message available for an idempotent retry.
    class ContactFlowV3 {
        constructor({store, activeAccount, makeBootstrap, importPeer, send}) {
            Object.assign(this, {store, activeAccount, makeBootstrap, importPeer, send});
            this.serial = Promise.resolve();
        }
        exclusive(fn) {const result = this.serial.then(fn); this.serial = result.catch(() => {}); return result;}
        read(id) {return this.store._get('contact-flow:' + id);}
        write(id, state) {return this.store._write('contact-flow:' + id, {...state, record: 'contact_flow'});}
        recordOutgoing(request, certificate, slot = this.activeAccount()) {
            return this.exclusive(async () => {
                request = global.ContactPayloads.validateRequest(request);
                if (!request.protocol_capabilities.includes('CONTACT_BOOTSTRAP_V3')) throw Error('Contact bootstrap v3 is required');
                if (!global.DeviceRoutes.verifyCertificate(certificate) || !global.DeviceRoutes.verifyCertificate(request.reply_route_certificate)) throw Error('Invalid contact route certificate');
                if (!slot || this.activeAccount() !== slot) throw Error('Откройте выбранный Account для нового контакта');
                const existing = await this.read(request.request_id);
                if (existing) {
                    if (existing.slot !== slot || existing.peerCertificate.routeId !== certificate.routeId ||
                        global.DmashSecureSession.canonical(existing.request) !== global.DmashSecureSession.canonical(request)) throw Error('Contact request context changed');
                    return;
                }
                await this.write(request.request_id, {role: 'caller', slot, request,
                    localCertificate: request.reply_route_certificate, peerCertificate: certificate, status: 'requested'});
            });
        }
        accept(request, localCertificate, displayName, slot = this.activeAccount()) {
            return this.exclusive(async () => {
                request = global.ContactPayloads.validateRequest(request);
                if (!request.protocol_capabilities.includes('CONTACT_BOOTSTRAP_V3')) throw Error('Отправителю нужно обновить Contact bootstrap до v3');
                if (!global.DeviceRoutes.verifyCertificate(localCertificate) || !global.DeviceRoutes.verifyCertificate(request.reply_route_certificate)) throw Error('Invalid contact route certificate');
                if (!slot || this.activeAccount() !== slot) throw Error('Откройте выбранный Account');
                let state = await this.read(request.request_id);
                if (!state) {
                    const accept = await this.makeBootstrap({request, localCertificate,
                        peerCertificate: request.reply_route_certificate, phase: 'ACCEPT', acceptHash: null, displayName, slot});
                    state = {role: 'acceptor', slot, request, localCertificate,
                        peerCertificate: request.reply_route_certificate, accept, status: 'accept_prepared'};
                    await this.write(request.request_id, state);
                }
                if (state.role !== 'acceptor' || state.slot !== slot) throw Error('Contact acceptance owner mismatch');
                if (state.localCertificate.routeId !== localCertificate.routeId ||
                    global.DmashSecureSession.canonical(state.request) !== global.DmashSecureSession.canonical(request)) throw Error('Contact request context changed');
                if (state.status === 'established') return state.status;
                await this.send(state.peerCertificate, state.accept);
                state.status = 'accept_sent'; state.lastSentAt = Date.now(); await this.write(request.request_id, state);
                return state.status;
            });
        }
        receive(routeId, message) {
            return this.exclusive(async () => {
                const id = message?.body?.request_id, state = await this.read(id);
                if (!state || routeId !== state.localCertificate.routeId) throw Error('Unsolicited contact bootstrap');
                const phase = state.role === 'caller' ? 'ACCEPT' : 'CONFIRM';
                const acceptHash = phase === 'CONFIRM' ? await global.ContactBootstrapV3.digest(state.accept) : null;
                global.ContactBootstrapV3.verify(message, {requestId: id, recipientRouteId: routeId,
                    senderRouteId: state.peerCertificate.routeId, phase, acceptHash});
                const old = state[phase.toLowerCase()];
                if (old && await global.ContactBootstrapV3.digest(old) !== await global.ContactBootstrapV3.digest(message)) throw Error('Conflicting contact bootstrap replay');
                state[phase.toLowerCase()] = message;
                if (phase === 'ACCEPT' || state.status !== 'established') state.status = 'bootstrap_received';
                await this.write(id, state);
                return 'DEVICE_STORED';
            });
        }
        resume() {
            return this.exclusive(async () => {
                const slot = this.activeAccount();
                if (!slot) return;
                for (const row of await this.store.store.all()) {
                    const state = await this.store._open(row);
                    if (state.record !== 'contact_flow' || state.slot !== slot || state.status === 'established') continue;
                    const id = state.request.request_id;
                    if (state.role === 'acceptor' && state.accept && !state.confirm) {
                        if ((!state.lastSentAt || Date.now() - state.lastSentAt >= 30000) && state.accept.body.expires_at > Math.floor(Date.now() / 1000)) {
                            await this.send(state.peerCertificate, state.accept);
                            state.lastSentAt = Date.now(); state.status = 'accept_sent'; await this.write(id, state);
                        }
                        continue;
                    }
                    if (state.role === 'caller' && state.accept) {
                        if (!state.confirm) {
                            state.confirm = await this.makeBootstrap({request: state.request,
                                localCertificate: state.localCertificate, peerCertificate: state.peerCertificate,
                                phase: 'CONFIRM', acceptHash: await global.ContactBootstrapV3.digest(state.accept),
                                displayName: state.request.sender_display_name, slot});
                            await this.write(id, state);
                        }
                        await this.importPeer(state.accept.body, slot);
                        await this.send(state.peerCertificate, state.confirm);
                    } else if (state.role === 'acceptor' && state.confirm) {
                        await this.importPeer(state.confirm.body, slot);
                    } else continue;
                    state.status = 'established'; await this.write(id, state);
                }
            });
        }
    }
    global.ContactFlowV3 = ContactFlowV3;
    if (typeof module !== 'undefined') module.exports = ContactFlowV3;
})(typeof window !== 'undefined' ? window : globalThis);
