'use strict';
(function (global) {
    // Account adapters create/verify account bootstrap; this coordinator only
    // persists transitions and sends opaque Device payloads. A failed send
    // leaves the exact signed message available for an idempotent retry.
    class ContactFlowV3 {
        constructor({store, activeAccount, makeBootstrap, importPeer, send, sendInitial = null,
                     clock = () => Date.now(), onChange = async () => {}}) {
            Object.assign(this, {store, activeAccount, makeBootstrap, importPeer, send, sendInitial, clock, onChange});
            this.serial = Promise.resolve();
        }
        exclusive(fn) {const result = this.serial.then(fn); this.serial = result.catch(() => {}); return result;}
        read(id) {return this.store._get('contact-flow:' + id);}
        write(id, state) {return this.store._write('contact-flow:' + id, {...state, record: 'contact_flow'});}
        async listForAccount() {
            const slot=this.activeAccount(),results=[];if(!slot)return results;
            for(const row of await this.store.store.all()){
                if(this.activeAccount()!==slot)return [];
                let state;try{state=await this.store._open(row);}catch(_){continue;}
                if(!state||state.record!=='contact_flow'||state.slot!==slot||state.status==='established'||
                    typeof state.request?.request_id!=='string'||!['caller','acceptor'].includes(state.role))continue;
                results.push({id:state.request.request_id,role:state.role,status:state.status,
                    name:state.role==='acceptor'?state.request.sender_display_name:(state.accept?.body?.display_name||'Новый контакт')});
            }
            return this.activeAccount()===slot?results:[];
        }
        recordOutgoing(request, certificate, slot = this.activeAccount(), envelope = null) {
            return this.exclusive(async () => {
                request = global.ContactPayloads.validateRequest(request);
                if (!request.protocol_capabilities.includes('CONTACT_BOOTSTRAP_V3')) throw Error('Contact bootstrap v3 is required');
                if (!global.DeviceRoutes.verifyCertificate(certificate) || !global.DeviceRoutes.verifyCertificate(request.reply_route_certificate)) throw Error('Invalid contact route certificate');
                if (!slot || this.activeAccount() !== slot) throw Error('Откройте выбранный Account для нового контакта');
                if(envelope){
                    envelope=global.ContactTransport.validateEnvelope(envelope);
                    if(envelope.type!=='CONTACT_REQUEST_V1'||envelope.request_id!==request.request_id)throw Error('Initial contact envelope context changed');
                }
                const existing = await this.read(request.request_id);
                if (existing) {
                    if (existing.slot !== slot || existing.peerCertificate.routeId !== certificate.routeId ||
                        global.DmashSecureSession.canonical(existing.request) !== global.DmashSecureSession.canonical(request)) throw Error('Contact request context changed');
                    if(envelope&&existing.initialEnvelope&&global.DmashSecureSession.canonical(existing.initialEnvelope)!==global.DmashSecureSession.canonical(envelope))throw Error('Initial contact ciphertext changed');
                    if(envelope&&!existing.initialEnvelope){existing.initialEnvelope=envelope;existing.createdAt=this.clock();existing.expiresAt=this.clock()+86400000;existing.attempts=0;existing.nextRetryAt=0;await this.write(request.request_id,existing);}
                    return;
                }
                await this.write(request.request_id, {role: 'caller', slot, request,
                    localCertificate: request.reply_route_certificate, peerCertificate: certificate,
                    status: envelope?'request_pending':'requested',...(envelope?{initialEnvelope:envelope,
                        createdAt:this.clock(),expiresAt:this.clock()+86400000,attempts:0,nextRetryAt:0}:{})});
                await this.onChange();
            });
        }
        async _dispatchInitial(state,slot){
            if(state.role!=='caller'||state.accept||!state.initialEnvelope||!this.sendInitial||this.activeAccount()!==slot)return false;
            const now=this.clock(),id=state.request.request_id;
            if(now>=state.expiresAt||state.attempts>=256){state.status='request_expired';await this.write(id,state);return false;}
            if(state.nextRetryAt>now)return false;
            state.attempts=(state.attempts||0)+1;
            state.nextRetryAt=now+Math.min(300000,5000*2**Math.min(state.attempts-1,6));
            state.status='request_pending';await this.write(id,state);
            if(this.activeAccount()!==slot)return false;
            try{
                const sent=await this.sendInitial(state.peerCertificate,state.initialEnvelope,state.localCertificate,slot);
                if(this.activeAccount()!==slot)return false;
                if(sent===false)throw Error('Initial request was not queued');
                state.status='requested';state.lastSentAt=this.clock();await this.write(id,state);return true;
            }catch(_){return false;}
        }
        dispatchInitial(id,slot=this.activeAccount()){
            return this.exclusive(async()=>{
                const state=await this.read(id);
                if(!state||state.slot!==slot||this.activeAccount()!==slot)throw Error('Contact request owner changed');
                const sent=await this._dispatchInitial(state,slot);await this.onChange();return sent;
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
                // A saved signature cannot be extended on retry. Keep the
                // original owner and ciphertext; a new request needs a new ID.
                if (!Number.isSafeInteger(state.accept?.body?.expires_at) ||
                    state.accept.body.expires_at <= Math.floor(this.clock() / 1000)) {
                    throw Error('Срок подписанного принятия истёк. Попросите собеседника отправить новый запрос. Сохранённые данные не изменены.');
                }
                if(await this.send(state.peerCertificate, state.accept)===false)throw Error('Contact acceptance was not queued');
                state.status = 'accept_sent'; state.lastSentAt = Date.now(); await this.write(request.request_id, state);
                await this.onChange();
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
                await this.onChange();
                return 'DEVICE_STORED';
            });
        }
        resume() {
            return this.exclusive(async () => {
                const slot = this.activeAccount();
                const result={processed:0,failed:0};if (!slot) return result;
                for (const row of await this.store.store.all()) {
                    if(this.activeAccount()!==slot)break;
                    try {
                    const state = await this.store._open(row);
                    if(this.activeAccount()!==slot)break;
                    if (state.record !== 'contact_flow' || state.slot !== slot || state.status === 'established') continue;
                    const id = state.request.request_id;
                    if(state.role==='caller'&&!state.accept&&state.initialEnvelope){await this._dispatchInitial(state,slot);continue;}
                    if (state.role === 'acceptor' && state.accept && !state.confirm) {
                        if ((!state.lastSentAt || Date.now() - state.lastSentAt >= 30000) && state.accept.body.expires_at > Math.floor(Date.now() / 1000)) {
                            if(await this.send(state.peerCertificate, state.accept)===false)throw Error('Contact acceptance was not queued');
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
                        if(await this.send(state.peerCertificate, state.confirm)===false)throw Error('Contact confirmation was not queued');
                    } else if (state.role === 'acceptor' && state.confirm) {
                        await this.importPeer(state.confirm.body, slot);
                    } else continue;
                    state.status = 'established'; await this.write(id, state);
                    result.processed++;
                    } catch (_) {result.failed++;}
                }
                await this.onChange();return result;
            });
        }
    }
    global.ContactFlowV3 = ContactFlowV3;
    if (typeof module !== 'undefined') module.exports = ContactFlowV3;
})(typeof window !== 'undefined' ? window : globalThis);
