const assert = require('node:assert/strict');
require('../js/call_runtime.js');
const request = () => ({version: 2, call_id: 'a'.repeat(64), expires_at: Math.floor(Date.now()/1000)+60,
    signaling: {wss_endpoint: 'wss://example.test/signal', session_id: 's'.repeat(43), one_time_key: 't'.repeat(43)}});
let created, selected, invitationMessages = [];
class Transport {
    constructor() { this.invitation = request(); }
    static async create() { created = new Transport(); return created; }
    close() {this.closed = true;}
}
class Session {
    constructor({signaling}) {this.signaling = signaling; this.stream = {}; this.pc = {};}
    async startOffer() {}
    async prepareIncoming() {this.prepared = true;}
    async accept() {this.accepted = true;}
    close() {this.closed = true; this.signaling.close();}
}
globalThis.DmashCallSignaling = {WebSocketSignaling: Transport, validEndpoint: value => value};
globalThis.DmashCallSession = {CallSignalingSession: Session};
globalThis.NodeManager = {async selectCallService() {selected = true; return 'wss://example.test/signal';}};
globalThis.document = {getElementById: () => null};
function core() {
    return {callState:'idle', activePeerId: 'recipient', updateCallUI() {}, startTimer() {}, shmon() {},
        attachCallSignaling(session) {this.callSignalingSession = session;},
        async sendMessage(value, handshake, peer, alias, noQueue) {invitationMessages.push({value, peer, noQueue}); return true;},
        async showIncomingCall(peer, accept) {this.accept = accept;},
        endCall() {clearTimeout(this._callExpiry); this._callAttempt = null; this.callState = 'idle'; this.callSignalingSession?.close();}};
}
(async () => {
    const source = require('node:fs').readFileSync(require.resolve('../js/core_engine.js'), 'utf8');
    const start = source.indexOf('sendVoipSignal: async function(data) {');
    const end = source.indexOf('    // Core.switchCamera', start);
    const signal = Function('return (' + source.slice(start, end).replace('sendVoipSignal: ', '').trim().replace(/,$/, '') + ')')();
    globalThis.Core = {callPeerId: 'recipient', sendMessage() {throw new Error('SDP escaped into Mesh MSG');}};
    assert.equal(await signal.call(Core, {type: 'voip_offer'}), false);
    let forwarded;
    Core.callSignalingSession = {async sendSignal(value) {forwarded = value;}};
    await signal.call(Core, {type: 'voip_offer'});
    assert.equal(forwarded.type, 'voip_offer');
    const caller = core();
    assert(await DmashCallRuntime.start(caller));
    assert(selected); assert.equal(invitationMessages.length, 1);
    assert.equal(invitationMessages[0].value.type, 'voip_call_request');
    assert.equal(invitationMessages[0].peer, 'recipient');
    assert(invitationMessages[0].noQueue, 'Expired invitation must not enter durable resend queue');
    assert(!('sdp' in invitationMessages[0].value));
    caller.endCall();
    assert(created.closed);
    const callee = core();
    assert(await DmashCallRuntime.incoming(callee, request(), 'caller'));
    assert(callee.callSignalingSession.prepared);
    assert(!callee.callSignalingSession.accepted, 'No microphone before acceptance');
    await callee.accept();
    assert(callee.callSignalingSession.accepted);
    callee.endCall();
    assert.equal(await DmashCallRuntime.incoming(core(), {...request(), expires_at: 1}, 'caller'), false);

    // Cancelling while CREATE is in flight closes its late result.
    let resolve;
    Transport.create = () => new Promise(r => {resolve = r;});
    const cancelled = core(), starting = DmashCallRuntime.start(cancelled);
    while (!resolve) await Promise.resolve();
    cancelled.endCall();
    const late = new Transport(); resolve(late);
    assert.equal(await starting, false); assert(late.closed);
    assert.equal(invitationMessages.length, 1);
    console.log('call_runtime.test.js: ok');
})().catch(error => {console.error(error); process.exitCode = 1;});
