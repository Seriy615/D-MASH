// Invoked by the backend suite against a real local signaling WebSocket.
const assert = require('node:assert/strict');
require('../js/call_signaling.js');
require('../js/call_session.js');
const {WebSocketSignaling} = globalThis.DmashCallSignaling;
const {CallSignalingSession} = globalThis.DmashCallSession;
const wait = async predicate => {
    const deadline = Date.now() + 5000;
    while (!predicate()) {
        if (Date.now() > deadline) throw new Error('exchange timed out');
        await new Promise(resolve => setTimeout(resolve, 5));
    }
};
function peer() {
    return {
        addTrack() {}, close() {this.closed = true;},
        async createOffer() { return {type: 'offer', sdp: 'test-offer'}; },
        async createAnswer() { return {type: 'answer', sdp: 'test-answer'}; },
        async setLocalDescription(value) { this.localDescription = value; },
        async setRemoteDescription(value) { this.remoteDescription = value; },
        async addIceCandidate(value) { (this.candidates ||= []).push(value); }
    };
}
(async () => {
    const callerTransport = await WebSocketSignaling.create(process.argv[2]);
    const invite = callerTransport.invitation;
    assert.match(invite.call_id, /^[a-f0-9]{64}$/);
    assert.notEqual(invite.signaling.one_time_key, callerTransport.ticket);
    const calleeTransport = new WebSocketSignaling({endpoint: invite.signaling.wss_endpoint,
        sessionId: invite.signaling.session_id, ticket: invite.signaling.one_time_key});
    const tracks = [];
    const mediaDevices = {async getUserMedia() {
        const track = {stop() {this.stopped = true;}}; tracks.push(track);
        return {getTracks: () => [track]};
    }};
    const caller = new CallSignalingSession({signaling: callerTransport, rtcFactory: peer, mediaDevices});
    const callee = new CallSignalingSession({signaling: calleeTransport, rtcFactory: peer, mediaDevices});
    try {
        await caller.startOffer(invite.call_id);
        await caller.sendSignal({type: 'voip_ice', candidate: {candidate: 'early'}});
        await callee.accept(invite.call_id);
        await wait(() => caller.remoteDescription && callee.pc.candidates?.length === 1);
        assert.equal(caller.pc.remoteDescription.type, 'answer');
        assert.equal(callee.pc.remoteDescription.type, 'offer');
        assert.equal(callee.pc.candidates[0].candidate, 'early');
        assert.equal(caller.iceServers.length, 1);
        assert.equal(callee.iceServers.length, 1);
        await callee.hangup();
        await wait(() => caller.closed);
        assert(tracks.every(track => track.stopped));
    } finally { await caller.close(); await callee.close(); }
    console.log('real WebSocket client exchange passed (RTC is a test double)');
})().catch(error => {console.error(error); process.exitCode = 1;});
