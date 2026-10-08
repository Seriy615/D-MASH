// Invoked by the backend suite against a real local signaling WebSocket.
const assert = require('node:assert/strict');
// Browser Worker semantics backed by a separate thread running shipped source.
// No synchronous proof implementation or production fallback is introduced.
const {Worker: NodeWorker} = require('node:worker_threads');
const {pathToFileURL, fileURLToPath} = require('node:url');
const path = require('node:path');
const workerExits = [];
let workerCount = 0, terminatedCount = 0;
globalThis.document = {currentScript: {src: pathToFileURL(path.join(__dirname, '../js/call_signaling.js')).href}};
globalThis.Worker = class BrowserWorker {
    constructor(url) {
        const workerPath = fileURLToPath(url);
        assert.equal(workerPath, path.resolve(__dirname, '../js/call_admission_worker.js'));
        this.thread = new NodeWorker(`
            const {parentPort, workerData} = require('node:worker_threads');
            const path = require('node:path');
            globalThis.self = globalThis;
            globalThis.postMessage = value => parentPort.postMessage(value);
            globalThis.importScripts = file => require(path.join(path.dirname(workerData), file));
            require(workerData);
            parentPort.on('message', data => { Promise.resolve(self.onmessage({data})).catch(error => { throw error; }); });
        `, {eval: true, workerData: workerPath});
        workerCount++;
        this.thread.on('message', data => this.onmessage?.({data}));
        this.thread.on('error', error => this.onerror?.(error));
        workerExits.push(new Promise(resolve => this.thread.once('exit', resolve)));
    }
    postMessage(value) { this.thread.postMessage(value); }
    terminate() { terminatedCount++; return this.thread.terminate(); }
};
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
        signalingState: 'stable',
        addTrack() {}, close() {this.closed = true;},
        async createOffer() { return {type: 'offer', sdp: 'test-offer'}; },
        async createAnswer() { return {type: 'answer', sdp: 'test-answer'}; },
        async setLocalDescription(value) {
            if (value.type === 'offer') {
                assert.equal(this.signalingState, 'stable'); this.signalingState = 'have-local-offer';
            } else if (value.type === 'answer') {
                assert.equal(this.signalingState, 'have-remote-offer'); this.signalingState = 'stable';
            } else if (value.type === 'rollback') this.signalingState = 'stable';
            this.localDescription = value;
        },
        async setRemoteDescription(value) {
            if (value.type === 'offer') {
                assert.equal(this.signalingState, 'stable'); this.signalingState = 'have-remote-offer';
            } else if (value.type === 'answer') {
                assert.equal(this.signalingState, 'have-local-offer'); this.signalingState = 'stable';
            }
            this.remoteDescription = value;
        },
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
    await Promise.all(workerExits);
    assert.equal(workerCount, 1, 'Admission must execute in a real worker thread');
    assert.equal(terminatedCount, 1, 'Completed admission must terminate its worker');
    console.log('real WebSocket client + admission worker exchange passed (RTC is a test double)');
})().catch(error => {console.error(error); process.exitCode = 1;});
