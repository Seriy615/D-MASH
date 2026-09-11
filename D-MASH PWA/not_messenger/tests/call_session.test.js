const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const source = fs.readFileSync(require.resolve('../js/call_session.js'), 'utf8');
const context = { window: {}, console, setTimeout, clearTimeout };
vm.runInNewContext(source, context, { filename: 'call_session.js' });
const Session = context.window.DmashCallSession.CallSignalingSession;

function makePeer() {
  return {
    localDescription: { type: 'offer', sdp: 'local' },
    connectionState: 'new',
    tracks: [],
    addTrack(track, stream) { this.tracks.push([track, stream]); },
    async createOffer() { return { type: 'offer', sdp: 'offer' }; },
    async createAnswer() { return { type: 'answer', sdp: 'answer' }; },
    async setLocalDescription(value) { this.localDescription = value; },
    async setRemoteDescription(value) { this.remote = value; },
    async addIceCandidate(value) { (this.ice || (this.ice = [])).push(value); },
    close() { this.connectionState = 'closed'; }
  };
}

(async () => {
  const sent = [];
  const signaling = {
    async open(callId, role) { this.opened = [callId, role]; },
    async send(message) { sent.push(message); },
    async close(callId) { this.closed = callId; }
  };
  const tracks = [{ stop() { this.stopped = true; } }];
  const mediaDevices = { async getUserMedia() { return { getTracks: () => tracks }; } };
  const session = new Session({ signaling, rtcFactory: () => makePeer(), mediaDevices });
  await session.startOffer('a'.repeat(64));
  assert.deepStrictEqual(signaling.opened, ['a'.repeat(64), 'caller']);
  assert.strictEqual(sent[0].type, 'offer');
  assert.strictEqual(sent[0].call_id, 'a'.repeat(64));
  await session.receive({ call_id: 'a'.repeat(64), type: 'ice', payload: JSON.stringify({ candidate: 'early' }) });
  assert.strictEqual(session.queuedIce.length, 1);
  await session.hangup();
  assert.strictEqual(sent.at(-1).type, 'hangup');
  assert.strictEqual(tracks[0].stopped, true);
  await assert.rejects(() => new Session({ signaling, rtcFactory: () => makePeer(), mediaDevices }).startOffer('route-id'), /invalid call id/);
  // An offer arriving during the microphone prompt must wait, then answer.
  let allowMedia;
  const calleeSignals = [];
  const calleeTransport = {async open() {
    this.delivery = this.onmessage({call_id: 'b'.repeat(64), type: 'offer',
      payload: JSON.stringify({type: 'offer', sdp: 'remote'})});
  }, async send(value) {calleeSignals.push(value);}, async close() {}};
  const callee = new Session({signaling: calleeTransport, rtcFactory: makePeer,
    mediaDevices: {getUserMedia: () => new Promise(resolve => {allowMedia = resolve;})}});
  const accepting = callee.accept('b'.repeat(64));
  while (!allowMedia) await Promise.resolve();
  assert.equal(calleeSignals.length, 0);
  allowMedia(await mediaDevices.getUserMedia());
  await accepting;
  await calleeTransport.delivery;
  assert.equal(calleeSignals[0].type, 'answer');
  assert.equal(callee.pc.remote.sdp, 'remote');
  await callee.close();

  // Cancelling while permission is pending stops tracks granted afterwards.
  let grant;
  const lateTrack = {stop() {this.stopped = true;}};
  const cancelled = new Session({signaling: {async open() {}, async send() {}, async close() {}},
    rtcFactory: () => {throw new Error('must not construct RTC after cancellation');},
    mediaDevices: {getUserMedia: () => new Promise(resolve => {grant = resolve;})}});
  const starting = cancelled.startOffer('c'.repeat(64));
  while (!grant) await Promise.resolve();
  await cancelled.close();
  grant({getTracks: () => [lateTrack]});
  await assert.rejects(starting, /cancelled/);
  assert(lateTrack.stopped);
  console.log('call_session.test.js: ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
