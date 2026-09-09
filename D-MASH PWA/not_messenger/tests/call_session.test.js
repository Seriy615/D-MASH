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
  console.log('call_session.test.js: ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
