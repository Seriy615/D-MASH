'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../js/call_session.js'), 'utf8');
const context = {window: {}, console, setTimeout, clearTimeout};
vm.runInNewContext(source, context, {filename: 'call_session.js'});
const Session = context.window.DmashCallSession.CallSignalingSession;
const callId = 'a'.repeat(64);
const track = kind => ({kind, enabled: true, readyState: 'live', stop() {this.readyState = 'ended';}});
const stream = tracks => ({items: [...tracks], getTracks() {return this.items;},
  getVideoTracks() {return this.items.filter(t => t.kind === 'video');},
  addTrack(t) {this.items.push(t);}, removeTrack(t) {this.items = this.items.filter(x => x !== t);}});
const fp = value => value.match(/.{1,2}/g).join(':');
function peer(identity) {
  const value = {
    connectionState: 'new', signalingState: 'stable', senders: [], changes: [],
    addTrack(t) {const sender = {track: t, async replaceTrack(next) {this.track = next;}}; this.senders.push(sender); return sender;},
    removeTrack(sender) {this.senders = this.senders.filter(x => x !== sender);},
    getSenders() {return this.senders;},
    async createOffer() {return {type: 'offer', sdp: this.sdp()};},
    async createAnswer() {return {type: 'answer', sdp: this.sdp()};},
    sdp() {return 'v=0\r\na=fingerprint:sha-256 ' + identity + '\r\n' +
      (this.senders.some(sender => sender.track?.kind === 'video') ? 'm=video 9 UDP/TLS/RTP/SAVPF 96\r\n' : 'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n');},
    async setLocalDescription(desc) {this.changes.push('local:' + desc.type); if(desc.type === 'rollback') this.signalingState = 'stable';
      else {this.localDescription = desc; this.signalingState = desc.type === 'offer' ? 'have-local-offer' : 'stable';}},
    async setRemoteDescription(desc) {this.changes.push('remote:' + desc.type); this.remoteDescription = desc;
      this.signalingState = desc.type === 'offer' ? 'have-remote-offer' : 'stable';},
    async addIceCandidate() {}, close() {this.connectionState = 'closed';}
  };
  return value;
}
const until = async condition => {for(let i=0;i<100;i++){if(condition())return;await new Promise(resolve=>setTimeout(resolve,2));}throw Error('event was not observed');};
function setup({denied = false, dropRenegotiationAnswer = false, timeout = 15000} = {}) {
  const calls = [[], []], peers = [peer(fp('11'.repeat(32))), peer(fp('22'.repeat(32)))];
  const transports = [0,1].map(i=>({async open() {}, async close() {}, async send(message) {
    if (dropRenegotiationAnswer && message.type === 'answer' && peers[i].changes.filter(s=>s==='local:answer').length > 1) return;
    setTimeout(()=>{void transports[1-i].onmessage(message);},0);
  }}));
  const devices = [0,1].map(i=>({async getUserMedia(constraints) {calls[i].push({audio: !!constraints.audio, video: !!constraints.video});
    if (constraints.video && denied) throw Object.assign(Error('permission denied'), {name:'NotAllowedError'});
    return stream([...(constraints.audio ? [track('audio')] : []), ...(constraints.video ? [track('video')] : [])]);}}));
  const sessions = [0,1].map(i=>new Session({signaling: transports[i], rtcFactory: () => peers[i], mediaDevices: devices[i], renegotiationTimeoutMs: timeout}));
  return {sessions, peers, calls, transports};
}
(async()=>{
  // The initial call requests only audio; the camera permission appears only
  // after the user enables video, and the new offer stays on the joined call.
  {
    const {sessions, peers, calls} = setup();
    const [caller,callee] = sessions;
    await callee.accept(callId);
    await caller.startOffer(callId);
    await until(()=>caller.remoteDescription && callee.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    assert.deepEqual(calls, [[{audio:true,video:false}],[{audio:true,video:false}]]);
    const originalFingerprint = caller.remoteFingerprint;
    await caller.enableVideo();
    assert.deepEqual(calls[0][1], {audio:false,video:true});
    assert.equal(caller.videoTrack.readyState, 'live');
    assert.equal(callee.pc.remoteDescription.sdp.includes('m=video'), true);
    assert.equal(caller.remoteFingerprint, originalFingerprint);
    assert.equal(caller.pc.signalingState, 'stable');
    assert.equal(callee.pc.signalingState, 'stable');
    const first = caller.videoTrack;
    const offers = caller.pc.changes.filter(change=>change==='local:offer').length;
    await caller.disableVideo();
    assert.equal(first.readyState, 'ended');
    assert.equal(caller.videoSender.track, null);
    await caller.enableVideo();
    assert.equal(caller.videoTrack.readyState, 'live');
    assert.equal(caller.pc.changes.filter(change=>change==='local:offer').length, offers, 're-enable reuses negotiated sender');
    const second = caller.videoTrack;
    await caller.switchVideoCamera({facingMode:'environment'});
    assert.equal(second.readyState, 'ended');
    assert.equal(caller.videoTrack.readyState, 'live');
    assert.equal(caller.videoSender.track, caller.videoTrack);
    await Promise.all(sessions.map(session=>session.close()));
  }
  // A denied permission leaves audio and the previously negotiated session intact.
  {
    const {sessions:[caller,callee], peers, calls} = setup({denied:true});
    await callee.accept(callId); await caller.startOffer(callId);
    await until(()=>caller.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    await assert.rejects(caller.enableVideo(), /permission denied/);
    assert.equal(caller.pc.connectionState, 'connected');
    assert.equal(caller.stream.getVideoTracks().length, 0);
    assert.deepEqual(calls[0][1], {audio:false,video:true});
    await Promise.all([caller.close(),callee.close()]);
  }
  // A failed replaceTrack(null) cannot leave the camera running or the UI in
  // an active-video state; the old track is disabled and stopped regardless.
  {
    const {sessions:[caller,callee], peers} = setup();
    await callee.accept(callId); await caller.startOffer(callId);
    await until(()=>caller.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    await caller.enableVideo();
    const old = caller.videoTrack;
    caller.videoSender.replaceTrack = async value => {if(value === null) throw Error('replace failed');};
    await assert.rejects(caller.disableVideo(), /replace failed/);
    assert.equal(old.readyState, 'ended');
    assert.equal(old.enabled, false);
    assert.equal(caller.videoTrack, null);
    assert.equal(caller.stream.getVideoTracks().length, 0);
    assert.equal(caller.pc.connectionState, 'connected');
    await Promise.all([caller.close(),callee.close()]);
  }
  // A forged replacement DTLS fingerprint is rejected before mutating RTC.
  {
    const {sessions:[caller,callee], peers} = setup();
    await callee.accept(callId); await caller.startOffer(callId);
    await until(()=>caller.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    const original = caller.pc.remoteDescription;
    await assert.rejects(caller.receive({call_id:callId,type:'offer',payload:JSON.stringify({type:'offer',sdp:'v=0\r\na=fingerprint:sha-256 '+fp('33'.repeat(32))+'\r\n'})}), /fingerprint changed/);
    assert.equal(caller.pc.remoteDescription, original);
    await Promise.all([caller.close(),callee.close()]);
  }
  // A missing answer times out, rolls the added track back, and keeps audio alive.
  {
    const {sessions:[caller,callee], peers} = setup({dropRenegotiationAnswer:true, timeout:20});
    await callee.accept(callId); await caller.startOffer(callId);
    await until(()=>caller.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    await assert.rejects(caller.enableVideo(), /renegotiation timeout/);
    assert.equal(caller.pc.connectionState, 'connected');
    assert.equal(caller.pc.signalingState, 'stable');
    assert.equal(caller.stream.getVideoTracks().length, 0);
    await Promise.all([caller.close(),callee.close()]);
  }
  // The joined peer cannot force an unbounded number of SDP renegotiations.
  {
    const {sessions:[caller,callee], peers} = setup();
    await callee.accept(callId); await caller.startOffer(callId);
    await until(()=>caller.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    const offer={call_id:callId,type:'offer',payload:JSON.stringify({type:'offer',sdp:caller.pc.remoteDescription.sdp})};
    for(let i=0;i<8;i++) assert.equal(await caller.receive(offer), true);
    await assert.rejects(caller.receive(offer), /renegotiation limit/);
    await Promise.all([caller.close(),callee.close()]);
  }
  // If both people enable cameras together, the callee rolls back its
  // colliding offer and answers the caller's offer on the same authenticated
  // signaling session. Neither permission result is silently discarded.
  {
    const {sessions:[caller,callee], peers} = setup({timeout:100});
    await callee.accept(callId); await caller.startOffer(callId);
    await until(()=>caller.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    await Promise.all([caller.enableVideo(),callee.enableVideo()]);
    assert.equal(caller.videoTrack.readyState, 'live');
    assert.equal(callee.videoTrack.readyState, 'live');
    assert.equal(caller.pc.signalingState, 'stable');
    assert.equal(callee.pc.signalingState, 'stable');
    assert(callee.pc.changes.includes('local:rollback'));
    await Promise.all([caller.close(),callee.close()]);
  }
  // Ending the call while camera permission is pending must stop a late grant
  // and never add that track to the old PeerConnection.
  {
    const {sessions:[caller,callee], peers} = setup();
    await callee.accept(callId); await caller.startOffer(callId);
    await until(()=>caller.remoteDescription);
    peers.forEach(p=>p.connectionState='connected');
    let grant;
    caller.mediaDevices.getUserMedia = () => new Promise(resolve=>{grant=resolve;});
    const enabling = caller.enableVideo();
    await until(()=>grant);
    await caller.close();
    const late = track('video');
    grant(stream([late]));
    await assert.rejects(enabling, /closed before camera was ready/);
    assert.equal(late.readyState, 'ended');
    assert.equal(caller.videoSender, null);
    await callee.close();
  }
  console.log('call_video.test.js: camera permission, same-call renegotiation, fingerprint, off/re-enable/switch, timeout rollback passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
