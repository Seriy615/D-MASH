'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const context={console,setTimeout,clearTimeout,window:{document:{getElementById:()=>null},navigator:{mediaDevices:{}}}};
vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../js/call_runtime.js'),'utf8'),context);
const runtime=context.window.DmashCallRuntime;
function core(){return {keys:{},activeIdentity:'slot-A',activePeerId:'peer',callState:'idle',alerts:[],
 updateCallUI(){},shmon(){},customAlert(title,text){this.alerts.push({title,text});},attachCallSignaling(session){this.session=session;},
 endCall(){clearTimeout(this._callExpiry);this._callAttempt=null;this.callState='idle';}};}
(async()=>{
 const missing=core();assert.equal(await runtime.start(missing),false);assert.match(missing.alerts[0].text,/MEDIA_RUNTIME_UNAVAILABLE/);
 context.window.DmashCallSession={CallSignalingSession:class{}};
 const disconnected=core();context.window.NodeManager={selectCallService:async()=>{throw Error('S-TURN unavailable');}};
 assert.equal(await runtime.start(disconnected),false);assert.match(disconnected.alerts[0].text,/S-TURN/);
 const noPeer=core();noPeer.activePeerId=null;assert.equal(await runtime.start(noPeer),false);assert.match(noPeer.alerts[0].text,/чат/);
 const invitation={version:2,call_id:'a'.repeat(64),expires_at:Math.floor(Date.now()/1000)+120,signaling:{session_id:'a'.repeat(43),one_time_key:'b'.repeat(43),wss_endpoint:'wss://signal.example/signal/v1'}};
 context.window.NodeManager.selectCallService=async()=>invitation.signaling.wss_endpoint;
 context.window.DmashCallSignaling={validEndpoint:value=>value,WebSocketSignaling:{create:async()=>({invitation,close(){}})}};
 let manual=false;
 context.window.DmashCallSession={CallSignalingSession:class{
  async startOffer(){const error=Object.assign(Error('Permission denied'),{name:'NotAllowedError'});this.failure=error;this.cancelled=manual;this.onclose();throw error;}
 }};
 const denied=core();assert.equal(await runtime.start(denied),false);assert.match(denied.alerts[0].text,/микрофону/,'permission failure stays visible after session cleanup');
 manual=true;const cancelled=core();assert.equal(await runtime.start(cancelled),false);assert.equal(cancelled.alerts.length,0,'manual cancellation does not display a spurious failure');
 console.log('PASS call-start failures visible for unavailable service/microphone; no-peer guidance and manual cancellation without stale alert');
})().catch(error=>{console.error(error);process.exitCode=1;});
