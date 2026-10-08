'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {createCore,nacl}=require('./fixtures/core_vm.cjs');
global.nacl=nacl;require('../js/route_discovery_v4.js');const recipient=require('../js/recipient_payload_v4.js');
require('../js/secure_session.js');const device=require('../js/device_envelope.js');
const hex=value=>Buffer.from(value).toString('hex');
(async()=>{
 // Legacy fragment rows remain readable/drainable; new UI notes use S-TURN.
 const [a,b]=await Promise.all([createCore(),createCore()]);let now=Date.now(),packets=[];
 const shared=hex(nacl.randomBytes(32));
 for(const [local,peer,slot,route] of [[a,b,'slot-A','a'.repeat(64)],[b,a,'slot-B','b'.repeat(64)]]){
  local.slot=slot;local.route=route;local.recipient=nacl.box.keyPair();local.history=[];local.failWrite=false;
  for(const name of ['account_ratchet.js','account_ratchet_runtime.js','account_recorded_media.js'])vm.runInContext(fs.readFileSync(require.resolve('../js/'+name),'utf8'),local.ctx);
  local.core.activeIdentity=slot;local.core.blindSalt=nacl.randomBytes(32);local.core.renderPeers=async()=>{};local.core.loadChat=async()=>{};
  local.storage.getAllBoxes=async table=>[...local.rows].filter(([key])=>key.startsWith(table)).map(([key,data])=>({...structuredClone(data),alias:key.slice(table.length)}));
  const write=local.storage.putBox;
  local.storage.putBox=async(...args)=>{if(local.failWrite)throw Error('Disk failure');if(local.failCompleteWrite&&args[1].data.record==='media_assembly'&&args[1].data.complete){local.failCompleteWrite=false;throw Error('Crash after receiver history');}return write(...args);};
  local.storage.deleteBox=async(table,alias)=>local.rows.delete(table+alias);
  local.storage.hasMessageWireId=async(peer,id)=>local.history.some(row=>row.peer===peer&&row.wireId===id);
  local.storage.saveMessageGamma=async(peer,text,inbound,read,state,wireId)=>{if(local.failWrite)throw Error('Disk failure');local.history.push({peer,text,inbound,transportState:state,wireId});return local.history.length;};
  local.storage.updateMessageTransportState=async(peer,id,state)=>{const row=local.history.find(row=>row.peer===peer&&row.wireId===id);if(row)row.transportState=state;return !!row;};
  local.storage.markMessageSendFailure=async(peer,id,reason)=>{const row=local.history.find(row=>row.wireId===id);if(row){row.transportState='FAILED';row.failure=reason;}};
  await local.storage.putBox('blind_peers',{alias:peer.core.keys.pub_hex,data:{curvePub:hex(peer.core.keys.box.publicKey)}});
  await local.storage.putBox('blind_secrets',{alias:peer.core.keys.pub_hex,data:{staticShared:shared,ratchetRoot:shared,ratchetEpoch:1}});
  await local.storage.putBox('pairing_material',{alias:'node-route-v4:'+route,data:{peerId:peer.core.keys.pub_hex}});
  local.restart=()=>{local.core.recordedMedia=new local.ctx.DmashAccountRecordedMedia(local.core,local.storage,{clock:()=>now});};local.restart();
  local.ctx.NodeManager={transportMode:'mesh',getMeshRoute:()=>({routeLocator:'fixture-out',backRouteLocator:'fixture-in'}),startProbe:async()=>({}),submitEnvelope:async(_,envelope)=>{
   const payload=JSON.stringify(envelope);assert(Buffer.byteLength(payload)<16000,'actual signed Account envelope fits v4 budget');
   device.seal(peer.recipient.publicKey,device.create(Buffer.from(peer.recipient.publicKey).toString('base64url'),'MSG',payload));
   const sealed=recipient.sealPayload(peer.recipient.publicKey,payload);packets.push({from:local,to:peer,sealed});return {state:'NODE_ACCEPTED'};
  }};
 }
 const open=packet=>JSON.parse(recipient.openPayload([packet.to.recipient.secretKey],packet.sealed).payload);
 const peek=async packet=>JSON.parse(await packet.to.core.decrypt(open(packet).ciphertext,packet.from.core.keys.pub_hex,true));
 async function deliver(packet){return packet.to.core.receiveAccountNodeRecordV4({routeId:packet.to.route,accountSlot:packet.to.slot,payload:JSON.stringify(open(packet))},packet.to.slot);}
 async function drain(drop=()=>false){let rounds=0;while(packets.length){assert(++rounds<200,'bounded fixture progress');const packet=packets.shift();if(await drop(packet))continue;assert.equal(await deliver(packet),true);}}
 const data='data:video/webm;codecs=vp8,opus;base64,'+Buffer.alloc(33700,7).toString('base64');
 assert.equal(await a.core.recordedMedia.queue(b.core.keys.pub_hex,{type:'video_note',name:'recorded',data}),true);
 await a.core.recordedMedia.flush();assert.equal(a.history.length,1);assert.equal(b.history.length,0);
 await drain();
 const operation=(await a.core.recordedMedia.operations(a.core.recordedMedia.capture()))[0];
 assert.equal(operation.status,'sending');
 assert.equal(await a.core.recordedMedia.receipt(b.core.keys.pub_hex,operation.meta.id,'DELIVERED'),true);
 assert.equal(a.history[0].transportState,'QUEUED','generic receipt cannot claim assembled-note delivery');
 await a.core.recordedMedia.flush();assert.equal(packets.length,8,'peer receipt window bounds queued fragments');
 let dropped=false;
 await drain(async packet=>{const message=await peek(packet);if(!dropped&&message.body?.type==='dmash_media_fragment'&&message.body.index===0){dropped=true;return true;}return false;});
 assert(dropped);assert.equal(b.history.length,0,'incomplete note does not enter history');
 a.restart();b.restart();now+=11000;
 await a.core.recordedMedia.flush();
 const savedPacket=packets[0];b.core.activeIdentity='other-slot';assert.equal(await deliver(savedPacket),false,'locked/different Account cannot consume fragment');b.core.activeIdentity=b.slot;
 b.failWrite=true;await assert.rejects(deliver(savedPacket),/Disk failure/);b.failWrite=false;
 let finalLost=false;b.failCompleteWrite=true;
 const dropFinal=async packet=>{const message=await peek(packet);if(message.type==='voip_media_complete'){finalLost=true;return true;}return false;};
 await assert.rejects(drain(dropFinal),/Crash after receiver history/);
 assert.equal(b.history.length,1,'receiver history persisted before crash');
 now+=11000;await a.core.recordedMedia.flush();await drain(dropFinal);
 assert(finalLost);assert.equal(b.history.length,1);assert.equal(b.history[0].text.data,'data:video/webm;base64,'+Buffer.alloc(33700,7).toString('base64'));
 assert.equal((await a.core.recordedMedia.operations(a.core.recordedMedia.capture())).length,1,'local acceptance/fragment receipts cannot retire without final receipt');
 a.restart();b.restart();now+=11000;await a.core.recordedMedia.flush();await drain();
 assert.equal(b.history.length,1,'lost final receipt retry cannot duplicate history');assert.equal(a.history[0].transportState,'DELIVERED');
 assert.equal((await a.core.recordedMedia.operations(a.core.recordedMedia.capture())).length,0);
 const body=(await peek(savedPacket)).body;
 await assert.rejects(b.core.recordedMedia.fragment({...body,data:body.data.slice(0,-1)+(body.data.endsWith('A')?'B':'A')},'media:'+body.meta.id+':'+body.index,a.core.keys.pub_hex,()=>true),/Conflicting/);
 assert.equal(b.history.length,1);
 const saveHistory=a.storage.saveMessageGamma;a.storage.saveMessageGamma=async()=>{throw Error('History write crash');};
 await assert.rejects(a.core.recordedMedia.queue(b.core.keys.pub_hex,{type:'voice',name:'crash-after-intent',data:'data:audio/webm;base64,YQ=='}),/History write crash/);
 a.storage.saveMessageGamma=saveHistory;a.restart();await a.core.recordedMedia.flush();
 assert.equal(a.history.filter(row=>row.text.name==='crash-after-intent').length,1,'restart repairs durable intent before network');
 await drain();await a.core.recordedMedia.flush();await drain();
 assert.equal(b.history.filter(row=>row.text.name==='crash-after-intent').length,1);assert.equal(packets.length,0);
 const challenge=()=>({type:'voip_media_profile_request',profile:'DMASH_NOTE_FRAGMENTS_V1',id:crypto.randomUUID(),nonce:hex(nacl.randomBytes(32)),expiresAt:now+120000});
 const firstPermit=challenge();b.failWrite=true;
 await assert.rejects(b.core.recordedMedia.profile(firstPermit,a.core.keys.pub_hex,()=>true),/Disk failure/);
 b.failWrite=false;assert.equal(packets.length,0,'temporary storage failure cannot become permanent profile refusal');
 for(const request of [firstPermit,challenge()]){await b.core.recordedMedia.profile(request,a.core.keys.pub_hex,()=>true);assert.equal((await peek(packets.shift())).supported,true);}
 await b.core.recordedMedia.profile(challenge(),a.core.keys.pub_hex,()=>true);assert.equal((await peek(packets.shift())).supported,false,'third concurrent peer assembly refused');
 await assert.rejects(b.core.recordedMedia.profile({...firstPermit,nonce:'0'.repeat(64)},a.core.keys.pub_hex,()=>true),/context mismatch/);
 await assert.rejects(b.core.recordedMedia.profile({...firstPermit,profile:'UNKNOWN'},a.core.keys.pub_hex,()=>true),/Unsupported/);
 now+=86400001;
 const expiredSession=b.core.recordedMedia.capture();await b.core.recordedMedia.purge(expiredSession);
 assert.equal((await b.core.recordedMedia.index(expiredSession)).entries.length,3,'bounded purge removes one expired transfer per pass');
 await b.core.recordedMedia.profile(challenge(),a.core.keys.pub_hex,()=>true);assert.equal((await peek(packets.shift())).supported,true,'expired allocations do not consume active quota');
 assert.equal(await a.core.recordedMedia.queue(b.core.keys.pub_hex,{type:'voice',name:'unsupported',data:'data:audio/webm;base64,'+Buffer.alloc(20000,3).toString('base64')}),true);
 await a.core.recordedMedia.flush();packets=[];now+=120001;await a.core.recordedMedia.flush();
 assert.equal(a.history[2].transportState,'FAILED','unsupported old peer does not receive fragments or infinite loading');
 assert.equal((await a.core.recordedMedia.operations(a.core.recordedMedia.capture()))[0].content,null,'terminal failure retires duplicate source from outbox');
 console.log('PASS real Account ratchet/signatures + recipient crypto: 33.7 KB note fits v3/v4 fragments, bounded receipt window, loss/restart, wrong Account, disk failure, final receipt dedupe/conflict profile timeout/quota/expiry and transient storage retry');
})().catch(error=>{console.error(error);process.exitCode=1;});
