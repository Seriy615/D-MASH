'use strict';
// Dedicated Node actor. No Account engine, DeviceRoot or UI module is loaded.
self.DMASH_NODE_WORKER_URLS=Object.freeze({
 identity:new URL('node_identity.js',self.location.href).href,
 admission:new URL('node_admission_v4.js',self.location.href).href,
 channel:new URL('node_channel_v4.js',self.location.href).href
});
importScripts('vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js',
 'node_identity.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js',
 'resource_pow.js','node_socket_v4.js','node_channel_v4.js','probe_primitives_v4.js',
 'route_discovery_v4.js','recipient_payload_v4.js','node_routing_v4.js','node_inbox_v4.js','node_local_delivery_v4.js');
let closed=false,ready=false,initializing=false,signing=null,store=null,runtime=null,gate=null,inbox=null,local=null;
const abort=new AbortController(),connecting=new Set(),requests=new Set();
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const wipe=value=>{if(value instanceof Uint8Array&&value.byteLength)value.fill(0);};
async function stop(){
 if(closed)return;closed=true;ready=false;abort.abort();inbox?.close();local?.close();store?.close();gate?.close();
 try{await runtime?.close();}finally{wipe(signing?.secretKey);self.close();}
}
async function claimActor(){
 // Inbox/relationship DB names are origin-wide, so ownership must be too.
 // Hold the browser-managed lock until this Worker actually exits, including
 // the host's bounded termination fallback. Page cleanup alone is too early.
 if(!self.navigator?.locks)throw Error('Exclusive Node ownership unavailable');
 await new Promise((resolve,reject)=>{
  self.navigator.locks.request('dmash-node-runtime-v4',{mode:'exclusive',ifAvailable:true},async lock=>{
   if(!lock)throw Error('Node already active in another context');
   resolve();await new Promise(()=>{});
  }).catch(reject);
 });
}
async function initialize(data){
 if(initializing||runtime||closed)throw Error();initializing=true;
 try{
  if(data.apiVersion!==2)throw Error('Incompatible Node worker API');
  for(const value of [data.seed,data.storageKey,data.baseNcrh])if(!(value instanceof Uint8Array)||value.length!==32)throw Error();
  signing=nacl.sign.keyPair.fromSeed(data.seed);const nodeId=hex(signing.publicKey);
  if(!DmashNodeIdentity.verify(nodeId))throw Error();
  await claimActor();if(closed)throw Error();
  store=await DmashNodeRelationshipsV4.open(data.storageKey,nodeId,{isCurrent:()=>!closed});
  if(closed)throw Error();
  runtime=new DmashNodeRoutingV4(data.baseNcrh);
  inbox=await DmashNodeInboxV4.open(data.storageKey,nodeId,{isCurrent:()=>!closed});
  local=new DmashNodeLocalDeliveryV4(runtime,inbox);await inbox.pruneSeen();
  const restored=await local.restore();
  if(data.credential)gate=new DmashNodeAdmissionV4.PasswordGate(data.credential);
  ready=true;return {apiVersion:2,nodeId,worker:true,...restored};
 }catch(error){self.postMessage({id:data.id,ok:false});await stop();throw error;}
 finally{wipe(data.seed);wipe(data.storageKey);wipe(data.baseNcrh);wipe(data.credential?.key);}
}
async function connect(data){
 if(!ready||closed||connecting.size>=2||connecting.has(data.nodeId)||runtime.peers.has(data.nodeId))throw Error();
 if(typeof data.url!=='string'||data.url.length>2048)throw Error();
 if(data.password!==undefined&&(typeof data.password!=='string'||!data.password||new TextEncoder().encode(data.password).length>1024))throw Error();
 connecting.add(data.nodeId);let secure,channel;const derived=[];
 try{
  secure=await DmashNodeSocketV4.connect(data.url,signing,data.nodeId,{signal:abort.signal});
  channel=await DmashNodeChannelV4.authorize(secure,store,{signal:abort.signal,passwordGate:gate,
   requirePeerPassword:data.password!==undefined,
   peerPasswordKey:data.password===undefined?null:async(_,challenge)=>{const key=await DmashNodeAdmissionV4.derivePasswordKey(data.password,Uint8Array.from(atob(challenge.salt),c=>c.charCodeAt(0)),{signal:abort.signal});derived.push(key);return key;}});
  if(closed)throw Error();await runtime.addPeer(data.nodeId,channel);return {connected:true};
 }catch(error){channel?.close();secure?.close();throw error;}
 finally{connecting.delete(data.nodeId);data.password=undefined;for(const key of derived)wipe(key);}
}
self.onmessage=async({data})=>{
 if(!data||!Number.isSafeInteger(data.id)||data.id<1||typeof data.type!=='string')return;
 if(data.type==='STOP'){await stop();return;}
 if(closed||requests.size>=16||requests.has(data.id)){self.postMessage({id:data.id,ok:false});return;}
 requests.add(data.id);
 try{
  let result;
  if(data.type==='INIT')result=await initialize(data);
  else if(data.type==='CONNECT')result=await connect(data);
  else{
   if(!ready||closed)throw Error();
   if(data.type==='BIND_LOCAL')result=await local.bind(data);
   else if(data.type==='INSTALL_RECIPIENT_KEYS')result=await local.installRecipientKeys(data.routeId,data.recipientKeys);
   else if(data.type==='DISCOVER')result=await local.discover(data.certificate);
   else if(data.type==='SUBMIT')result=local.send(data.handle,data.payload,data.replyRouteId);
   else if(data.type==='INBOX_LIST')result=await inbox.list(data.accountSlot,data.limit,data.after);
   else if(data.type==='INBOX_ACK')result=await inbox.acknowledge(data.handle,data.accountSlot);
   else if(data.type==='STATS')result={...runtime.stats,owned:runtime.owned.length,peers:runtime.peers.size,
    queued:[...runtime.queues.values()].reduce((n,q)=>n+q.length,0),sending:runtime.senders.size,
    cover:runtime.coverHistory.length,worker:true};
   else if(data.type==='INJECT_COVER')result=runtime.injectCoverOnce(data.size);
   else if(data.type==='COVER_POLICY'){if(data.enabled)runtime.startCover(data.policy);else runtime.stopCover();result=true;}
   else throw Error();
  }
  if(!closed)self.postMessage({id:data.id,ok:true,result});
 }catch(_){if(!closed)self.postMessage({id:data.id,ok:false});}
 finally{requests.delete(data.id);wipe(data.discoverySeed);wipe(data.discoveryBox);if(Array.isArray(data.recipientKeys))for(const key of data.recipientKeys)wipe(key);}
};
