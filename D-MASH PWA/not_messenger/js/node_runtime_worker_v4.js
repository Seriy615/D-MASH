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
 'route_discovery_v4.js','recipient_payload_v4.js','node_routing_v4.js');
let closed=false,initializing=false,signing=null,store=null,runtime=null,gate=null;
const abort=new AbortController(),connecting=new Set(),requests=new Set();
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const wipe=value=>{if(value instanceof Uint8Array&&value.byteLength)value.fill(0);};
async function stop(){
 if(closed)return;closed=true;abort.abort();
 try{await runtime?.close();}finally{store?.close();gate?.close();wipe(signing?.secretKey);self.close();}
}
async function initialize(data){
 if(initializing||runtime||closed)throw Error();initializing=true;
 try{
  for(const value of [data.seed,data.storageKey,data.baseNcrh])if(!(value instanceof Uint8Array)||value.length!==32)throw Error();
  signing=nacl.sign.keyPair.fromSeed(data.seed);const nodeId=hex(signing.publicKey);
  if(!DmashNodeIdentity.verify(nodeId))throw Error();
  store=await DmashNodeRelationshipsV4.open(data.storageKey,nodeId,{isCurrent:()=>!closed});
  if(closed)throw Error();
  runtime=new DmashNodeRoutingV4(data.baseNcrh);
  if(data.credential)gate=new DmashNodeAdmissionV4.PasswordGate(data.credential);
  return {nodeId,worker:true};
 }catch(error){self.postMessage({id:data.id,ok:false});await stop();throw error;}
 finally{wipe(data.seed);wipe(data.storageKey);wipe(data.baseNcrh);wipe(data.credential?.key);}
}
async function connect(data){
 if(!runtime||closed||connecting.size>=2||connecting.has(data.nodeId)||runtime.peers.has(data.nodeId))throw Error();
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
   if(!runtime||closed)throw Error();
   if(data.type==='STATS')result={...runtime.stats,owned:runtime.owned.length,peers:runtime.peers.size,
    queued:[...runtime.queues.values()].reduce((n,q)=>n+q.length,0),sending:runtime.senders.size,
    cover:runtime.coverHistory.length,worker:true};
   else if(data.type==='INJECT_COVER')result=runtime.injectCoverOnce(data.size);
   else if(data.type==='COVER_POLICY'){if(data.enabled)runtime.startCover(data.policy);else runtime.stopCover();result=true;}
   else throw Error();
  }
  if(!closed)self.postMessage({id:data.id,ok:true,result});
 }catch(_){if(!closed)self.postMessage({id:data.id,ok:false});}
 finally{requests.delete(data.id);}
};
