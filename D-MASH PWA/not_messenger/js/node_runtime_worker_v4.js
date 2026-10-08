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
 'route_discovery_v4.js','recipient_payload_v4.js','node_routing_v4.js','node_inbox_v4.js','node_local_delivery_v4.js','node_local_ownership_v4.js');
let localOwnership='legacy-migration';
let closed=false,ready=false,initializing=false,signing=null,store=null,runtime=null,gate=null,inbox=null,local=null,ownership=null,bootstrap=null;
const abort=new AbortController(),connecting=new Set(),requests=new Set();
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const wipe=value=>{if(value instanceof Uint8Array&&value.byteLength)value.fill(0);};
async function stop(){
 if(closed)return;closed=true;ready=false;abort.abort();bootstrap?.close();ownership?.close();inbox?.close();local?.close();store?.close();gate?.close();
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
  if(data.apiVersion!==3)throw Error('Incompatible Node worker API');
  const bootstrapProfile=data.bootstrapProfile??null;
  if(bootstrapProfile!==null&&(bootstrapProfile!=='private-v1'||data.localOwnership!=='managed'))throw Error('Unsupported bootstrap profile');
  if(!['legacy-migration','managed'].includes(data.localOwnership))throw Error('Ownership profile required');localOwnership=data.localOwnership;
  for(const value of [data.seed,data.storageKey,data.baseNcrh])if(!(value instanceof Uint8Array)||value.length!==32)throw Error();
  signing=nacl.sign.keyPair.fromSeed(data.seed);const nodeId=hex(signing.publicKey);
  if(!DmashNodeIdentity.verify(nodeId))throw Error();
  await claimActor();if(closed)throw Error();
  store=await DmashNodeRelationshipsV4.open(data.storageKey,nodeId,{isCurrent:()=>!closed});
  if(closed)throw Error();
  runtime=new DmashNodeRoutingV4(data.baseNcrh);
  inbox=await DmashNodeInboxV4.open(data.storageKey,nodeId,{isCurrent:()=>!closed});
  local=new DmashNodeLocalDeliveryV4(runtime,inbox);await inbox.pruneSeen();
  const restored=await local.restore({managedOnly:localOwnership==='managed'});ownership=new DmashNodeLocalOwnershipV4(local,inbox);
  if(bootstrapProfile==='private-v1'){
   importScripts('account_pairing_v2.js','account_route_binding_v2.js','node_bootstrap_control_v4.js','node_bootstrap_dispatcher_v4.js','node_bootstrap_runtime_v4.js');
   bootstrap=await DmashNodeBootstrapRuntimeV4.open(data.storageKey,nodeId,{runtime,ownership,local,isCurrent:()=>!closed});
   ownership.detachBootstrap=routeId=>bootstrap.detach(routeId);ownership.archiveRowProvider=owner=>bootstrap.archiveRow(owner);
  }
  if(data.credential)gate=new DmashNodeAdmissionV4.PasswordGate(data.credential);
  ready=true;return {apiVersion:3,localOwnership,bootstrapProfile,nodeId,worker:true,...restored};
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
   if(localOwnership==='managed'&&['BIND_LOCAL','INSTALL_RECIPIENT_KEYS','INBOX_LIST','INBOX_ACK','SUBMIT','DISCOVER'].includes(data.type))throw Error('Managed owner capability required');
   if(data.type==='OWNER_ARCHIVE_CHALLENGE')result=await ownership.challenge(data.accountPublic,data.certificate,{archive:true});
   else if(data.type==='OWNER_CHALLENGE')result=await ownership.challenge(data.accountPublic,data.certificate);
   else if(data.type==='OWNER_REGISTER')result=await ownership.register(data.challenge,data.signature);
   else if(data.type==='OWNER_PREPARE')result=await ownership.prepare(data.ownerToken,data);
   else if(data.type==='OWNER_DISCOVER'){ownership.owner(data.ownerToken);const found=await local.discover(data.certificate);try{ownership.owner(data.ownerToken);}catch(error){local.routes.delete(found.handle);throw error;}result=found;}
   else if(data.type==='OWNER_INBOX_LIST'){const owner=ownership.owner(data.ownerToken,{archiveAllowed:true});result=await inbox.list(owner.ownerSlot,data.limit,data.after);ownership.owner(data.ownerToken,{archiveAllowed:true});}
   else if(data.type==='OWNER_INBOX_ACK'){const owner=ownership.owner(data.ownerToken,{archiveAllowed:true});result=await inbox.acknowledge(data.handle,owner.ownerSlot,{guard:()=>{ownership.owner(data.ownerToken,{archiveAllowed:true});return true;}});ownership.owner(data.ownerToken,{archiveAllowed:true});}
   else if(data.type==='OWNER_SUBMIT_SEALED'){const owner=ownership.owner(data.ownerToken),row=await ownership.read(owner.routeId);ownership.owner(data.ownerToken);ownership.matches(row,owner);if(row.state!=='ACTIVE')throw Error('Binding not active');result=await local.sendSealed(data.handle,data.blob,owner.routeId,data.certificateDigest,{guard:()=>{ownership.owner(data.ownerToken);return true;}});}
   else if(data.type==='OWNER_SUBMIT'){const owner=ownership.owner(data.ownerToken),row=await ownership.read(owner.routeId);ownership.owner(data.ownerToken);ownership.matches(row,owner);if(row.state!=='ACTIVE')throw Error('Binding not active');result=local.send(data.handle,data.payload,owner.routeId);}
   else if(data.type.startsWith('OWNER_BOOTSTRAP_')){
    if(!bootstrap)throw Error('Private bootstrap profile required');
    if(data.type==='OWNER_BOOTSTRAP_PROVISION')result=await bootstrap.provision(data.ownerToken,data);
    else if(data.type==='OWNER_BOOTSTRAP_LIST')result=await bootstrap.dispatcher.list(data.ownerToken);
    else if(data.type==='OWNER_BOOTSTRAP_SELECT')result=await bootstrap.dispatcher.select(data.ownerToken,data.exchangeId,data.requestDigest,{deny:data.deny});
    else if(data.type==='OWNER_BOOTSTRAP_SUBMIT')result=await bootstrap.submit(data.ownerToken,data.handle,data.control);
    else throw Error('Unknown bootstrap operation');
   }
   else if(data.type==='OWNER_RELEASE'){ownership.owners.delete(data.ownerToken);result=true;}
   else if(data.type==='OWNER_QUERY')result=await ownership.query(data.ownerToken,data.migrationId);
   else if(data.type==='OWNER_ACTIVATE')result=await ownership.change(data.ownerToken,data.tuple,'ACTIVE');
   else if(data.type==='OWNER_RETIRE')result=await ownership.change(data.ownerToken,data.tuple,'RETIRED');
   else if(data.type==='BIND_LOCAL'){if(localOwnership==='managed')throw Error('Explicit migration required');result=await local.bind(data);}
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
