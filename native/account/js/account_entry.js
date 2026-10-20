'use strict';
(function(g){
 const host=NativePlatform.host,utf=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,v=>v.toString(16).padStart(2,'0')).join('');
 const fail=c=>{throw Object.assign(Error(c),{code:c});};
 // QuickJS has no browser structuredClone intrinsic. Account protocol state
 // contains plain records/arrays and byte buffers; preserve references and
 // undefined instead of silently dropping fields through JSON serialization.
 const copy=(value,seen=new Map())=>{
  if(value===null||typeof value!=='object'){if(['function','symbol'].includes(typeof value))fail('ACCOUNT_STATE_CLONE_TYPE');return value;}
  if(seen.has(value))return seen.get(value);
  if(value instanceof ArrayBuffer)return value.slice(0);
  if(ArrayBuffer.isView(value)){if(value instanceof DataView)return new DataView(value.buffer.slice(value.byteOffset,value.byteOffset+value.byteLength));return new value.constructor(value);}
  const proto=Object.getPrototypeOf(value);if(!Array.isArray(value)&&proto!==Object.prototype&&proto!==null)fail('ACCOUNT_STATE_CLONE_TYPE');
  const result=Array.isArray(value)?new Array(value.length):{};seen.set(value,result);
  for(const name of Object.keys(value))Object.defineProperty(result,name,{value:copy(value[name],seen),enumerable:true,writable:true,configurable:true});return result;
 };
 if(typeof g.structuredClone!=='function')g.structuredClone=value=>copy(value);
 let generation=0,session=null,core=null,journal=null,sealed=null,runtime=null,root=null;
 const peers=new Map();let preparations=new WeakMap();
 const preparationFields=['accountPublic','ownerSlot','routeAuthorityDigest','routeId','migrationId','bindingDigest','generation','preparationDigest'];
 const preparationTuple=value=>Object.fromEntries(preparationFields.map(name=>[name,value[name]]));
 const samePreparation=(a,b)=>preparationFields.every(name=>a?.[name]===b?.[name]);
 const key=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
 const read=(db,store,id)=>new Promise((resolve,reject)=>{const tx=db.transaction(store,'readonly'),request=tx.objectStore(store).get(id);request.onsuccess=()=>resolve(request.result??null);tx.onabort=()=>reject(tx.error);});
 const all=(db,store)=>new Promise((resolve,reject)=>{const tx=db.transaction(store,'readonly'),request=tx.objectStore(store).getAll();request.onsuccess=()=>resolve(request.result??[]);tx.onabort=()=>reject(tx.error);});
 function current(){if(!session||session.signal.aborted||host('epoch')!==session.epoch)fail('ACCOUNT_SESSION_CHANGED');return session;}
 async function wait(p){const s=current(),v=await p;if(current()!==s)fail('ACCOUNT_SESSION_CHANGED');return v;}
 async function plain(row){if(!row)return null;let bytes;try{const raw=Uint8Array.from(atob(row.blob),c=>c.charCodeAt(0));bytes=new Uint8Array(await wait(crypto.subtle.decrypt({name:'AES-GCM',iv:raw.subarray(0,12)},current().masterKey,raw.subarray(12))));return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}finally{bytes?.fill(0);}}
 async function alias(base,level){const salt=current().blindSalt,bytes=utf(base+level),input=new Uint8Array(bytes.length+salt.length);input.set(bytes);input.set(salt,bytes.length);try{return await core.fastHash(input);}finally{input.fill(0);}}
 const kem=Object.freeze({generateKeys:()=>{const k=host('kemKeypair');return {pk:k.pk,sk:k.sk,success:true};},encapsulate:pk=>{const k=host('kemEncapsulate',pk);return {ct:k.ct,ss:k.ss,success:true};},decapsulate:(ct,sk)=>({ss:host('kemDecapsulate',ct,sk),success:true})});
 function logout(){++generation;runtime?.close();runtime=null;sealed?.close();sealed=null;journal?.close();journal=null;for(const p of peers.values()){try{host('transport',p.route,'owner.release',{});}catch(_){}}peers.clear();preparations=new WeakMap();if(session){session.controller.abort();session.db.close();session.keys.sign.secretKey.fill(0);session.keys.box.secretKey.fill(0);session.blindSalt.fill(0);}session=core=root=null;if(g.DMashStorage){DMashStorage.db=null;DMashStorage.masterKey=null;}return {loggedOut:true};}
 async function registryAccounts(){const secure=host('hasSecureRegistry'),db=new NativeAccountDatabase(secure?'dm_registry_secure_v1':'dm_registry_v1');try{const rows=await all(db,'accounts');return secure?host('registryRead',rows):rows;}finally{db.close();}}
 async function listAccounts(){return (await registryAccounts()).map(a=>({identity:a.id,accountPublicId:typeof a.pk==='string'?a.pk.slice(0,64):null}));}
 async function login({identity,password}){
  logout();const epoch=host('epoch');let full;
  try{const saved=(await registryAccounts()).find(a=>a.id===identity);if(!saved||typeof saved.pk!=='string'||!/^[0-9a-f]{128}/i.test(saved.pk))fail('ACCOUNT_NOT_SAVED');
   full=host('accountKdf',identity,password);if(host('epoch')!==epoch)fail('ACCOUNT_SESSION_CHANGED');
   const sign=nacl.sign.keyPair.fromSeed(full.slice(64,96)),box=nacl.box.keyPair.fromSecretKey(full.slice(96,128));
   if(hex(sign.publicKey)!==saved.pk.slice(0,64).toLowerCase()||hex(box.publicKey)!==saved.pk.slice(64,128).toLowerCase()){sign.secretKey.fill(0);box.secretKey.fill(0);fail('ACCOUNT_PASSWORD_REJECTED');}
   const masterKey=await crypto.subtle.importKey('raw',full.slice(0,32),{name:'AES-GCM'},false,['encrypt','decrypt']);
   if(host('epoch')!==epoch){sign.secretKey.fill(0);box.secretKey.fill(0);fail('ACCOUNT_SESSION_CHANGED');}
   const controller=new AbortController(),db=new NativeAccountDatabase('dm_gamma_vault'),keys={sign,box},blindSalt=full.slice(32,64);
   session={epoch,controller,signal:controller.signal,db,masterKey,keys,blindSalt,generation:++generation,assertCurrent:()=>current()};
   const listeners=new Set();root={state:{nativeOwnerEpoch:epoch},onLock:fn=>{listeners.add(fn);return()=>listeners.delete(fn);}};
   core={keys,blindSalt,activeIdentity:identity,_accountBootAttempt:{},captureAccountSessionV4:()=>{current();return session;},
    // Exact effective legacy Core.fastHash: UTF8(String(typedArray)), including commas.
    fastHash:async m=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',utf(String(m)))))};
   g.Core=core;Storage.db=db;Storage.masterKey=masterKey;
   const codec=DmashAccountRouteBindingV2.createBindingCodec({nacl,discovery:DmashRouteDiscoveryV4,pairing:DmashAccountPairingV2.createCodec({nacl,discovery:DmashRouteDiscoveryV4}),subtle:crypto.subtle});
   journal=await DmashAccountRouteJournalV2.open({storage:{db,masterKey},core,deviceRoot:root,accountSignal:controller.signal,bindingCodec:codec,verifyPreparation});
   sealed=await DmashAccountSealedOperationV4.open({session,journal});
   const history=new DmashAccountAuthenticatedHistoryV4({core});
   const transport={readRouteSnapshot:peer=>journal.readRouteSnapshot(peer),prepareAndSubmitIntent:submitIntent};
   runtime=new DmashAccountSessionRuntimeV4({core,transport,kem,persistAuthenticated:v=>history.persistAuthenticated(v),persistOutgoing:v=>history.persistOutgoing(v),persistOutgoingAck:v=>history.ackOutgoing(v),outgoingDeliveryStatus:v=>history.outgoingDeliveryStatus(v),verifyOutgoingDeliveryStatus:(v,e)=>history.verifyOutgoingDeliveryStatus(v,e)});
   controller.signal.addEventListener('abort',()=>history.close(),{once:true});
   return {accountPublicId:hex(sign.publicKey),displayName:identity};
  }catch(e){logout();throw e;}finally{full?.fill(0);}
 }
 async function listContacts(){const s=current(),rows=await wait(all(s.db,'blind_peers')),out=[];for(const row of rows){try{const p=await plain(row);if(typeof p?.id==='string'&&typeof p.name==='string')out.push({id:p.id,name:p.name,state:p.securityAlert?'SECURITY_ALERT':p.transportProfile||'LEGACY',chatLocked:!!p.chatLock});}catch(e){current();/* Different Accounts share encrypted blind rows; no plaintext is exposed. */}}return DmashSavedMessages.peers(out);}
 async function listHistory({peer,before=0,limit=50}){current();if(typeof peer!=='string'||!Number.isInteger(limit)||limit<1||limit>100)fail('ACCOUNT_HISTORY_INPUT');const a=await alias(peer,'L1'),contact=await plain(await wait(read(session.db,'blind_peers',a)));if(contact?.chatLock)fail('ACCOUNT_CHAT_PASSWORD_REQUIRED');const secrets=await plain(await wait(read(session.db,'blind_secrets',a))),count=secrets?.msgCount??0;if(!Number.isSafeInteger(count)||count<0||count>1000000)fail('ACCOUNT_HISTORY_CORRUPT');let seq=before?Math.min(count,before-1):count;const out=[];for(;seq>0&&out.length<limit;--seq){const row=await wait(read(session.db,'blind_messages',await alias(a+seq,'L3')));if(!row)continue;const m=await plain(row);if(typeof m?.text!=='string')fail('ACCOUNT_HISTORY_CORRUPT');out.push({sequence:seq,operationId:m.wireId??null,direction:m.inbound?'in':'out',text:m.text,time:m.ts,state:m.transportState??null});}return out;}
 async function verifyPreparation(handle,expected={}){
  current();const entry=preparations.get(handle);if(!entry)fail('NODE_PREPARATION_HANDLE_REQUIRED');
  const live=host('transport',entry.route,'owner.query',{migrationId:entry.tuple.migrationId});current();
  if(!['NODE_PREPARED','ACTIVE'].includes(live?.state)||!samePreparation(live,entry.tuple)||Object.entries(expected).some(([name,value])=>live[name]!==value))fail('NODE_PREPARATION_CHANGED');
  return live;
 }
 // Read only the existing authenticated orchestrator index and its selected
 // intent. Route material is never invented to make an imported contact ready.
 async function routeIntent(peer,snapshot){
  const domain='D-MASH|PUBLIC-ACCOUNT-INTENT|V4\0',account=hex(current().keys.sign.publicKey),hmac=await wait(crypto.subtle.importKey('raw',session.blindSalt,{name:'HMAC',hash:'SHA-256'},false,['sign']));
  const location=async(a,b)=>hex(new Uint8Array(await wait(crypto.subtle.sign('HMAC',hmac,utf(domain+account+'|'+a+'|'+b)))));
  const readIntent=async id=>{const row=await wait(read(session.db,'pairing_material',id));if(!row||row.alias!==id||typeof row.blob!=='string'||row.blob.length>65536)fail('NODE_ROUTE_INTENT_REQUIRED');let bytes;
   try{const raw=Uint8Array.from(atob(row.blob),v=>v.charCodeAt(0));if(raw.length<28)fail('NODE_ROUTE_INTENT_CORRUPT');bytes=new Uint8Array(await wait(crypto.subtle.decrypt({name:'AES-GCM',iv:raw.subarray(0,12),additionalData:utf(domain+id)},session.masterKey,raw.subarray(12))));return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}finally{bytes?.fill(0);}};
  const index=await readIntent(await location('0'.repeat(64),'0'.repeat(64)));
  if(index.type!=='PUBLIC_ACTIVE_INDEX_V4'||index.account!==account||!Array.isArray(index.peers)||index.peers.length>32)fail('NODE_ROUTE_INDEX_CORRUPT');
  const selected=index.peers.filter(row=>row.peer===peer);if(selected.length!==1||!key(selected[0].intentAlias))fail('NODE_ROUTE_INTENT_REQUIRED');
  const value=await readIntent(selected[0].intentAlias);
  if(value.type!=='PUBLIC_ACCOUNT_INTENT_V4'||value.account!==account||!key(value.registration)||!key(value.requestId)||!key(value.migrationId)||await location(value.registration,value.requestId)!==selected[0].intentAlias)fail('NODE_ROUTE_INTENT_CORRUPT');
  const local=DmashAccountPairingV2.createCodec({nacl,discovery:DmashRouteDiscoveryV4}).parse(value.bundle,{expectedPeer:account,localAccount:peer}).bundle;
  if(JSON.stringify(local.inbound_certificate)!==JSON.stringify(snapshot.localCertificate)||local.account_keys.signing!==account||local.account_keys.box!==hex(session.keys.box.publicKey))fail('NODE_ROUTE_AUTHORITY_CHANGED');
  for(const name of ['discoverySeed','discoveryBox','recipientKey'])if(!key(value[name]))fail('NODE_ROUTE_MATERIAL_REQUIRED');
  return value;
 }
 async function activateRoute(peer,snapshot,p){
  if(snapshot.preparation){const live=host('transport',p.route,'owner.query',{migrationId:snapshot.preparation.migrationId});if(!samePreparation(live,snapshot.preparation))fail('NODE_PREPARATION_CHANGED');if(live.state==='ACTIVE')return p;}
  const intent=await routeIntent(peer,snapshot),coherent=await wait(journal.readCoherent(peer));
  if(!coherent||coherent.summary.digest!==snapshot.digest||coherent.summary.generation!==snapshot.generation||!coherent.journal.bundles.includes(intent.bundle))fail('ACCOUNT_ROUTE_CHANGED');
  const tuple=host('transport',p.route,'owner.prepare',{migrationId:intent.migrationId,bindingDigest:snapshot.digest,expectedGeneration:snapshot.generation,certificate:snapshot.localCertificate,discoverySeed:intent.discoverySeed,discoveryBox:intent.discoveryBox,recipientKeys:[intent.recipientKey]});current();
  const handle=Object.freeze({});preparations.set(handle,{route:p.route,tuple:preparationTuple(tuple)});
  const stage=await wait(journal.stage(coherent.journal.bundles,peer));await wait(journal.reserveAndSign(stage,coherent.journal.receipts[0]));
  const committed=await wait(journal.commit(stage,coherent.journal.receipts,{preparation:handle}));
  if(!committed.commitReceipt||!await wait(journal.verifyCommitReceipt(committed.commitReceipt,preparationTuple(tuple))))fail('ACCOUNT_COMMIT_RECEIPT_REQUIRED');
  const active=host('transport',p.route,'owner.activate',{tuple:preparationTuple(tuple)});current();
  if(active.state!=='ACTIVE'||!samePreparation(active,tuple))fail('NODE_ROUTE_NOT_ACTIVE');return p;
 }
 async function owner(peer,snapshot){let p=peers.get(peer);const route=snapshot.localCertificate.route_id;
  if(p&&p.route===route){try{return await activateRoute(peer,snapshot,p);}catch(error){current();if(!['REQUEST_REJECTED','ACCOUNT_TRANSPORT_UNAVAILABLE','ACCOUNT_TRANSPORT_FAILED','ACCOUNT_TRANSPORT_TIMEOUT','ACCOUNT_TRANSPORT_REJECTED'].includes(error.code))throw error;peers.delete(peer);/* A renewed daemon capability has a fresh local owner socket. Re-prove the same Account before retrying once. */}}
  const challenge=host('transport',route,'owner.challenge',{accountPublic:hex(current().keys.sign.publicKey),certificate:snapshot.localCertificate,archive:false});
  const proof=JSON.parse(challenge.transcript);if(proof.domain!=='D-MASH|LOCAL-OWNER|V4'||proof.accountPublic!==hex(session.keys.sign.publicKey)||proof.routeId!==route||proof.challenge!==challenge.challenge)fail('ACCOUNT_OWNER_CHALLENGE');
  const signature=hex(nacl.sign.detached(utf(challenge.transcript),session.keys.sign.secretKey));host('transport',route,'owner.register',{challenge:challenge.challenge,signature});
  p={route};peers.set(peer,p);return activateRoute(peer,snapshot,p);
 }
 async function submitIntent(intent){let snapshot=await wait(journal.readRouteSnapshot(intent.peer));if(!snapshot||snapshot.readiness!=='NODE_PROOF_REQUIRED')fail(snapshot?.readiness||'ACCOUNT_ROUTE_REQUIRED');if(snapshot.digest!==intent.bindingDigest||snapshot.generation!==intent.generation)fail('ACCOUNT_ROUTE_CHANGED');const p=await owner(intent.peer,snapshot);snapshot=await wait(journal.readRouteSnapshot(intent.peer));
  if(!snapshot.preparation)fail('NODE_PREPARATION_REQUIRED');const actual=host('transport',p.route,'owner.query',{migrationId:snapshot.preparation.migrationId});if(actual?.state!=='ACTIVE')fail('NODE_ROUTE_NOT_ACTIVE');
  const sealedOperation=await wait(sealed.materialize(intent)),destination=host('transport',p.route,'destination.install',{certificate:snapshot.remoteCertificate,replyRouteId:p.route});
  const expiresAt=Math.min(destination.expiresAt,Date.now()+86400000),result=host('transport',p.route,'job.submit',{destination:destination.handle,operationId:intent.operationId,blob:sealedOperation.blob,expiresAt});if(result.accepted!==true)fail('LOCAL_NODE_REFUSED');return {queued:true,state:result.state,jobId:result.id};
 }
 async function sendText({peer,operationId,text}){current();if(DmashSavedMessages.isLocal(peer)){
  if(!key(operationId)||typeof text!=='string'||!text||utf(text).length>8192)fail('ACCOUNT_MESSAGE_INPUT');
  await DmashSavedMessages.ensure(Storage);
  const a=await alias(peer,'L1'),secrets=await plain(await wait(read(session.db,'blind_secrets',a))),count=secrets?.msgCount??0;
  for(let seq=count;seq>0;--seq){const row=await plain(await wait(read(session.db,'blind_messages',await alias(a+seq,'L3'))));if(row?.wireId===operationId){if(row.text!==text)fail('ACCOUNT_OPERATION_CONFLICT');return {accepted:true,operationId,transportState:'LOCAL',recipientAck:false,sequence:seq,duplicate:true};}}
  const sequence=await wait(Storage.saveMessageGamma(peer,text,false,true,'LOCAL',operationId));return {accepted:true,operationId,transportState:'LOCAL',recipientAck:false,sequence};
 }if(!key(peer)||!key(operationId)||typeof text!=='string'||utf(text).length>8192)fail('ACCOUNT_MESSAGE_INPUT');const status=await wait(runtime.openPeer(peer,{requiredSuite:DmashAccountHandshakeV4.SUITE}));if(status.phase!=='ESTABLISHED'){if(status.phase==='NO_SESSION')await wait(runtime.initiate(peer));return {accepted:false,operationId,transportState:'HANDSHAKE_PENDING',recipientAck:false};}const result=await wait(runtime.sendApplication(peer,{operationId,plaintext:text}));return {accepted:result?.durable===true,operationId,transportState:result?.recipientAck===true?'DELIVERED':result?.queued===true?'NODE_ACCEPTED':'APPLICATION_PENDING',recipientAck:result?.recipientAck===true,result};}
 async function sync(){current();const contacts=await listContacts(),results=[];
  for(const contact of contacts.filter(p=>key(p.id)&&p.state==='NODE_ACCOUNT_V4').slice(0,32)){
   const peer=contact.id;try{const snapshot=await wait(journal.readRouteSnapshot(peer));if(!snapshot||snapshot.readiness!=='NODE_PROOF_REQUIRED')fail(snapshot?.readiness||'ACCOUNT_ROUTE_REQUIRED');
    await wait(runtime.openPeer(peer,{requiredSuite:DmashAccountHandshakeV4.SUITE}));const p=await owner(peer,snapshot);
    const page=host('transport',p.route,'inbox.list',{limit:32,after:null});let consumed=0;
    for(const record of page.records||[]){if(typeof record.payload!=='string'||record.routeId!==p.route)continue;
     const received=await wait(runtime.receive({peer,frame:record.payload,localRouteId:p.route,bindingDigest:snapshot.digest,generation:snapshot.generation}));
     if(received?.persisted===true){const commitToken=hex(new Uint8Array(await wait(crypto.subtle.digest('SHA-256',utf(record.payload)))));host('transport',p.route,'inbox.commitConsumption',{recordHandle:record.handle,applicationCommitToken:commitToken});consumed++;}
    }
    await wait(runtime.resume());results.push({peer,consumed,status:await wait(runtime.status(peer))});
   }catch(e){current();results.push({peer,code:e.code||'ACCOUNT_SYNC_FAILED',debugStack:String(e.stack).slice(0,2048)});}
  }return results;
 }
 g.NativeAccount=Object.freeze({listAccounts,login,listContacts,listHistory,sendText,sync,logout});
})(globalThis);
