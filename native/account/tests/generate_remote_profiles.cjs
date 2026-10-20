'use strict';
// Private synthetic bilateral fixture. Actual shipped Argon2, pairing signatures,
// journal reserve/commit and original Kyber WASM are used; no UI pairing claim.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {webcrypto,createHash}=require('node:crypto');
const {indexedDB}=require('fake-indexeddb');
const repo=path.resolve(__dirname,'../../..'),js=path.join(repo,'D-MASH PWA/not_messenger/js');
const output=path.resolve(process.argv[2]);fs.mkdirSync(output,{recursive:true,mode:0o700});
global.nacl=require(path.join(js,'vendor/nacl-fast.min.js'));
const hex=b=>Buffer.from(b).toString('hex'),utf=s=>new TextEncoder().encode(s),random=()=>webcrypto.getRandomValues(new Uint8Array(32));
const discovery=require(path.join(js,'route_discovery_v4.js'));
const pairing=require(path.join(js,'account_pairing_v2.js')).createCodec({nacl,discovery});
const binding=require(path.join(js,'account_route_binding_v2.js')).createBindingCodec({nacl,discovery,pairing});
const Journal=require(path.join(js,'account_route_journal_v2.js'));
const StaticKem=require(path.join(js,'account_static_kem_v1.js'));
async function packed(master,value,aad){const iv=webcrypto.getRandomValues(new Uint8Array(12));return Buffer.concat([Buffer.from(iv),Buffer.from(await webcrypto.subtle.encrypt({name:'AES-GCM',iv,...(aad?{additionalData:utf(aad)}:{})},master,utf(JSON.stringify(value))))]).toString('base64');}
async function rows(db,store){return new Promise((resolve,reject)=>{const tx=db.transaction(store,'readonly'),r=tx.objectStore(store).getAll();r.onsuccess=()=>resolve(r.result);tx.onabort=()=>reject(tx.error);});}
async function put(db,store,row){return new Promise((resolve,reject)=>{const tx=db.transaction(store,'readwrite');tx.objectStore(store).put(row);tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);});}
(async()=>{
 const context={WebAssembly,TextEncoder,TextDecoder,Uint8Array,Int8Array,Uint16Array,Int16Array,Uint32Array,Int32Array,Float32Array,Float64Array,ArrayBuffer,Promise,Math,Date,console,atob,btoa,setTimeout,clearTimeout};context.window=context;context.self=context;vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(js,'vendor/argon2-bundled.min.js'),'utf8'),context);
 let wasm;const raw=fs.readFileSync(path.join(js,'vendor/kyber768.wasm'));
 if(createHash('sha256').update(raw).digest('hex')!=='e9b316e56f5d1eef1f44f28bca99bec16ec9cff69af4b17d318143512255b009')throw Error('KEM fixture source changed');
 const instance=await WebAssembly.instantiate(raw,{a:{a(){throw Error('original OOM');},b(code,signature,args){if(code!==1476)throw Error('original random callback');const heap=new Uint8Array(wasm.c.buffer),view=new DataView(wasm.c.buffer),at=view.getUint32(args,true),size=view.getUint32(args+4,true);webcrypto.getRandomValues(heap.subarray(at,at+size));return 0;}}});wasm=instance.instance.exports;wasm.d();
 const module={_malloc:wasm.h,_free:wasm.i,_wasm_keypair:wasm.e,_wasm_encapsulate:wasm.f,_wasm_decapsulate:wasm.g,get HEAPU8(){return new Uint8Array(wasm.c.buffer);}};
 const storeNames=['blind_peers','blind_secrets','blind_messages','pairing_material','blind_outbox','blind_files','blind_file_owners'];
 const people=[];
 for(let i=0;i<2;i++){
  const identity='native-remote-'+i+'-'+hex(random()).slice(0,12),password=hex(random());
  const full=(await context.argon2.hash({pass:password,salt:identity+'D_MASH_GAMMA_V1_STABLE',type:0,time:3,mem:65536,hashLen:128})).hash;
  const sign=nacl.sign.keyPair.fromSeed(full.slice(64,96)),box=nacl.box.keyPair.fromSecretKey(full.slice(96,128)),masterKey=await webcrypto.subtle.importKey('raw',full.slice(0,32),'AES-GCM',false,['encrypt','decrypt']);
  const db=await new Promise(resolve=>{const r=indexedDB.open('native-remote-'+i,1);r.onupgradeneeded=()=>storeNames.forEach(s=>r.result.createObjectStore(s,{keyPath:'alias'}));r.onsuccess=()=>resolve(r.result);});
  const controller=new AbortController(),root={state:{},onLock(){return()=>{};}},session={db,masterKey,keys:{sign,box},blindSalt:full.slice(32,64),generation:1,signal:controller.signal,assertCurrent(){if(controller.signal.aborted)throw Error('fixture closed');}};
  const core={keys:session.keys,blindSalt:session.blindSalt,activeIdentity:identity,_accountBootAttempt:{},captureAccountSessionV4:()=>session};
  const journal=await Journal.open({storage:{db,masterKey},core,deviceRoot:root,accountSignal:controller.signal,bindingCodec:binding});
  const kem=await StaticKem.open({session,kem:StaticKem.wasmAdapter(module)}),keys=await kem.createExplicit();
  const p={identity,password,full,sign,box,masterKey,db,journal,kem,keys,session,route:nacl.sign.keyPair(),ds:nacl.sign.keyPair(),dbox:nacl.box.keyPair(),recipient:nacl.box.keyPair(),migrationId:hex(random()),id:hex(random())};people.push(p);
 }
 const now=Math.floor(Date.now()/1000),certificateLifetime=process.env.DMASH_TEST_LONG_CERT==='1'?172800:3600;
 for(const p of people){const peer=people.find(x=>x!==p);p.peer=hex(peer.sign.publicKey);p.certificate=discovery.issueCertificate(p.route,p.ds.publicKey,p.dbox.publicKey,p.recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+certificateLifetime});p.bundle=pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(random()),generation:1,issued_at:now,expires_at:now+3600,previous_binding:null,intended_peer:p.peer,contribution:hex(random()),account_keys:{signing:hex(p.sign.publicKey),box:hex(p.box.publicKey),kem_profile:p.keys.profile,kem_public:Buffer.from(p.keys.publicKey).toString('base64url')},inbound_certificate:p.certificate},p.sign.secretKey,{localAccount:p.peer}).serialized;}
 const bundles=people.map(p=>p.bundle);for(const p of people)p.stage=await p.journal.stage(bundles,p.peer);
 const first=people.find(p=>p.stage.phase==='ACCEPT'),last=people.find(p=>p.stage.phase==='CONFIRM');
 const accept=await first.journal.reserveAndSign(first.stage),confirm=await last.journal.reserveAndSign(last.stage,accept);
 for(const p of people){
  await p.journal.commit(p.stage,[accept,confirm]);
  const account=hex(p.sign.publicKey),domain='D-MASH|PUBLIC-ACCOUNT-INTENT|V4\0',hmac=await webcrypto.subtle.importKey('raw',p.session.blindSalt,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const location=async(a,b)=>hex(new Uint8Array(await webcrypto.subtle.sign('HMAC',hmac,utf(domain+account+'|'+a+'|'+b))));
  const intentAlias=await location(p.id,p.id),indexAlias=await location('0'.repeat(64),'0'.repeat(64));
  const intent={type:'PUBLIC_ACCOUNT_INTENT_V4',account,registration:p.id,requestId:p.id,requestDigest:p.id,direction:'PRIVATE',target:p.peer,bundle:p.bundle,routeSeed:hex(p.route.secretKey.subarray(0,32)),discoverySeed:hex(p.ds.secretKey.subarray(0,32)),discoveryBox:hex(p.dbox.secretKey),recipientKey:hex(p.recipient.secretKey),migrationId:p.migrationId,controls:{}};
  await put(p.db,'pairing_material',{alias:intentAlias,blob:await packed(p.masterKey,intent,domain+intentAlias)});
  await put(p.db,'pairing_material',{alias:indexAlias,blob:await packed(p.masterKey,{type:'PUBLIC_ACTIVE_INDEX_V4',account,peers:[{peer:p.peer,intentAlias}]},domain+indexAlias)});
  const alias=(base,level)=>createHash('sha256').update(Array.from(Buffer.concat([Buffer.from(base+level),Buffer.from(p.session.blindSalt)])).join(',')).digest('hex');
  await put(p.db,'blind_peers',{alias:alias(p.peer,'L1'),blob:await packed(p.masterKey,{id:p.peer,name:'Synthetic remote peer',transportProfile:'NODE_ACCOUNT_V4',chatLock:false})});
  const base=JSON.parse(fs.readFileSync(path.join(__dirname,'account_profile.json'))),profile=base.profile;
  const registryRaw=new Uint8Array(32).fill(11),registry=await webcrypto.subtle.importKey('raw',registryRaw,'AES-GCM',false,['encrypt']),registryHmac=await webcrypto.subtle.importKey('raw',registryRaw,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const registryAlias=Buffer.from(await webcrypto.subtle.sign('HMAC',registryHmac,utf(p.identity))).toString('base64');
  profile.databases.find(x=>x.name==='dm_registry_secure_v1').stores.find(x=>x.name==='accounts').records=[{alias:registryAlias,blob:await packed(registry,{id:p.identity,pk:account+hex(p.box.publicKey)},'dmash/account-registry/v1')}];
  profile.databases.find(x=>x.name==='dm_gamma_vault').stores=await Promise.all(storeNames.map(async name=>({name,records:await rows(p.db,name)})));
  const fixture={synthetic:true,identity:p.identity,password:p.password,rootPin:base.rootPin,accountPublicId:account,peer:p.peer,routeId:p.certificate.route_id,ownerStorageKey:hex(random()),profile};
  fs.writeFileSync(path.join(output,'account-'+people.indexOf(p)+'.json'),JSON.stringify(fixture),{mode:0o600});
  p.kem.release(p.keys);p.kem.close();p.journal.close();p.full.fill(0);p.sign.secretKey.fill(0);p.box.secretKey.fill(0);p.db.close();
 }
 console.log(JSON.stringify({status:'PASS',scope:'synthetic bilateral real pairing/journal and legacy WASM fixture',accounts:2}));
})().catch(error=>{console.error(error.code||error.message);process.exitCode=1;});
