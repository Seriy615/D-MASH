'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const names=['vendor/nacl-fast.min.js','route_discovery_v4.js','account_pairing_v2.js','account_route_binding_v2.js','account_route_journal_v2.js','storage.js','secure_session.js','recipient_payload_v4.js','account_sealed_operation_v4.js'];
const sources=new Map(names.map(name=>['/js/'+name,fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js',name))]));
(async()=>{
 const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(names.map(name=>'<script src="/js/'+name+'"></script>').join(''));}else if(sources.has(req.url)){res.setHeader('Content-Type','application/javascript');res.end(sources.get(req.url));}else{res.statusCode=404;res.end();}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME,headless:true});const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  const setup=async()=>page.evaluate(async()=>{
   const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''),seed=n=>new Uint8Array(32).fill(n);
   const person=n=>({n,sign:nacl.sign.keyPair.fromSeed(seed(n)),box:nacl.box.keyPair.fromSecretKey(seed(n+1)),route:nacl.sign.keyPair.fromSeed(seed(n+2)),ds:nacl.sign.keyPair.fromSeed(seed(n+3)),db:nacl.box.keyPair.fromSecretKey(seed(n+4)),recipient:nacl.box.keyPair.fromSecretKey(seed(n+5))});
   const people=[person(1),person(11)].sort((a,b)=>hex(a.sign.publicKey)<hex(b.sign.publicKey)?-1:1),local=people[0],remote=people[1],third=person(21);let now=Math.floor(Date.now()/1000);
   await Storage.initGamma(seed(100));
   const pairing=DmashAccountPairingV2.createCodec({nacl,discovery:DmashRouteDiscoveryV4}),binding=DmashAccountRouteBindingV2.createBindingCodec({nacl,discovery:DmashRouteDiscoveryV4,pairing,clock:()=>now});
   const bundle=(p,{generation=1,previous=null,id=p.n+30,contribution=p.n+60,target=null}={})=>pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(seed(id)),generation,issued_at:now,expires_at:now+600,previous_binding:previous,intended_peer:target,contribution:hex(seed(contribution)),account_keys:{signing:hex(p.sign.publicKey),box:hex(p.box.publicKey),kem_profile:'LEGACY_KYBER768_BUNDLE_V1',kem_public:btoa(String.fromCharCode(...new Uint8Array(1184).fill(p.n))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')},inbound_certificate:DmashRouteDiscoveryV4.issueCertificate(p.route,p.ds.publicKey,p.db.publicKey,p.recipient.publicKey,{generation,issuedAt:now,expiresAt:now+900})},p.sign.secretKey,{now,localAccount:target??undefined}).serialized;
   const make=async(p=local,keyByte=100)=>{
    const controller=new AbortController(),observers=new Set(),root={state:{},onLock(fn){observers.add(fn);return()=>observers.delete(fn);},lock(){this.state=null;for(const fn of observers)fn();}};
    const key=await crypto.subtle.importKey('raw',seed(keyByte),'AES-GCM',false,['encrypt','decrypt']),storage={db:Storage.db,masterKey:key},core={keys:{sign:p.sign},blindSalt:seed(p.n+120),activeIdentity:'synthetic-'+p.n,_accountBootAttempt:{},_accountTransitioning:false};
    const options={storage,core,deviceRoot:root,accountSignal:controller.signal,bindingCodec:binding,clock:()=>now},journal=await DmashAccountRouteJournalV2.open(options);return {journal,storage,core,root,controller,options};
   };
   const raw=()=>new Promise((resolve,reject)=>{const tx=Storage.db.transaction('pairing_material','readonly'),r=tx.objectStore('pairing_material').getAll();r.onsuccess=()=>resolve(r.result);tx.onerror=()=>reject(tx.error);});
   const rawPut=row=>new Promise((resolve,reject)=>{const tx=Storage.db.transaction('pairing_material','readwrite');tx.objectStore('pairing_material').put(row);tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);});
   const rejects=async(fn,code)=>{try{await fn();return false;}catch(error){if(code&&error.code!==code)throw error;return true;}};
   const complete=async(bundles,receipt,committed=null)=>{const c=await binding.prepare(bundles,{expectedParticipants:[hex(local.sign.publicKey),hex(remote.sign.publicKey)],committed});return [receipt,binding.signReceipt(c,'CONFIRM',remote.sign.secretKey,receipt)];};
   window.qa={setTime:value=>now=value,hex,seed,local,remote,third,binding,bundle,make,raw,rawPut,rejects,complete,peer:hex(remote.sign.publicKey),localId:hex(local.sign.publicKey)};
  });
  await setup();
  const result=await page.evaluate(async()=>{
   const q=qa,f=await q.make(),j=f.journal,bundles=[q.bundle(q.local),q.bundle(q.remote,{target:q.localId})],h=await j.stage(bundles,q.peer);
   const receipt=await j.reserveAndSign(h);await j.commit(h,await q.complete(bundles,receipt));
   const session={...f.storage,db:f.storage.db,masterKey:f.storage.masterKey,blindSalt:f.core.blindSalt,signal:f.controller.signal,assertCurrent:()=>j.check()};
   const options={session,journal:j},Store=DmashAccountSealedOperationV4,store=await Store.open(options),op={operationId:'ab'.repeat(32),peer:q.peer,bindingDigest:h.digest,generation:1,frame:'synthetic exact signed frame bytes'};
   const first=await store.materialize(op),second=await store.materialize(op);if(first.blob!==second.blob)throw Error('Retry resealed');
   const opened=DmashRecipientPayloadV4.openPayload([q.remote.recipient.secretKey],first.blob);if(opened.status!=='accepted'||opened.payload!==op.frame)throw Error('Real recipient decryption failed');
   store.close();const restored=await Store.open(options),third=await restored.materialize(op);if(third.blob!==first.blob)throw Error('Restart resealed');
   if(!await q.rejects(()=>restored.materialize({...op,frame:op.frame+' altered'}),'SEALED_OPERATION_CONFLICT'))throw Error('Changed frame accepted');
   if(!await q.rejects(()=>restored.materialize({...op,generation:2}),'SEALED_OPERATION_BINDING'))throw Error('Changed generation accepted');
   const concurrentOp={...op,operationId:'ac'.repeat(32)},other=await Store.open(options),race=await Promise.all([restored.materialize(concurrentOp),other.materialize(concurrentOp)]);if(race[0].blob!==race[1].blob)throw Error('Competing envelopes escaped');
   const nativePut=IDBObjectStore.prototype.put;let aborted=false;
   IDBObjectStore.prototype.put=function(row,...args){const value=nativePut.call(this,row,...args);if(row.alias&&!aborted){aborted=true;this.transaction.abort();}return value;};
   const failedOp={...op,operationId:'ad'.repeat(32)};let failed=false;try{await restored.materialize(failedOp);}catch(_){failed=true;}finally{IDBObjectStore.prototype.put=nativePut;}
   if(!failed||!aborted)throw Error('Aborted persistence returned ciphertext');
   const retry=await restored.materialize(failedOp);if(!retry.blob)throw Error('Crash retry failed');
   let release,entered;const gate=new Promise(r=>entered=r),wrapper={getRandomValues:crypto.getRandomValues.bind(crypto),subtle:{importKey:crypto.subtle.importKey.bind(crypto.subtle),sign:crypto.subtle.sign.bind(crypto.subtle),digest:crypto.subtle.digest.bind(crypto.subtle),decrypt:crypto.subtle.decrypt.bind(crypto.subtle),encrypt:async(...args)=>{entered();await new Promise(r=>release=r);return crypto.subtle.encrypt(...args);}}};
   const migrationDelayed=await Store.open({...options,crypto:wrapper}),migrationPending=q.rejects(()=>migrationDelayed.materialize({...op,operationId:'af'.repeat(32)}),'SEALED_OPERATION_BINDING');await gate;
   const nextBundles=[q.bundle(q.local,{generation:2,previous:h.digest,target:q.peer,id:101,contribution:102}),q.bundle(q.remote,{generation:2,previous:h.digest,target:q.localId,id:103,contribution:104})];
   const next=await j.stage(nextBundles,q.peer),nextReceipt=await j.reserveAndSign(next);await j.commit(next,await q.complete(nextBundles,nextReceipt,{generation:1,binding_digest:h.digest,participants:[q.localId,q.peer]}));
   release();if(!await migrationPending)throw Error('Changed binding emitted old operation');migrationDelayed.close();
   let abortEntered;const abortGate=new Promise(r=>abortEntered=r);wrapper.subtle.encrypt=async(...args)=>{abortEntered();await new Promise(r=>release=r);return crypto.subtle.encrypt(...args);};
   const delayed=await Store.open({...options,crypto:wrapper}),pending=q.rejects(()=>delayed.materialize({...op,bindingDigest:next.digest,generation:2,operationId:'ae'.repeat(32)}));await abortGate;f.controller.abort();release();if(!await pending)throw Error('Aborted Account emitted durable envelope');
   return {exactRetry:true,realRecipientDecrypt:true,reopenExactBytes:true,frameConflict:true,generationConflict:true,concurrentOneEnvelope:true,bindingMigrationDuringCryptoNoEnvelope:true,abortBeforePersistenceNoEnvelope:true,sessionAbortNoEnvelope:true};
  });
  assert(Object.values(result).every(Boolean));
  const report={scope:'BROWSER inactive sealed-operation fixture; real signed binding, AES-GCM/IndexedDB and recipient NaCl; no Node queue or UI claim',browser:await browser.version(),sourceHashes:Object.fromEntries([...sources].map(([name,data])=>[name,crypto.createHash('sha256').update(data).digest('hex')])),checks:result};
  if(process.env.DMASH_QA_OUTPUT)fs.writeFileSync(process.env.DMASH_QA_OUTPUT,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
