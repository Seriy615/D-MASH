'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const names=['vendor/nacl-fast.min.js','route_discovery_v4.js','account_pairing_v2.js','account_route_binding_v2.js','account_route_journal_v2.js','storage.js'];
const sources=new Map(names.map(name=>['/js/'+name,fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js',name))]));
(async()=>{
 const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(names.map(name=>'<script src="/js/'+name+'"></script>').join(''));}else if(sources.has(req.url)){res.setHeader('Content-Type','application/javascript');res.end(sources.get(req.url));}else{res.statusCode=404;res.end();}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME,headless:true});const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  const setup=async()=>page.evaluate(async()=>{
   const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''),seed=n=>new Uint8Array(32).fill(n);
   const person=n=>({n,sign:nacl.sign.keyPair.fromSeed(seed(n)),box:nacl.box.keyPair.fromSecretKey(seed(n+1)),route:nacl.sign.keyPair.fromSeed(seed(n+2)),ds:nacl.sign.keyPair.fromSeed(seed(n+3)),db:nacl.box.keyPair.fromSecretKey(seed(n+4)),recipient:nacl.box.keyPair.fromSecretKey(seed(n+5))});
   const people=[person(1),person(11)].sort((a,b)=>hex(a.sign.publicKey)<hex(b.sign.publicKey)?-1:1),local=people[0],remote=people[1],third=person(21),now=1800000000;
   await Storage.initGamma(seed(100));
   const pairing=DmashAccountPairingV2.createCodec({nacl,discovery:DmashRouteDiscoveryV4}),binding=DmashAccountRouteBindingV2.createBindingCodec({nacl,discovery:DmashRouteDiscoveryV4,pairing,clock:()=>now});
   const bundle=(p,{generation=1,previous=null,id=p.n+30,contribution=p.n+60,target=null}={})=>pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(seed(id)),generation,issued_at:now,expires_at:now+600,previous_binding:previous,intended_peer:target,contribution:hex(seed(contribution)),account_keys:{signing:hex(p.sign.publicKey),box:hex(p.box.publicKey),kem_profile:'LEGACY_KYBER768_BUNDLE_V1',kem_public:btoa(String.fromCharCode(...new Uint8Array(1184).fill(p.n))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')},inbound_certificate:DmashRouteDiscoveryV4.issueCertificate(p.route,p.ds.publicKey,p.db.publicKey,p.recipient.publicKey,{generation,issuedAt:now,expiresAt:now+900})},p.sign.secretKey,{now,localAccount:target??undefined}).serialized;
   const make=async(p=local,keyByte=100)=>{
    const controller=new AbortController(),observers=new Set(),root={state:{},onLock(fn){observers.add(fn);return()=>observers.delete(fn);},lock(){this.state=null;for(const fn of observers)fn();}};
    const key=await crypto.subtle.importKey('raw',seed(keyByte),'AES-GCM',false,['encrypt','decrypt']),storage={db:Storage.db,masterKey:key},core={keys:{sign:p.sign},blindSalt:seed(p.n+120),activeIdentity:'synthetic-'+p.n,_accountBootAttempt:{},_accountTransitioning:false};
    const options={storage,core,deviceRoot:root,accountSignal:controller.signal,bindingCodec:binding},journal=await DmashAccountRouteJournalV2.open(options);return {journal,storage,core,root,controller,options};
   };
   const raw=()=>new Promise((resolve,reject)=>{const tx=Storage.db.transaction('pairing_material','readonly'),r=tx.objectStore('pairing_material').getAll();r.onsuccess=()=>resolve(r.result);tx.onerror=()=>reject(tx.error);});
   const rawPut=row=>new Promise((resolve,reject)=>{const tx=Storage.db.transaction('pairing_material','readwrite');tx.objectStore('pairing_material').put(row);tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);});
   const rejects=async(fn,code)=>{try{await fn();return false;}catch(error){if(code&&error.code!==code)throw error;return true;}};
   const complete=async(bundles,receipt,committed=null)=>{const c=await binding.prepare(bundles,{expectedParticipants:[hex(local.sign.publicKey),hex(remote.sign.publicKey)],committed});return [receipt,binding.signReceipt(c,'CONFIRM',remote.sign.secretKey,receipt)];};
   window.qa={hex,seed,local,remote,third,binding,bundle,make,raw,rawPut,rejects,complete,peer:hex(remote.sign.publicKey),localId:hex(local.sign.publicKey)};
  });
  await setup();
  const first=await page.evaluate(async()=>{
   const q=qa,f=await q.make(),j=f.journal,bundles=[q.bundle(q.local),q.bundle(q.remote,{target:q.localId})],handle=await j.stage(bundles,q.peer);
   await Storage.putBox('blind_messages',{alias:'synthetic-history-sentinel',data:{text:'retained history'}});
   const before=(await q.raw()).length,oneReceipt=await q.rejects(()=>j.commit(handle,[]),'BOTH_RECEIPTS_REQUIRED');if((await q.raw()).length!==before)throw Error('Unsigned commit wrote records');
   const receipt=await j.reserveAndSign(handle),retry=await j.reserveAndSign(handle);if(retry!==receipt)throw Error('Receipt retry changed bytes');
   const crossed=[q.bundle(q.local,{id:90,contribution:91}),q.bundle(q.remote,{id:92,contribution:93})],other=await j.stage(crossed,q.peer);
   const signingConflict=await q.rejects(()=>j.reserveAndSign(other),'SIGNING_CONFLICT');
   const otherPeer=q.hex(q.third.sign.publicKey),reused=await j.stage([bundles[0],q.bundle(q.third)],otherPeer);
   const consumedOffer=await q.rejects(()=>j.reserveAndSign(reused),'OFFER_CONSUMED');
   const full=await q.complete(bundles,receipt);j.close();
   return {bundles,receipt,full,digest:handle.digest,oneReceipt,signingConflict,consumedOffer};
  });
  for(const key of ['oneReceipt','signingConflict','consumedOffer'])assert.equal(first[key],true,key);
  // Restart after durable reservation but before map commit: exact receipt survives.
  await page.reload();await setup();
  const committed=await page.evaluate(async first=>{
   const q=qa,f=await q.make(),j=f.journal,h=await j.stage(first.bundles,q.peer),sameReceipt=await j.reserveAndSign(h)===first.receipt;
   if(await j.readCommitted(q.peer)!==null)throw Error('Reservation activated mapping');
   const result=await j.commit(h,first.full),view=await j.readCommitted(q.peer);if(result.ready||view.ready||view.digest!==h.digest)throw Error('Invalid blocked commit');
   const repeated=await j.commit(h,first.full);if(!repeated.replayed)throw Error('Non-idempotent commit');
   const all=JSON.stringify(await q.raw()),encrypted=![q.localId,q.peer,'DMASH_ACCOUNT_ROUTE_RECEIPT',first.receipt].some(value=>all.includes(value));
   const inactive=await q.rejects(()=>j.activate({state:'NODE_ACTIVE'}),'NODE_ACTIVATION_UNIMPLEMENTED');j.close();return {sameReceipt,encrypted,inactive,digest:view.digest};
  },first);
  for(const key of ['sameReceipt','encrypted','inactive'])assert.equal(committed[key],true,key);
  // Restart after the four-record commit and fault each subsequent put independently.
  await page.reload();await setup();
  const faults=await page.evaluate(async first=>{
   const q=qa,f=await q.make(),j=f.journal,previous=await j.readCommitted(q.peer);if(previous.digest!==first.digest)throw Error('Committed pointer lost on reload');
   const bundles=[q.bundle(q.local,{generation:2,previous:first.digest,target:q.peer,id:101,contribution:102}),q.bundle(q.remote,{generation:2,previous:first.digest,target:q.localId,id:103,contribution:104})],h=await j.stage(bundles,q.peer),receipt=await j.reserveAndSign(h),snapshot={generation:1,binding_digest:first.digest,participants:[q.localId,q.peer]},full=await q.complete(bundles,receipt,snapshot);
   const baseline=JSON.stringify(await q.raw()),nativePut=IDBObjectStore.prototype.put,aborts=[];
   for(let at=1;at<=4;at++){
    let writes=0;IDBObjectStore.prototype.put=function(...args){const result=nativePut.apply(this,args);if(this.name==='pairing_material'&&++writes===at)this.transaction.abort();return result;};
    try{aborts.push(await q.rejects(()=>j.commit(h,full)));}finally{IDBObjectStore.prototype.put=nativePut;}
    if(JSON.stringify(await q.raw())!==baseline||(await j.readCommitted(q.peer)).digest!==first.digest)throw Error('Torn map after abort '+at);
   }
   const upgraded=await j.commit(h,full);if(upgraded.generation!==2||upgraded.ready)throw Error('Upgrade failed');
   const history=await Storage.getBox('blind_messages','synthetic-history-sentinel');if(history.text!=='retained history')throw Error('History modified');
   // Corrupt active ciphertext is not treated as an empty map.
   const active=await j.location('active',q.peer),original=(await q.raw()).find(row=>row.alias===active.alias);await q.rawPut({...original,blob:'AAAA'});
   const corruption=await q.rejects(()=>j.stage(bundles,q.peer),'CORRUPT_RECORD');await q.rawPut(original);
   j.close();return {aborts,corruption,generation:upgraded.generation,digest:h.digest};
  },first);
  assert(faults.aborts.length===4&&faults.aborts.every(Boolean));assert(faults.corruption);
  const isolation=await page.evaluate(async previous=>{
   const q=qa,fixture=await q.make(),j=fixture.journal,oldRows=JSON.stringify(await q.raw());
   const other=await q.make(q.third,101);if(await other.journal.readCommitted(q.peer)!==null)throw Error('Other Account inherited route');
   const otherBundles=[q.bundle(q.third,{id:111,contribution:112}),q.bundle(q.remote,{id:113,contribution:114})];const hOther=await other.journal.stage(otherBundles,q.peer);
   let accept;
   if(hOther.phase==='CONFIRM'){const c=await q.binding.prepare(otherBundles,{expectedParticipants:[q.hex(q.third.sign.publicKey),q.peer],committed:null});accept=q.binding.signReceipt(c,'ACCEPT',q.remote.sign.secretKey);}
   const otherLocalReceipt=await other.journal.reserveAndSign(hOther,accept),otherCandidate=await q.binding.prepare(otherBundles,{expectedParticipants:[q.hex(q.third.sign.publicKey),q.peer],committed:null});
   const otherReceipts=hOther.phase==='CONFIRM'?[accept,otherLocalReceipt]:[otherLocalReceipt,q.binding.signReceipt(otherCandidate,'CONFIRM',q.remote.sign.secretKey,otherLocalReceipt)];
   await other.journal.commit(hOther,otherReceipts);if((await other.journal.readCommitted(q.peer)).digest!==hOther.digest)throw Error('Other Account commit failed');other.journal.close();
   const before=JSON.stringify(await q.raw());
   // Mutating Storage.masterKey during an await cannot redirect encryption/write.
   let entered,release;const entry=new Promise(resolve=>entered=resolve),wrapped={getRandomValues:crypto.getRandomValues.bind(crypto),subtle:{importKey:crypto.subtle.importKey.bind(crypto.subtle),sign:crypto.subtle.sign.bind(crypto.subtle),decrypt:crypto.subtle.decrypt.bind(crypto.subtle),encrypt:async(...args)=>{entered();await new Promise(resolve=>release=resolve);return crypto.subtle.encrypt(...args);}}};
   const late=await q.make(),lateJournal=await DmashAccountRouteJournalV2.open({...late.options,crypto:wrapped}),fresh=[q.bundle(q.local,{generation:3,previous:previous.digest,target:q.peer,id:115,contribution:116}),q.bundle(q.remote,{generation:3,previous:previous.digest,target:q.localId,id:117,contribution:118})],h=await lateJournal.stage(fresh,q.peer);
   const pending=lateJournal.reserveAndSign(h);await entry;late.controller.abort();late.core._accountBootAttempt={};release();const switched=await q.rejects(()=>pending,'SESSION_CHANGED');
   if(JSON.stringify(await q.raw())!==before)throw Error('Late crypto wrote into replaced session');
   // Root invalidation synchronously aborts an in-flight actual IDB transaction.
   const rootFixture=await q.make(),rootHandle=await rootFixture.journal.stage(fresh,q.peer),nativePut=IDBObjectStore.prototype.put;
   IDBObjectStore.prototype.put=function(...args){const result=nativePut.apply(this,args);if(this.name==='pairing_material')rootFixture.root.lock();return result;};
   let rootAbort;try{rootAbort=await q.rejects(()=>rootFixture.journal.reserveAndSign(rootHandle));}finally{IDBObjectStore.prototype.put=nativePut;}
   if(JSON.stringify(await q.raw())!==before)throw Error('Root-lock transaction changed records');
   const wrong=await q.make(q.local,102),wrongKey=await q.rejects(()=>wrong.journal.readCommitted(q.peer),'CORRUPT_RECORD');wrong.journal.close();
   j.close();late.journal.close();return {switched,rootAbort,wrongKey,otherAccountCommitted:before!==oldRows};
  },faults);
  for(const [name,value]of Object.entries(isolation))assert.equal(value,true,name);
  // Two independent journal owners contend on the same persistent signing slot.
  const concurrent=await page.evaluate(async previous=>{
   const q=qa,a=await q.make(),b=await q.make();
   const bundles=n=>[q.bundle(q.local,{generation:3,previous:previous.digest,target:q.peer,id:n,contribution:n+1}),q.bundle(q.remote,{generation:3,previous:previous.digest,target:q.localId,id:n+2,contribution:n+3})];
   const h1=await a.journal.stage(bundles(130),q.peer),h2=await b.journal.stage(bundles(140),q.peer);
   const results=await Promise.allSettled([a.journal.reserveAndSign(h1),b.journal.reserveAndSign(h2)]);a.journal.close();b.journal.close();
   if(results.filter(r=>r.status==='fulfilled').length!==1)throw Error('Competing signatures escaped reservation');
   return {singleWinner:true,error:results.find(r=>r.status==='rejected').reason.code};
  },faults);assert(concurrent.singleWinner);
  const report={scope:'BROWSER inactive journal fixture; real IndexedDB/WebCrypto, synthetic lifecycle owners; no PWA/SW/Node activation',browser:await browser.version(),sourceHashes:Object.fromEntries([...sources].map(([name,data])=>[name,crypto.createHash('sha256').update(data).digest('hex')])),checks:{reservationRestart:committed.sameReceipt,atomicAbortEachPut:faults.aborts.length,encrypted:committed.encrypted,nodeGate:committed.inactive,...isolation,concurrent}};
  if(process.env.DMASH_QA_OUTPUT)fs.writeFileSync(process.env.DMASH_QA_OUTPUT,JSON.stringify(report,null,2)+'\n');
  console.log('PASS real Chromium IndexedDB Account journal: durable exact receipts, cross-peer offer pin, one-signature refusal, four-write atomic aborts, restart, history retention, other Account isolation, corrupt/key mismatch refusal, session/root abort and concurrent signing CAS; transport activation blocked');
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
