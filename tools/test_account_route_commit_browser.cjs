'use strict';
// Real local Node/Account journals, synthetic keys/profile. No ordinary UI or mesh claim.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const scripts=['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','vendor/argon2-bundled.min.js','device_root.js','node_runtime_host_v4.js','route_discovery_v4.js','account_pairing_v2.js','account_route_binding_v2.js','account_route_journal_v2.js','storage.js','node_runtime_coordinator_v4.js'];
const names=[...new Set([...scripts,'node_runtime_worker_v4.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js','resource_pow.js','node_socket_v4.js','node_channel_v4.js','probe_primitives_v4.js','recipient_payload_v4.js','node_routing_v4.js','node_inbox_v4.js','node_local_delivery_v4.js','node_local_ownership_v4.js','vendor/argon2.wasm'])];
const sources=new Map(names.map(name=>['/js/'+name,fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js',name))]));
(async()=>{
 const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(scripts.map(name=>'<script src="/js/'+name+'"></script>').join(''));}else if(sources.has(req.url)){res.setHeader('Content-Type',req.url.endsWith('.wasm')?'application/wasm':'application/javascript');res.end(sources.get(req.url));}else{res.statusCode=404;res.end();}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME,headless:true});const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  const result=await page.evaluate(async()=>{
   const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''),seed=n=>new Uint8Array(32).fill(n),rejects=async fn=>{try{await fn();return false;}catch{return true;}};
   const vacant=async()=>{const until=Date.now()+10000;while((await navigator.locks.query()).held.some(lock=>lock.name==='dmash-node-runtime-v4')){if(Date.now()>until)throw Error('Worker ownership not released');await new Promise(resolve=>setTimeout(resolve,25));}};
   const person=n=>({n,sign:nacl.sign.keyPair.fromSeed(seed(n)),box:nacl.box.keyPair.fromSecretKey(seed(n+1)),route:nacl.sign.keyPair.fromSeed(seed(n+2)),ds:nacl.sign.keyPair.fromSeed(seed(n+3)),db:nacl.box.keyPair.fromSecretKey(seed(n+4)),recipient:nacl.box.keyPair.fromSecretKey(seed(n+5))});
   const [local,remote]=[person(1),person(11)].sort((a,b)=>hex(a.sign.publicKey)<hex(b.sign.publicKey)?-1:1),localId=hex(local.sign.publicKey),peer=hex(remote.sign.publicKey),now=Math.floor(Date.now()/1000);
   const pairing=DmashAccountPairingV2.createCodec({nacl,discovery:DmashRouteDiscoveryV4}),binding=DmashAccountRouteBindingV2.createBindingCodec({nacl,discovery:DmashRouteDiscoveryV4,pairing});
   const bundle=(p,target=p===local?null:localId,offset=0)=>pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(seed(p.n+30+offset)),generation:1,issued_at:now,expires_at:now+3600,previous_binding:null,intended_peer:target,contribution:hex(seed(p.n+60+offset)),account_keys:{signing:hex(p.sign.publicKey),box:hex(p.box.publicKey),kem_profile:'LEGACY_KYBER768_BUNDLE_V1',kem_public:btoa(String.fromCharCode(...new Uint8Array(1184).fill(p.n))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')},inbound_certificate:DmashRouteDiscoveryV4.issueCertificate(p.route,p.ds.publicKey,p.db.publicKey,p.recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+7200})},p.sign.secretKey,{now,localAccount:target??undefined}).serialized;
   const bundles=[bundle(local),bundle(remote)],certificate=JSON.parse(bundles[0]).inbound_certificate,migrationId=hex(seed(90));
   await DeviceRoot.unlock('Account-Node-proof-fixture-only');await Storage.initGamma(seed(100));
   const coordinator=new DmashNodeRuntimeCoordinatorV4(DeviceRoot,{localOwnership:'managed'});let host=await coordinator.start();const firstHost=host,nodeId=host.identity.nodeId;
   let controller=new AbortController(),core={keys:{sign:local.sign},blindSalt:seed(120),activeIdentity:'synthetic-local',_accountBootAttempt:{},_accountTransitioning:false};
   const register=async()=>{const generation=core._accountBootAttempt,c=await host.challengeLocalOwner(localId,certificate);return host.registerLocalOwner(c.challenge,nacl.sign.detached(new TextEncoder().encode(c.transcript),local.sign.secretKey),{accountPublic:localId,isAccountCurrent:()=>core._accountBootAttempt===generation&&!core._accountTransitioning,signal:controller.signal});};
   let owner=await register(),journal=await DmashAccountRouteJournalV2.open({storage:Storage,core,deviceRoot:DeviceRoot,accountSignal:controller.signal,bindingCodec:binding,verifyPreparation:host.verifyPreparation.bind(host)});
   coordinator.registerAccountJournal(journal);
   const verifierFixed=await rejects(()=>host.setCommitReceiptVerifier(async()=>true));
   const stage=await journal.stage(bundles,peer),accept=await journal.reserveAndSign(stage),candidate=await binding.prepare(bundles,{expectedParticipants:[localId,peer],committed:null}),confirm=binding.signReceipt(candidate,'CONFIRM',remote.sign.secretKey,accept),receipts=[accept,confirm];
   const material={migrationId,bindingDigest:stage.digest,expectedGeneration:1,certificate,discoverySeed:local.ds.secretKey.slice(0,32),discoveryBox:local.db.secretKey.slice(),recipientKeys:[local.recipient.secretKey.slice()]};
   const preparation=await host.prepareLocalBinding(owner,material),tuple=await host.verifyPreparation(preparation),notAdvertised=(await host.stats()).owned===0;
   const wrongProof=await rejects(()=>journal.commit(stage,receipts,{preparation:{}})),fakeReceipt=await rejects(()=>host.activateLocalBinding(owner,preparation,{digest:stage.digest}));
   const oneReceipt=await rejects(()=>journal.commit(stage,[accept],{preparation}));
   const nativePut=IDBObjectStore.prototype.put;let put=0;IDBObjectStore.prototype.put=function(...args){const result=nativePut.apply(this,args);if(this.name==='pairing_material'&&++put===4)this.transaction.abort();return result;};
   let aborted;try{aborted=await rejects(()=>journal.commit(stage,receipts,{preparation}));}finally{IDBObjectStore.prototype.put=nativePut;}
   const noTornCommit=await journal.readCommitted(peer)===null&&(await host.stats()).owned===0;
   const committed=await journal.commit(stage,receipts,{preparation}),privateReceipt=committed.commitReceipt,receiptValid=await journal.verifyCommitReceipt(privateReceipt,tuple),cloneDenied=!await journal.verifyCommitReceipt(structuredClone(privateReceipt),tuple),wrongTuple=!await journal.verifyCommitReceipt(privateReceipt,{...tuple,migrationId:hex(seed(91))});
   const active=await host.activateLocalBinding(owner,preparation,privateReceipt),activated=active.state==='ACTIVE'&&(await host.stats()).owned===1;
   const activeReceipt=await journal.verifyCommitReceipt(privateReceipt,await host.verifyPreparation(preparation));
   // Durable pointer must be read for every activation, not just the in-memory brand.
   const activeLocation=await journal.location('active',peer);
   const readRaw=()=>new Promise(resolve=>{const r=Storage.db.transaction('pairing_material','readonly').objectStore('pairing_material').get(activeLocation.alias);r.onsuccess=()=>resolve(r.result);});
   const writeRaw=value=>new Promise((resolve,reject)=>{const tx=Storage.db.transaction('pairing_material','readwrite');tx.objectStore('pairing_material').put(value);tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);});
   const saved=await readRaw();await writeRaw({...saved,blob:'AAAA'});const durableGuard=!await journal.verifyCommitReceipt(privateReceipt,tuple);await writeRaw(saved);
   const replay=await journal.commit(stage,receipts,{preparation}),reminted=replay.replayed&&await journal.verifyCommitReceipt(replay.commitReceipt,tuple);
   controller.abort();core._accountBootAttempt={};const accountDenied=!await journal.verifyCommitReceipt(privateReceipt,tuple),nodeSurvives=(await host.stats()).worker===true&&(await host.stats()).owned===1;
   // A -> B -> A on the SAME managed Host: fixed verifier routes real journal brands.
   const foreignJournalDenied=await rejects(()=>coordinator.registerAccountJournal({verifyCommitReceipt:async()=>true}));
   const b=person(21),bid=hex(b.sign.publicKey),bController=new AbortController(),bCore={keys:{sign:b.sign},blindSalt:seed(121),activeIdentity:'synthetic-B',_accountBootAttempt:{},_accountTransitioning:false};
   const bStorage={db:Storage.db,masterKey:await crypto.subtle.importKey('raw',seed(101),'AES-GCM',false,['encrypt','decrypt'])},bBundles=[bundle(b,null),bundle(remote,bid,100)],bCertificate=JSON.parse(bBundles[0]).inbound_certificate;
   const bChallenge=await host.challengeLocalOwner(bid,bCertificate),bOwner=await host.registerLocalOwner(bChallenge.challenge,nacl.sign.detached(new TextEncoder().encode(bChallenge.transcript),b.sign.secretKey),{accountPublic:bid,isAccountCurrent:()=>!bCore._accountTransitioning,signal:bController.signal});
   const bJournal=await DmashAccountRouteJournalV2.open({storage:bStorage,core:bCore,deviceRoot:DeviceRoot,accountSignal:bController.signal,bindingCodec:binding,verifyPreparation:host.verifyPreparation.bind(host)});coordinator.registerAccountJournal(bJournal);
   const bStage=await bJournal.stage(bBundles,peer),bCandidate=await binding.prepare(bBundles,{expectedParticipants:[bid,peer],committed:null});
   const bAccept=bStage.phase==='CONFIRM'?binding.signReceipt(bCandidate,'ACCEPT',remote.sign.secretKey):undefined,bLocalReceipt=await bJournal.reserveAndSign(bStage,bAccept),bReceipts=bStage.phase==='CONFIRM'?[bAccept,bLocalReceipt]:[bLocalReceipt,binding.signReceipt(bCandidate,'CONFIRM',remote.sign.secretKey,bLocalReceipt)];
   const bPreparation=await host.prepareLocalBinding(bOwner,{migrationId:hex(seed(92)),bindingDigest:bStage.digest,expectedGeneration:1,certificate:bCertificate,discoverySeed:b.ds.secretKey.slice(0,32),discoveryBox:b.db.secretKey.slice(),recipientKeys:[b.recipient.secretKey.slice()]});
   const bCommit=await bJournal.commit(bStage,bReceipts,{preparation:bPreparation});
   bJournal.verifyCommitReceipt=async()=>false; // Instance override is ignored by trusted router.
   await host.activateLocalBinding(bOwner,bPreparation,bCommit.commitReceipt);delete bJournal.verifyCommitReceipt;
   const prototypeVerifier=(await host.stats()).owned===2,secondAccount=(await bJournal.readCommitted(peer)).digest===bStage.digest;
   const staleAfterSwitch=await rejects(()=>host.activateLocalBinding(owner,preparation,privateReceipt));
   bController.abort();bCore._accountBootAttempt={};
   controller=new AbortController();core={keys:{sign:local.sign},blindSalt:seed(120),activeIdentity:'synthetic-local',_accountBootAttempt:{},_accountTransitioning:false};owner=await register();
   const back=await host.queryLocalBinding(owner,migrationId);journal=await DmashAccountRouteJournalV2.open({storage:Storage,core,deviceRoot:DeviceRoot,accountSignal:controller.signal,bindingCodec:binding,verifyPreparation:host.verifyPreparation.bind(host)});coordinator.registerAccountJournal(journal);
   const backStage=await journal.stage(bundles,peer),backCommit=await journal.commit(backStage,receipts,{preparation:back.handle});await host.activateLocalBinding(owner,back.handle,backCommit.commitReceipt);
   const sameHostSwitch=host===firstHost&&await coordinator.start()===host&&host.identity.nodeId===nodeId&&(await host.stats()).owned===2;
   const oldReceiptDenied=await rejects(()=>host.activateLocalBinding(owner,back.handle,privateReceipt));
   DeviceRoot.lock();await vacant();await DeviceRoot.unlock('Account-Node-proof-fixture-only');
   host=await coordinator.start();const rootRestored=host.identity.nodeId===nodeId&&(await host.stats()).owned===2;
   controller=new AbortController();core={keys:{sign:local.sign},blindSalt:seed(120),activeIdentity:'synthetic-local',_accountBootAttempt:{},_accountTransitioning:false};owner=await register();
   const restored=await host.queryLocalBinding(owner,migrationId);journal=await DmashAccountRouteJournalV2.open({storage:Storage,core,deviceRoot:DeviceRoot,accountSignal:controller.signal,bindingCodec:binding,verifyPreparation:host.verifyPreparation.bind(host)});coordinator.registerAccountJournal(journal);
   const restoredStage=await journal.stage(bundles,peer),restoredCommit=await journal.commit(restoredStage,receipts,{preparation:restored.handle}),restoredReceipt=await journal.verifyCommitReceipt(restoredCommit.commitReceipt,await host.verifyPreparation(restored.handle));
   await host.retireLocalBinding(owner,restored.handle,1,stage.digest);const retired=!await journal.verifyCommitReceipt(restoredCommit.commitReceipt,tuple)&&(await host.stats()).owned===1;
   DeviceRoot.lock();await vacant();coordinator.close();return {verifierFixed,notAdvertised,wrongProof,fakeReceipt,oneReceipt,aborted,noTornCommit,receiptValid,cloneDenied,wrongTuple,activated,activeReceipt,durableGuard,reminted,accountDenied,nodeSurvives,rootRestored,restoredReceipt,retired,foreignJournalDenied,prototypeVerifier,secondAccount,staleAfterSwitch,sameHostSwitch,oldReceiptDenied};
  });
  for(const [name,value]of Object.entries(result))assert.equal(value,true,name);
  const report={scope:'BROWSER real DeviceRoot/Worker and Account IndexedDB proof-gated local activation; synthetic profile; no ordinary UI or real mesh acceptance',browser:await browser.version(),sourceHashes:Object.fromEntries([...sources].map(([name,data])=>[name,crypto.createHash('sha256').update(data).digest('hex')])),checks:result};
  if(process.env.DMASH_QA_OUTPUT)fs.writeFileSync(process.env.DMASH_QA_OUTPUT,JSON.stringify(report,null,2)+'\n');
  console.log('PASS real Worker+Account journals: actual PREPARED, four-row commit, private receipt required for ACTIVE, cloned/digest/tuple/durable-tamper/retired proof refused, same-Host A→B→A with fixed branded verifier, Account logout preserves Node, root restore preserves identity and both ACTIVE mappings');
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
