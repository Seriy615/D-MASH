'use strict';
const assert=require('node:assert/strict'),{indexedDB}=require('fake-indexeddb');
global.nacl=require('../js/vendor/nacl-fast.min.js');
const nacl=global.nacl,discovery=require('../js/route_discovery_v4.js'),
 pairing=require('../js/account_pairing_v2.js').createCodec({nacl,discovery}),
 {createBindingCodec}=require('../js/account_route_binding_v2.js'),Journal=require('../js/account_route_journal_v2.js');
const hex=x=>Buffer.from(x).toString('hex'),seed=n=>new Uint8Array(32).fill(n);
const person=n=>({n,sign:nacl.sign.keyPair.fromSeed(seed(n)),box:nacl.box.keyPair.fromSecretKey(seed(n+1)),
 route:nacl.sign.keyPair.fromSeed(seed(n+2)),ds:nacl.sign.keyPair.fromSeed(seed(n+3)),
 db:nacl.box.keyPair.fromSecretKey(seed(n+4)),recipient:nacl.box.keyPair.fromSecretKey(seed(n+5))});
(async()=>{
 let now=1800000000,verifies=0,decrypts=0,gate=null;
 const people=[person(1),person(11)].sort((a,b)=>hex(a.sign.publicKey)<hex(b.sign.publicKey)?-1:1),local=people[0],peer=hex(people[1].sign.publicKey);
 const bundles=people.map(p=>pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,
  pairing_id:hex(seed(p.n+30)),generation:1,issued_at:now,expires_at:now+600,previous_binding:null,
  intended_peer:null,contribution:hex(seed(p.n+60)),account_keys:{signing:hex(p.sign.publicKey),box:hex(p.box.publicKey),
   kem_profile:'LEGACY_KYBER768_BUNDLE_V1',kem_public:Buffer.alloc(1184,p.n).toString('base64url')},
  inbound_certificate:discovery.issueCertificate(p.route,p.ds.publicKey,p.db.publicKey,p.recipient.publicKey,
   {generation:1,issuedAt:now,expiresAt:now+900})},p.sign.secretKey,{now}).serialized);
 const actual=createBindingCodec({nacl,discovery,pairing,clock:()=>now}),codec={...actual,
  async verifyCommitted(...args){verifies++;if(gate)await gate;return actual.verifyCommitted(...args);}};
 const db=await new Promise(resolve=>{const r=indexedDB.open('journal-validation-reuse',1);r.onupgradeneeded=()=>r.result.createObjectStore('pairing_material',{keyPath:'alias'});r.onsuccess=()=>resolve(r.result);});
 const dataKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),controller=new AbortController(),listeners=new Set(),
  storage={db,masterKey:dataKey},core={keys:{sign:local.sign},blindSalt:seed(91),activeIdentity:'synthetic',_accountBootAttempt:{}},
  root={state:{},onLock(fn){listeners.add(fn);return()=>listeners.delete(fn);}},
  cryptoWrapper={getRandomValues:crypto.getRandomValues.bind(crypto),subtle:{
   importKey:crypto.subtle.importKey.bind(crypto.subtle),sign:crypto.subtle.sign.bind(crypto.subtle),encrypt:crypto.subtle.encrypt.bind(crypto.subtle),
   decrypt(...args){decrypts++;return crypto.subtle.decrypt(...args);}}},
  options={storage,core,deviceRoot:root,accountSignal:controller.signal,bindingCodec:codec,crypto:cryptoWrapper,clock:()=>now};
 let journal=await Journal.open(options);
 const stage=await journal.stage(bundles,peer),candidate=await actual.prepare(bundles,{expectedParticipants:people.map(p=>hex(p.sign.publicKey)),committed:null}),
  accept=actual.signReceipt(candidate,'ACCEPT',local.sign.secretKey),confirm=actual.signReceipt(candidate,'CONFIRM',people[1].sign.secretKey,accept);
 await journal.reserveAndSign(stage);await journal.commit(stage,[accept,confirm]);
 const nativePut=async row=>new Promise((resolve,reject)=>{const tx=db.transaction('pairing_material','readwrite');tx.objectStore('pairing_material').put(row);tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);}),
  raw=async alias=>new Promise(resolve=>{const r=db.transaction('pairing_material').objectStore('pairing_material').get(alias);r.onsuccess=()=>resolve(r.result);});
 const first=await journal.readRouteSnapshot(peer),afterFirst=decrypts;
 assert.equal(first.readiness,'NODE_PROOF_REQUIRED');
 const repeated=await journal.readRouteSnapshot(peer);await journal.readRouteSnapshot(peer);
 assert.equal(verifies,1,'unchanged authenticated dependency bytes must not repeat full signature validation');
 assert(decrypts>=afterFirst+10,'every cache hit must still authenticate fresh coherent DB rows');
 assert(Object.isFrozen(first)&&Object.isFrozen(repeated.localCertificate));
 assert.throws(()=>{repeated.localCertificate.route_id='0'.repeat(64);},TypeError);
 const coherent=await journal.readCoherent(peer),active=await journal.location('active',peer),
  journalLocation={kind:'journal',alias:coherent.pointer.journal},journalRow=await raw(journalLocation.alias),
  activeRow=await raw(active.alias);
 // Re-encryption changes exact authenticated dependencies even with equal plaintext.
 await nativePut(await journal.encrypt(journalLocation,coherent.journal));
 const beforeReencrypt=verifies;await journal.readRouteSnapshot(peer);assert.equal(verifies,beforeReencrypt+1);
 // Same-alias, valid AES-GCM with an invalid signed receipt must never hit cache.
 const corrupted=structuredClone(coherent.journal),receipt=JSON.parse(corrupted.receipts[0]);receipt.signature='00'.repeat(64);corrupted.receipts[0]=JSON.stringify(receipt);
 await nativePut(await journal.encrypt(journalLocation,corrupted));
 await assert.rejects(()=>journal.readRouteSnapshot(peer));
 await nativePut(journalRow);const beforeRestored=verifies;await journal.readRouteSnapshot(peer);assert.equal(verifies,beforeRestored+1,'restore after observed tamper must revalidate');
 // Corrupt ciphertext and coherent-pointer changes invalidate previously verified bytes.
 for(const changed of [{...journalRow,blob:'AAAA'},await journal.encrypt(active,{...coherent.pointer,state:'WRONG_OWNER'})]) {
  await nativePut(changed);await assert.rejects(()=>journal.readRouteSnapshot(peer));
  await nativePut(journalRow);await nativePut(activeRow);const before=verifies;await journal.readRouteSnapshot(peer);assert.equal(verifies,before+1);
 }
 // Stale Account/root observations cannot leave a usable validation cache behind.
 for(const field of ['account','root']) {
  const old=field==='account'?core.activeIdentity:root.state;
  if(field==='account')core.activeIdentity='different';else root.state={};
  await assert.rejects(()=>journal.readRouteSnapshot(peer),e=>e.code==='SESSION_CHANGED');
  if(field==='account')core.activeIdentity=old;else root.state=old;
  const before=verifies;await journal.readRouteSnapshot(peer);assert.equal(verifies,before+1);
 }
 now+=100;await journal.readRouteSnapshot(peer);now--;const beforeRollback=verifies;
 await journal.readRouteSnapshot(peer);assert.equal(verifies,beforeRollback+1,'backward clock invalidates validation reuse');
 now=1800000601;const beforeOfferExpiry=verifies;await journal.readRouteSnapshot(peer);await journal.readRouteSnapshot(peer);
 assert.equal(verifies,beforeOfferExpiry+2,'expired signed binding is never cached');
 now=1800000900;assert.equal((await journal.readRouteSnapshot(peer)).readiness,'ROUTE_EXPIRED');
 // Fresh journal/reload never inherits a prior instance's verification decision.
 now=1800000100;journal.close();journal=await Journal.open(options);const beforeReopen=verifies;
 await journal.readRouteSnapshot(peer);assert.equal(verifies,beforeReopen+1);
 // Row mutation while a cache miss verifies must fail the post-await CAS barrier.
 await nativePut(await journal.encrypt(journalLocation,coherent.journal));
 let release;gate=new Promise(resolve=>{release=resolve;});const beforeInterleave=verifies;
 const pending=journal.readRouteSnapshot(peer);while(verifies===beforeInterleave)await new Promise(resolve=>setImmediate(resolve));
 await nativePut(journalRow);gate=null;release();await assert.rejects(pending,e=>e.code==='CAS_CONFLICT');
 const beforeLast=verifies;await journal.readRouteSnapshot(peer);assert.equal(verifies,beforeLast+1);
 controller.abort();await assert.rejects(()=>journal.readRouteSnapshot(peer),e=>e.code==='SESSION_CHANGED');db.close();
 console.log('PASS real signed pairing/receipts + AES-GCM synthetic IDB: validation reuse, fresh decrypt/coherence, ciphertext/tamper/owner/clock/expiry/reload invalidation and interleaved-write CAS; no browser/UI claim');
})().catch(error=>{console.error(error);process.exitCode=1;});
