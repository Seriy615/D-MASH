'use strict';
const assert=require('node:assert/strict');
const Journal=require('../js/account_route_journal_v2.js');
const nacl=require('../js/vendor/nacl-fast.min.js');
(async()=>{
 const key=await crypto.subtle.importKey('raw',new Uint8Array(32).fill(4),'AES-GCM',false,['encrypt','decrypt']);
 const identity=nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(1));
 function fixture(){const controller=new AbortController(),listeners=new Set();return {storage:{db:{objectStoreNames:{contains:()=>true}},masterKey:key},core:{keys:{sign:identity},blindSalt:new Uint8Array(32).fill(5),activeIdentity:'synthetic',_accountBootAttempt:{}},deviceRoot:{state:{},onLock(fn){listeners.add(fn);return()=>listeners.delete(fn);},lock(){this.state=null;for(const fn of listeners)fn();}},accountSignal:controller.signal,controller,bindingCodec:{prepare(){throw Error('unused');}}};}
 const f=fixture(),journal=await Journal.open(f),location=await journal.location('test','record');
 const row=await journal.encrypt(location,{retained:'payload'});
 // Existing Storage ciphertext framing: base64 IV[12] + AES-GCM ciphertext/tag.
 const raw=Buffer.from(row.blob,'base64'),clear=JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.subarray(0,12)},key,raw.subarray(12))));
 assert.equal(clear.payload.retained,'payload');assert.equal(clear.alias,location.alias);
 assert.deepEqual(await journal.decrypt(location,row),{retained:'payload'});
 await assert.rejects(journal.decrypt({...location,alias:'ab'.repeat(32)},{...row,alias:'ab'.repeat(32)}),e=>e.code==='CORRUPT_RECORD');
 assert.throws(()=>journal.activate({nodeActive:true}),e=>e.code==='NODE_ACTIVATION_UNIMPLEMENTED');
 f.controller.abort();assert.throws(()=>journal.check(),e=>e.code==='SESSION_CHANGED');
 const f2=fixture(),j2=await Journal.open(f2);f2.deviceRoot.lock();assert.throws(()=>j2.check(),e=>e.code==='SESSION_CHANGED');
 for(const change of [f=>f.storage.masterKey={},f=>f.storage.db={},f=>f.core._accountBootAttempt={},f=>f.core.keys={sign:identity},f=>f.core.activeIdentity='other',f=>f.core.blindSalt=new Uint8Array(32).fill(5)]){
  const f=fixture(),j=await Journal.open(f);change(f);await assert.rejects(j.location('test','late'),e=>e.code==='SESSION_CHANGED');j.close();
 }
 // Key switch during awaited encryption must not return a blob under a new session.
 const late=fixture();let release,entered;
 const gate=new Promise(resolve=>entered=resolve),cryptoWrapper={getRandomValues:crypto.getRandomValues.bind(crypto),subtle:{importKey:crypto.subtle.importKey.bind(crypto.subtle),sign:crypto.subtle.sign.bind(crypto.subtle),encrypt:async(...args)=>{entered();await new Promise(resolve=>release=resolve);return crypto.subtle.encrypt(...args);}}};
 const j3=await Journal.open({...late,crypto:cryptoWrapper}),l3=await j3.location('test','await');const pending=j3.encrypt(l3,{secret:'old owner'});await gate;late.core._accountBootAttempt={};release();await assert.rejects(pending,e=>e.code==='SESSION_CHANGED');j3.close();
 await assert.rejects(Journal.open({...fixture(),accountSignal:null}),e=>e.code==='SESSION_REQUIRED');
 const shared=fixture(),router=Journal.createReceiptRouter(shared.deviceRoot),registered=[];
 assert.throws(()=>router.register({verifyCommitReceipt:async()=>true}),e=>e.code==='JOURNAL_BRAND');
 for(let i=0;i<32;i++){const f={...fixture(),deviceRoot:shared.deviceRoot},j=await Journal.open(f);registered.push({f,j,cap:router.register(j)});}
 const overflowFixture={...fixture(),deviceRoot:shared.deviceRoot},overflow=await Journal.open(overflowFixture);
 assert.throws(()=>router.register(overflow),e=>e.code==='JOURNAL_QUOTA');
 registered[0].j.verifyCommitReceipt=async()=>true;
 assert.equal(await router.verify({},{}),false,'instance monkeypatch cannot inject a verifier');
 assert.equal(router.register(registered[1].j),registered[1].cap,'duplicate registration stable');
 registered[0].f.controller.abort();router.register(overflow);
 assert.equal(router.unregister(registered[0].cap),false,'abort revokes registration');
 const foreign=await Journal.open(fixture());assert.throws(()=>router.register(foreign),e=>e.code==='ROOT_MISMATCH');foreign.close();
 shared.deviceRoot.lock();assert.equal(await router.verify({},{}),false);assert.throws(()=>router.register(overflow),e=>e.code==='ROOT_CHANGED');
 console.log('PASS journal captured key/session guards, existing AES-GCM framing, authenticated alias isolation, explicit inactive Node gate, bounded branded receipt router/prototype verifier/root+Account revocation');
})().catch(error=>{console.error(error);process.exitCode=1;});
