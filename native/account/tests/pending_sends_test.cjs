'use strict';
// Real AES-GCM/IndexedDB queue transactions; established outbox is a typed fake
// here. The separate actual pairing fixture proves real outbox/network handoff.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {indexedDB}=require('fake-indexeddb');
require('../js/pending_sends.js');
const request=r=>new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
(async()=>{
 const db=await new Promise((resolve,reject)=>{const r=indexedDB.open('native-pending-real-crypto',1);r.onupgradeneeded=()=>r.result.createObjectStore('pairing_material',{keyPath:'alias'});r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
 const masterKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),salt=crypto.getRandomValues(new Uint8Array(32)),local=crypto.getRandomValues(new Uint8Array(32)),peer='b'.repeat(64),operationId='c'.repeat(64),text='private first message before the other owner is ready',binding='d'.repeat(64);let generation=1;
 let controller;const session=()=>{controller=new AbortController();return {db,masterKey,blindSalt:salt,keys:{sign:{publicKey:local}},signal:controller.signal,assertCurrent(){if(this.signal.aborted)throw Error('SESSION_CHANGED');}};};
 const snapshot=async id=>({peer:id,readiness:'NODE_PROOF_REQUIRED',digest:binding,generation}),accepted=new Map();let crash=true,calls=0,submitFailure=null;
 const submit=async(id,message)=>{calls++;if(submitFailure)throw Object.assign(Error(submitFailure),{code:submitFailure});assert.equal(id,peer);const prior=accepted.get(message.operationId);if(prior)assert.deepEqual(message,prior);else accepted.set(message.operationId,message);if(crash){crash=false;throw Object.assign(Error('CRASH_AFTER_REAL_OUTBOX_COMMIT'),{code:'TEST_CRASH'});}return {durable:true,queued:false,recipientAck:false};};
 let queue=await DmashNativePendingSends.open({session:session(),snapshot,submit});
 assert.equal((await queue.stage({peer,operationId,text})).duplicate,false);
 assert.equal((await queue.stage({peer,operationId,text})).duplicate,true);
 await assert.rejects(queue.stage({peer,operationId,text:text+' changed'}),e=>e.code==='ACCOUNT_OPERATION_CONFLICT');
 assert.equal(calls,0);assert.equal((await queue.list(peer))[0].state,'HANDSHAKE_PENDING');
 const rows=await request(db.transaction('pairing_material','readonly').objectStore('pairing_material').getAll()),raw=JSON.stringify(rows);
 for(const secret of [text,peer,operationId,binding])assert(!raw.includes(secret),'encrypted at rest');
 generation=2;await assert.rejects(queue.flush(peer),e=>e.code==='ACCOUNT_PENDING_BINDING_CHANGED');generation=1;assert.equal(calls,0);
 await assert.rejects(queue.flush(peer),e=>e.code==='TEST_CRASH');assert.equal(accepted.size,1);
 queue.close();controller.abort();queue=await DmashNativePendingSends.open({session:session(),snapshot,submit});
 assert.equal((await queue.list(peer)).length,1,'crash before handoff marker preserves first send');
 await queue.flush(peer);assert.equal(calls,2);assert.equal(accepted.size,1,'same operation handed to outbox again');assert.deepEqual(await queue.list(peer),[]);
 assert.equal((await queue.stage({peer,operationId,text})).state,'HANDED_OFF');
 await assert.rejects(queue.stage({peer,operationId,text:'conflicting duplicate'}),e=>e.code==='ACCOUNT_OPERATION_CONFLICT');
 assert(!JSON.stringify(await request(db.transaction('pairing_material','readonly').objectStore('pairing_material').getAll())).includes(text));
 // Paused/unavailable transport after Account staging is a deferred handoff,
 // not an RPC-level rejection of the already durable logical send.
 const unavailableId='e'.repeat(64);await queue.stage({peer,operationId:unavailableId,text});submitFailure='ACCOUNT_TRANSPORT_UNAVAILABLE';
 assert.deepEqual(await queue.handoff(peer),{durable:true,deferred:true,results:[]});assert.equal((await queue.list(peer))[0].operationId,unavailableId);
 queue.close();controller.abort();queue=await DmashNativePendingSends.open({session:session(),snapshot,submit});submitFailure=null;
 assert.equal((await queue.handoff(peer)).deferred,false);assert.deepEqual(await queue.list(peer),[]);assert.equal(accepted.size,2);
 const conflictId='f'.repeat(64);await queue.stage({peer,operationId:conflictId,text});submitFailure='APP_OUTBOX_CONFLICT';
 await assert.rejects(queue.handoff(peer),e=>e.code==='APP_OUTBOX_CONFLICT');assert.equal((await queue.list(peer)).length,1);
 generation=2;await assert.rejects(queue.handoff(peer),e=>e.code==='ACCOUNT_PENDING_BINDING_CHANGED');generation=1;submitFailure='ACCOUNT_PENDING_CORRUPT';
 await assert.rejects(queue.handoff(peer),e=>e.code==='ACCOUNT_PENDING_CORRUPT');
 for(const code of ['ACCOUNT_TRANSPORT_REJECTED','ACCOUNT_TRANSPORT_PEER_REJECTED','SESSION_CHANGED','APP_OPERATION_CONFLICT','BINDING_MIGRATION_REQUIRED'])assert.equal(DmashNativePendingSends.transient({code}),false);
 queue.close();controller.abort();await assert.rejects(queue.list(peer),e=>e.code==='ACCOUNT_PENDING_CLOSED');
 const wrong=session();wrong.masterKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);const denied=await DmashNativePendingSends.open({session:wrong,snapshot,submit});await assert.rejects(denied.list(peer),e=>e.code==='ACCOUNT_PENDING_CORRUPT');denied.close();controller.abort();db.close();
 console.log('PASS transient unavailable handoff accepted/deferred, hard conflicts preserved; encrypted first-send queue; pending visibility, idempotence/conflict, binding guard, crash after durable outbox handoff, reopen and closed-owner fencing');
})().catch(e=>{console.error(e);process.exitCode=1;});
