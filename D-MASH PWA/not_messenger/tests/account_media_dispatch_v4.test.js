'use strict';
const assert=require('node:assert/strict'),{indexedDB}=require(process.env.DMASH_FAKE_IDB||'fake-indexeddb'),crypto=require('node:crypto').webcrypto,Dispatch=require('../js/account_media_dispatch_v4.js'),schema=require('../js/account_media_control_v4.js');
(async()=>{
 const db=await new Promise((resolve,reject)=>{const r=indexedDB.open('control-test',1);r.onupgradeneeded=()=>r.result.createObjectStore('pairing_material',{keyPath:'alias'});r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
 const abort=new AbortController(),session={db,signal:abort.signal,blindSalt:new Uint8Array(32).fill(7),masterKey:await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),assertCurrent(){if(abort.signal.aborted)throw Error('ACCOUNT_CHANGED');}};
 const core={captureAccountSessionV4:()=>session,fastHash:async b=>Buffer.from(await crypto.subtle.digest('SHA-256',b)).toString('hex')},open=()=>Dispatch.open({core,schema,clock:()=>100});
 const a=await open(),b=await open(),record={peer:'a'.repeat(64),operationId:'b'.repeat(64),bindingDigest:'c'.repeat(64),sessionId:'d'.repeat(64),generation:1,type:'ACCEPT',payload:{version:1,transferId:'e'.repeat(64),kind:'voice',expiresAt:200}};
 const results=await Promise.all([a.persist(record),b.persist(record)]);assert.equal(results.filter(r=>!r.duplicate).length,1);assert.equal((await a.pending()).length,1);
 assert((await a.persist({...record,payload:Object.fromEntries(Object.entries(record.payload).reverse())})).duplicate);
 a.close();const reopened=await open();assert.deepEqual((await reopened.pending())[0].payload,record.payload);
 await assert.rejects(()=>reopened.persist({...record,generation:2}),/CONFLICT/);
 await reopened.applied(record.peer,record.operationId);assert.equal((await reopened.pending()).length,0);assert((await b.persist(record)).duplicate);
 const rows=await new Promise(resolve=>{const r=db.transaction('pairing_material').objectStore('pairing_material').getAll();r.onsuccess=()=>resolve(r.result);});assert.equal(rows.length,1);assert(!JSON.stringify(rows).includes(record.peer));assert(!JSON.stringify(rows).includes('ACCEPT'));
 abort.abort();await assert.rejects(()=>b.persist(record),/CLOSED|CHANGED/);reopened.close();b.close();db.close();console.log('PASS durable encrypted CONTROL pending/CAS duplicate/reopen/commit-before-ACK boundary and Account abort; inactive');
})().catch(e=>{console.error(e);process.exitCode=1;});
