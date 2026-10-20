'use strict';
const assert=require('node:assert/strict'),{IDBFactory}=require('fake-indexeddb');
const {DurableWipeCoordinator,CredentialWipeControlStore,LocalCredentialService}=require('../js/local_credentials.js');
const lock={request:async(_n,_o,run)=>run()};
const open=(idb,name)=>new Promise((resolve,reject)=>{const r=idb.open(name,1);r.onupgradeneeded=()=>r.result.createObjectStore('rows');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
(async()=>{
 const idb=new IDBFactory(),events=[],control=new CredentialWipeControlStore(idb);
 const account=await open(idb,'dm_gamma_vault'),root=await open(idb,'dmash_device_root_v1');root.close();
 // Abort after native request success but before the INITIAL intent tx commits.
 // Neither durable intent nor deletion may survive the abort.
 const intentDb=await control.open(),originalTransaction=intentDb.transaction.bind(intentDb),abortIntent=new AbortController();let abortOnce=true,intentShutdowns=0;
 intentDb.transaction=function(...args){const tx=originalTransaction(...args);if(args[1]==='readwrite'&&abortOnce){const os=tx.objectStore.bind(tx);tx.objectStore=function(...names){const store=os(...names),put=store.put.bind(store);store.put=function(...values){const request=put(...values);request.addEventListener('success',()=>{if(abortOnce){abortOnce=false;abortIntent.abort();}});return request;};return store;};}return tx;};
 const cancelled=new DurableWipeCoordinator({indexedDb:idb,control,lock,shutdown:async()=>{intentShutdowns++;},cleanup:async()=>{}});await assert.rejects(cancelled.wipe({signal:abortIntent.signal}),e=>e.code==='CREDENTIAL_CANCELLED');assert.equal(await cancelled.pending(),null);assert.equal(intentShutdowns,0);assert((await idb.databases()).some(x=>x.name==='dm_gamma_vault'));intentDb.transaction=originalTransaction;

 // Deliberately keep another tab's connection open without versionchange close.
 const coordinator=new DurableWipeCoordinator({indexedDb:idb,control,lock,shutdown:async()=>events.push('shutdown'),cleanup:async()=>events.push('ancillary')});
 const aborted=new AbortController();aborted.abort();await assert.rejects(coordinator.wipe({signal:aborted.signal}),e=>e.code==='CREDENTIAL_CANCELLED');assert.equal(await coordinator.pending(),null);
 await assert.rejects(coordinator.wipe(),e=>e.code==='WIPE_BLOCKED');assert.equal(events.includes('ancillary'),false);assert((await idb.databases()).some(x=>x.name==='dmash_device_root_v1'),'blocked account deletion retains root');assert(await coordinator.pending());
 const restarted=new DurableWipeCoordinator({indexedDb:idb,control:new CredentialWipeControlStore(idb),lock,shutdown:async()=>events.push('shutdown-restarted'),cleanup:async()=>events.push('ancillary-restarted')});
 await assert.rejects(restarted.resume(),e=>e.code==='WIPE_AUTH_REQUIRED');assert(await restarted.pending());
 account.close();await new Promise(setImmediate);await restarted.resume({authorize:async()=>true});assert.equal(await restarted.pending(),null);assert.deepEqual((await idb.databases()).map(x=>x.name),['dmash_local_credentials_control_v1']);assert(events.includes('ancillary-restarted'));
 // Ancillary cleanup failure must not erase the last recoverable root or mark
 // success. Retry after restart resumes from persisted pending state.
 const r=await open(idb,'dmash_device_root_v1');r.close();let fail=true;
 const partial=new DurableWipeCoordinator({indexedDb:idb,control,lock,shutdown:async()=>{},cleanup:async()=>{if(fail)throw Error('synthetic OPFS failure');}});
 await assert.rejects(partial.wipe(),/OPFS failure/);assert(await partial.pending());assert((await idb.databases()).some(x=>x.name==='dmash_device_root_v1'));fail=false;await partial.resume({authorize:async()=>true});assert.equal(await partial.pending(),null);
 // No central service wrong-code or malformed-verifier path invokes deletion.
 let deletes=0;const storage={getItem:()=>null,removeItem(){}};
 const fakeRoot={validateCredentialRecord(){},onLock:()=>()=>{},_store:()=>({get:async()=>record})};
 const record={credentialRevision:1,credentials:{version:1,state:'ready',wipe:{profile:'sha256-prehash-argon2id-v1',salt:Buffer.alloc(16,3).toString('base64'),digest:Buffer.alloc(32,9).toString('base64')}}};
 const service=new LocalCredentialService({root:fakeRoot,storage,kdf:{derive:async()=>new Uint8Array(32)},lock,wipeCoordinator:{wipe:async()=>{deletes++;}}});
 await assert.rejects(service.wipe('111111'),e=>e.code==='WIPE_CODE_INVALID');assert.equal(deletes,0);record.credentials.wipe.salt='bad';await assert.rejects(service.wipe('111111'),e=>e.code==='STORAGE_CORRUPT');assert.equal(deletes,0);service.dispose();
 // At accepted durable intent, shutdown may cancel the service's signal.
 // Completion belongs to the coordinator and must not pretend rollback.
 const acceptedRoot=await open(idb,'dmash_device_root_v1');acceptedRoot.close();
 let acceptedService;const accepted=new DurableWipeCoordinator({indexedDb:idb,control,lock,shutdown:async()=>acceptedService.cancel(),cleanup:async()=>{}});
 record.credentials.wipe.salt=Buffer.alloc(16,3).toString('base64');record.credentials.wipe.digest=Buffer.alloc(32).toString('base64');
 acceptedService=new LocalCredentialService({root:fakeRoot,storage,kdf:{derive:async()=>new Uint8Array(32)},lock,wipeCoordinator:accepted});assert.deepEqual(await acceptedService.wipe('730158'),{complete:true});assert.equal(await accepted.pending(),null);acceptedService.dispose();
 const pendingService=new LocalCredentialService({root:{...fakeRoot,prepareSetup(){throw Error('must not create');}},storage,kdf:{derive:async()=>new Uint8Array(32)},lock,inventory:async()=>true,wipeCoordinator:{pending:async()=>({state:'pending'})}});await assert.rejects(pendingService.beginSetup('482619'),e=>e.code==='WIPE_PENDING');pendingService.dispose();control.close();restarted.control.close();
 console.log('PASS wipe durable intent, zero-delete cancellation/wrong code, blocked/error preservation, explicit authorized restart, ancillary failure retry and pending-wipe setup gate');
})().catch(e=>{console.error(e);process.exitCode=1;});
