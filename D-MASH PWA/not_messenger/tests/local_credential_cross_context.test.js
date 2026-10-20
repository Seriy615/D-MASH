'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),{IDBFactory}=require('fake-indexeddb');
const {LocalCredentialService,DurableWipeCoordinator,CredentialWipeControlStore}=require('../js/local_credentials.js');
const indexedDB=new IDBFactory(),nacl=require('../js/vendor/nacl-fast.min.js');
const makeRoot=()=>{const c={crypto,indexedDB,nacl,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,DataView,AbortController,btoa,atob,console,structuredClone};c.window=c;vm.createContext(c);vm.runInContext(fs.readFileSync(require.resolve('../js/device_root.js'),'utf8'),c);return c.DeviceRoot;};
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
const tails=new Map();let lockStarts=0;
const lock={request:(name,options,run)=>{const next=(tails.get(name)||Promise.resolve()).then(()=>{if(options.signal?.aborted)throw Object.assign(Error('cancelled'),{code:'CREDENTIAL_CANCELLED'});lockStarts++;return run();});tails.set(name,next.catch(()=>{}));return next;}};
const listeners=new Set(),lifecycle={subscribe:f=>{listeners.add(f);return()=>listeners.delete(f);},invalidate:()=>{for(const f of listeners)f();},close(){}};
const storage={getItem:()=>null,removeItem(){}},digest=async p=>new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('TEST|'+p.type+'|'+p.pass+'|'+p.salt)));
(async()=>{
 const rootA=makeRoot(),rootB=makeRoot(),entered=deferred(),release=deferred();let first=true;
 const kdfA={derive:async p=>{if(first){first=false;entered.resolve();await release.promise;}return digest(p);}},kdfB={derive:digest};
 const control=new CredentialWipeControlStore(indexedDB),coordinator=new DurableWipeCoordinator({indexedDb:indexedDB,control,lock,lifecycle,shutdown:async()=>{rootB.lock();rootB._store().close();},cleanup:async()=>{}});
 const a=new LocalCredentialService({root:rootA,storage,kdf:kdfA,lock,lifecycle,inventory:async()=>true,wipeCoordinator:coordinator});
 const b=new LocalCredentialService({root:rootB,storage,kdf:kdfB,lock,lifecycle,inventory:async()=>true,wipeCoordinator:coordinator});
 // Independent VM roots, independent IDB connections, one real lock contract.
 const setup=a.beginSetup('482619');await entered.promise;const wipe=coordinator.wipe();await new Promise(setImmediate);assert.equal(await coordinator.pending(),null,'other-context wipe cannot accept intent while setup owns shared lock');assert.equal(lockStarts,1);
 release.resolve();await setup;await wipe;assert.equal(rootA.state,null);assert.equal(rootB.state,null);assert.deepEqual((await indexedDB.databases()).map(x=>x.name),['dmash_local_credentials_control_v1']);
 await assert.rejects(rootA.unlock('482619'),e=>e.code==='ROOT_STORE_INVALIDATED','old context may not reopen deleted root DB');await assert.rejects(b.unlock('482619'),e=>e.code==='ROOT_STORE_INVALIDATED'||e.code==='ROOT_MISSING');assert.equal((await indexedDB.databases()).some(x=>x.name==='dmash_device_root_v1'),false);
 // Deleting root in another context also invalidates an idle unlocked owner,
 // even if a lifecycle broadcast was missed. Its old store stays fenced.
 const rootC=makeRoot(),c=new LocalCredentialService({root:rootC,storage,kdf:kdfB,lock,lifecycle,inventory:async()=>true});await c.beginSetup('482619');await c.completeSetup('482619','730158');await c.unlock('482619');assert(rootC.state.root);
 await new Promise((resolve,reject)=>{const request=indexedDB.deleteDatabase('dmash_device_root_v1');request.onsuccess=resolve;request.onerror=reject;});assert.equal(rootC.state,null);await assert.rejects(rootC.unlock('482619'),e=>e.code==='ROOT_STORE_INVALIDATED');assert.equal((await indexedDB.databases()).some(x=>x.name==='dmash_device_root_v1'),false);
 a.dispose();b.dispose();c.dispose();control.close();console.log('PASS independent Root/service shared-lock setup-vs-wipe serialization, lifecycle fencing, versionchange invalidation and no old-context root recreation');
})().catch(e=>{console.error(e);process.exitCode=1;});
