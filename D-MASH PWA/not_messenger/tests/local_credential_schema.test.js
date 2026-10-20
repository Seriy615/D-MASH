'use strict';
const assert=require('node:assert/strict'),{IDBFactory}=require('fake-indexeddb');
const {DeviceRoot,IndexedDbDeviceRootStore}=require('../js/device_root.js');
global.nacl=require('../js/vendor/nacl-fast.min.js');global.argon2={hash:async p=>({hash:new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('TEST|'+p.type+'|'+p.pass+'|'+p.salt)))})};
(async()=>{
 const store=new IndexedDbDeviceRootStore(new IDBFactory());DeviceRoot.setStoreForTests(store);const state=await DeviceRoot.unlock('482619');const good=structuredClone(state.record);DeviceRoot.lock();
 const raw=async record=>{const db=await store.open();await new Promise((resolve,reject)=>{const tx=db.transaction('device_root','readwrite');tx.oncomplete=resolve;tx.onerror=reject;tx.objectStore('device_root').put(record);});};
 const canonical={version:1,state:'ready',legacyCleanup:'complete',wipe:null,wipeDisabledReason:'not-configured'};
 const bad=[...['1',-1,NaN,Number.MAX_SAFE_INTEGER+1].map(credentialRevision=>({...good,credentialRevision})),{...good,credentialRevision:1,credentials:{...canonical,version:99}},{...good,credentialRevision:1,credentials:{...canonical,state:'unknown'}},{...good,credentialRevision:1,credentials:{...canonical,legacyCleanup:'unknown'}},{...good,credentialRevision:1,credentials:{...canonical,wipe:{profile:'unknown',salt:'bad',digest:'bad'}}},{...good,credentialRevision:1,credentials:{...canonical,extra:'unsupported'}}];
 for(const record of bad){await raw(record);await assert.rejects(DeviceRoot.prepareUnlock('482619'),e=>e.code==='STORAGE_CORRUPT');assert.equal(DeviceRoot.state,null);await assert.rejects(store.compareAndSwap(record,{credentialRevision:2,credentials:canonical}),e=>e.code==='STORAGE_CORRUPT');assert.deepEqual(await store.get(),record);}
 const exhausted={...good,credentialRevision:Number.MAX_SAFE_INTEGER,credentials:canonical};await raw(exhausted);const h=await DeviceRoot.prepareUnlock('482619');await assert.rejects(DeviceRoot.commitPreparedMetadata(h,canonical),e=>e.code==='CREDENTIAL_CONFLICT');h.dispose();assert.deepEqual(await store.get(),exhausted);DeviceRoot.lock();store.close();console.log('PASS strict legacy-absence/canonical credential schema and bounded safe revision before prepare/CAS/publication');
})().catch(e=>{console.error(e);process.exitCode=1;});
