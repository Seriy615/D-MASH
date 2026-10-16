'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {IDBFactory}=require('fake-indexeddb'),{DeviceRoot}=require('../js/device_root.js');
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const deadline=async promise=>{let timer;try{return await Promise.race([promise,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('independent operation blocked behind creator')),5000))]);}finally{clearTimeout(timer);}};
function setup(){DeviceRoot.lock();const store={record:{id:'root',version:1,materials:{},wrappedRoot:'preserved-wrap'},writes:0,async get(){return structuredClone(this.record);},async put(record){this.writes++;this.record=structuredClone(record);}};DeviceRoot.setStoreForTests(store);DeviceRoot.state={root:crypto.getRandomValues(new Uint8Array(32)),record:structuredClone(store.record)};return store;}
function v52(){const storage={getAllRegistryAccounts:async()=>[]},ctx={Storage:storage,DeviceRoot,crypto,Uint8Array,TextEncoder,TextDecoder,btoa,atob,console,indexedDB:new IDBFactory(),setInterval:()=>0,setTimeout:()=>0,clearInterval:()=>{}};ctx.window=ctx;vm.createContext(ctx);vm.runInContext(fs.readFileSync(require.resolve('../js/acceptance_v52.js'),'utf8'),ctx);assert.equal(storage.getAllRegistryAccounts.name,'encryptedRegistryListV52');return storage;}
(async()=>{
 let store=setup();await DeviceRoot.deviceMaterial('existing',()=>new Uint8Array([4,5]));
 const entered=deferred(),release=deferred(),created=new Uint8Array([1,2,3]);let creates=0;
 const node=DeviceRoot.deviceMaterial('node-ed25519-pow-v4',async()=>{creates++;entered.resolve();await release.promise;return created;});await entered.promise;
 const storage=v52();
 try{
  // Actual V52, native AES/HKDF and IndexedDB; only PoW creator is deferred.
  assert.deepEqual(await deadline(storage.getAllRegistryAccounts()),[]);
  assert.deepEqual(await deadline(DeviceRoot.deviceMaterial('existing',()=>{throw Error('must retain existing material');})),new Uint8Array([4,5]));
  assert(!Object.hasOwn(store.record.materials,'node-ed25519-pow-v4'));
  assert(Object.hasOwn(store.record.materials,'account-registry-v1'));
 }finally{release.resolve();await node;}
 const same=await DeviceRoot.deviceMaterial('node-ed25519-pow-v4',()=>{throw Error('must retain Node identity');});assert.deepEqual(same,new Uint8Array([1,2,3]));assert.equal(creates,1);assert.equal(store.record.wrappedRoot,'preserved-wrap');
 // Same-name creation is deduplicated, but callers own independent plaintext.
 store=setup();const gate=deferred(),started=deferred(),bytes=new Uint8Array([7,8]);creates=0;
 const a=DeviceRoot.deviceMaterial('same',async()=>{creates++;started.resolve();await gate.promise;return bytes;});await started.promise;
 const b=DeviceRoot.deviceMaterial('same',()=>{creates++;return new Uint8Array([9]);});gate.resolve();const [x,y]=await Promise.all([a,b]);assert.equal(creates,1);assert.notStrictEqual(x,y);x.fill(0);assert.deepEqual(y,new Uint8Array([7,8]));assert.deepEqual(bytes,new Uint8Array([0,0]),'creator plaintext must be wiped after encryption');
 // Concurrent whole-record commits retain all names, including after reload.
 await Promise.all(Array.from({length:12},(_,i)=>DeviceRoot.deviceMaterial('n'+i,()=>new Uint8Array([i]))));assert.equal(Object.keys(store.record.materials).length,13);
 const root=DeviceRoot.state.root.slice();DeviceRoot.lock();DeviceRoot.state={root,record:structuredClone(store.record)};assert.deepEqual(await DeviceRoot.deviceMaterial('same',()=>{throw Error('reload must not replace');}),new Uint8Array([7,8]));
 // Invalid existing entries fail closed rather than becoming new identities.
 for(const broken of [null,{iv:'bad',ciphertext:'bad'}]){DeviceRoot.state.record.materials.corrupt=broken;let called=false;await assert.rejects(DeviceRoot.deviceMaterial('corrupt',()=>{called=true;return new Uint8Array([1]);}),e=>e.code==='STORAGE_CORRUPT');assert.equal(called,false);}
 // Rejected creator permits retry and never poisons unrelated writes.
 await assert.rejects(DeviceRoot.deviceMaterial('retry',()=>{throw Error('creator failed');}),/creator failed/);assert.deepEqual(await DeviceRoot.deviceMaterial('retry',()=>new Uint8Array([6])),new Uint8Array([6]));
 // A late creator cannot write/return bytes into a changed root or store.
 for(const replaceStore of [false,true]){store=setup();const start=deferred(),end=deferred(),stale=new Uint8Array([8,9]);const old=DeviceRoot.deviceMaterial('late',async()=>{start.resolve();await end.promise;return stale;});const rejected=assert.rejects(old,e=>e.code==='DEVICE_LOCKED');await start.promise;const before=store.writes;if(replaceStore)DeviceRoot.setStoreForTests({async put(){throw Error('stale new-store write');}});else DeviceRoot.lock();end.resolve();await rejected;assert.deepEqual(stale,new Uint8Array([0,0]));assert.equal(store.writes,before);}
 // Master rewrap must merge the latest material record, without waiting for
 // unrelated creation or letting that creation restore the old wrapping key.
 store=setup();Object.assign(store.record,{iv:'old-iv',wrapSalt:'old-salt'});DeviceRoot.state.record=structuredClone(store.record);
 const decrypt=DeviceRoot._decryptRoot,encrypt=DeviceRoot._encryptRoot,wrapping=deferred(),wrapEntered=deferred();
 DeviceRoot._decryptRoot=async()=>DeviceRoot.state.root.slice();DeviceRoot._encryptRoot=async()=>{wrapEntered.resolve();await wrapping.promise;return {iv:'new-iv',wrappedRoot:'new-wrap'};};
 try{const wrap=DeviceRoot.rewrapMasterPin('old','new');await wrapEntered.promise;await deadline(DeviceRoot.deviceMaterial('during-wrap',()=>new Uint8Array([3])));wrapping.resolve();await wrap;assert(Object.hasOwn(store.record.materials,'during-wrap'));assert.equal(store.record.wrappedRoot,'new-wrap');assert.equal(DeviceRoot.state.record.wrappedRoot,'new-wrap');}finally{wrapping.resolve();DeviceRoot._decryptRoot=decrypt;DeviceRoot._encryptRoot=encrypt;}
 DeviceRoot.lock();console.log('PASS DeviceRoot/V52 independent progress, independent copies, retained ciphertext/root, serialized commits, fail-closed corruption, retry, stale-session cleanup and concurrent master rewrap');
})().catch(e=>{console.error(e);process.exitCode=1;});
