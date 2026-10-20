'use strict';
const assert=require('node:assert/strict'),{IDBFactory}=require('fake-indexeddb');
const {DeviceRoot,IndexedDbDeviceRootStore}=require('../js/device_root.js');
const {LocalCredentialService,CredentialWorkerKdf}=require('../js/local_credentials.js');
const calls=[];let gate=null;
// Instrumented test port, not cryptographic validation. No nonexistent enum alias.
global.argon2={ArgonType:{Argon2d:0,Argon2id:2},hash:async p=>{calls.push({...p});if(gate)await gate.promise;return {hash:new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('TEST|'+p.type+'|'+p.pass+'|'+p.salt)))};}};
global.nacl={sign:{keyPair:{fromSeed:s=>({publicKey:s.slice(),secretKey:new Uint8Array([...s,...s])})}},box:{keyPair:{fromSecretKey:s=>({publicKey:s.slice(),secretKey:s.slice()})}}};
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
const legacy=async(pass='482619',type=0)=>{const salt=new Uint8Array(16).fill(3),root=new Uint8Array(32).fill(7),iv=new Uint8Array(12).fill(4),key=await DeviceRoot._wrapKey(pass,salt,type),wrapped=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode('dmash/device-root-wrap/v1')},key,root);return {id:'root',version:1,wrap:'argon2id-aes-256-gcm-v1',wrapSalt:Buffer.from(salt).toString('base64'),iv:Buffer.from(iv).toString('base64'),wrappedRoot:Buffer.from(wrapped).toString('base64'),materials:{retained:{opaque:'ciphertext'}}};};
const conflict=fn=>assert.rejects(fn,e=>e.code==='CREDENTIAL_CONFLICT');
const stores=async record=>{DeviceRoot.lock();const factory=new IDBFactory(),a=new IndexedDbDeviceRootStore(factory),b=new IndexedDbDeviceRootStore(factory);if(record)await a.put(record);DeviceRoot.setStoreForTests(a);return {a,b};};
const memoryStorage=()=>{const values=new Map();return {values,getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,String(v)),removeItem:k=>values.delete(k)};};
const lock={request:async(_name,_options,run)=>run()};
const kdf={derive:async p=>(await global.argon2.hash(p)).hash};
(async()=>{
 for(const type of [0,2]){const record=await legacy('482619',type),{a,b}=await stores(record);calls.length=0;const h=await DeviceRoot.prepareUnlock('482619');assert.equal(DeviceRoot.state,null);assert.deepEqual(calls.map(p=>p.type),type===0?[0]:[0,2]);await DeviceRoot.commitPreparedCredentials(h,'594827',{version:1,state:'ready',legacyCleanup:'complete',wipe:null,wipeDisabledReason:'not-configured'});const next=await a.get();assert.equal(next.wrap,'argon2id-aes-256-gcm-v2');assert.equal(next.wrapKdf.type,2);assert.equal(next.version,1);assert.deepEqual(next.materials,record.materials);h.dispose();const p=await DeviceRoot.prepareUnlock('594827');await DeviceRoot.publishPrepared(p);p.dispose();assert(DeviceRoot.state.root.every(x=>x===7));await assert.rejects(DeviceRoot.prepareUnlock('482619'),e=>e.code==='UNLOCK_FAILED');a.close();b.close();}
 let {a,b}=await stores(await legacy());const before=await a.get();
 gate=deferred();const pending=DeviceRoot.prepareUnlock('482619');await new Promise(setImmediate);DeviceRoot.lock();gate.resolve();await assert.rejects(pending,e=>e.code==='DEVICE_LOCKED');gate=null;assert.equal(DeviceRoot.state,null);assert.deepEqual(await a.get(),before);
 // Two independent store instances: unrelated new biometrics survive stale
 // material writers, and a stale biometric value is not copied back wholesale.
 const base=await a.get();await b.put({...base,biometricWrap:{id:'new'}},{expected:base});await a.put({...base,materials:{...base.materials,a:{ciphertext:'A'}}},{expected:base});assert.deepEqual((await a.get()).biometricWrap,{id:'new'});
 let v=await a.get();await b.put({...v,biometricWrap:{id:'newer'}},{expected:v});await a.put({...v,materials:{...v.materials,b:{ciphertext:'B'}}},{expected:v});assert.deepEqual((await a.get()).biometricWrap,{id:'newer'});
 v=await a.get();await b.put({...v,materials:{...v.materials,same:{ciphertext:'winner'}}},{expected:v});await conflict(()=>a.put({...v,materials:{...v.materials,same:{ciphertext:'loser'}}},{expected:v}));assert.equal((await a.get()).materials.same.ciphertext,'winner');
 const proof=await a.get();await b.put({...proof,materials:{...proof.materials,during:{ciphertext:'retain'}}},{expected:proof});const committed=await a.compareAndSwap(proof,{credentialRevision:1,credentials:{version:1,state:'ready',legacyCleanup:'complete',wipe:null,wipeDisabledReason:'not-configured'}});assert.equal(committed.materials.during.ciphertext,'retain');assert.equal(committed.biometricWrap.id,'newer');await conflict(()=>a.put({...proof,materials:{...proof.materials,late:{ciphertext:'stale'}}},{expected:proof}));await conflict(()=>b.compareAndSwap(proof,{credentialRevision:1}));
 a.close();b.close();
 // Fresh setup persists ONE root pending wipe, survives restart, and rejects
 // ordinary unlock as implicit creation or nonempty-installation setup.
 ({a,b}=await stores());const storage=memoryStorage(),service=new LocalCredentialService({root:DeviceRoot,storage,kdf,inventory:async()=>true,lock});
 await assert.rejects(service.unlock('482619'),e=>e.code==='ROOT_MISSING');
 await assert.rejects(DeviceRoot.prepareSetup('482619',{assertEmpty:async()=>false}),e=>e.code==='LEGACY_MIGRATION_REQUIRED');assert.equal(await a.get(),null);
 const savedInventory=service.inventory;service.inventory=async()=>false;await assert.rejects(service.beginSetup('482619'),e=>e.code==='LEGACY_MIGRATION_REQUIRED');assert.equal(await a.get(),null);service.inventory=savedInventory;
 await service.beginSetup('482619');const setupRoot=await a.get();assert.equal(setupRoot.credentials.state,'pending-wipe');assert.equal(DeviceRoot.state,null);await service.completeSetup('482619','730158');const setupDone=await a.get();assert.equal(setupDone.wrappedRoot,setupRoot.wrappedRoot);assert.equal(setupDone.credentials.wipe.profile,'sha256-prehash-argon2id-v1');await service.unlock('482619');const id=DeviceRoot.state.identity.deviceId;DeviceRoot.lock();await service.change('482619','594827','845269');await service.unlock('594827');assert.equal(DeviceRoot.state.identity.deviceId,id);await assert.rejects(service.unlock('482619'));assert.equal(storage.getItem('sys_m'),null);assert.equal(storage.getItem('sys_w'),null);service.dispose();a.close();b.close();
 // Migration handles cleanup failure AFTER atomic root+wipe commit; retry
 // uses that same wrap and retries cleanup instead of allocating an identity.
 ({a,b}=await stores(await legacy()));const ls=memoryStorage();ls.setItem('sys_m','stale-fast-master');ls.setItem('sys_w',Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('730158'))).toString('hex'));const remove=ls.removeItem;ls.removeItem=()=>{throw Error('quota/privacy');};const migration=new LocalCredentialService({root:DeviceRoot,storage:ls,kdf,lock});await assert.rejects(migration.unlock('482619'),e=>e.code==='MIGRATION_CLEANUP_REQUIRED');const migrated=await a.get();assert.equal(migrated.credentials.legacyCleanup,'required');assert.equal(migrated.wrap,'argon2id-aes-256-gcm-v2');assert(!JSON.stringify(migrated).includes(ls.getItem('sys_w')));ls.removeItem=remove;await migration.unlock('482619');assert.equal((await a.get()).wrappedRoot,migrated.wrappedRoot);assert.equal((await a.get()).credentials.legacyCleanup,'complete');ls.setItem('sys_m','reintroduced-old-client-fast-hash');ls.setItem('sys_w','reintroduced-old-client-fast-hash');await migration.unlock('482619');assert.equal(ls.getItem('sys_m'),null);assert.equal(ls.getItem('sys_w'),null);migration.dispose();a.close();b.close();
 // A cleanup fault after a DIFFERENT master was committed is a typed
 // committed-new-master outcome, not a rollback or generic old-PIN failure.
 ({a,b}=await stores(await legacy()));const receiptStorage=memoryStorage(),receiptService=new LocalCredentialService({root:DeviceRoot,storage:receiptStorage,kdf,lock});await receiptService.unlock('482619');const retainedId=DeviceRoot.state.identity.deviceId;receiptStorage.removeItem=()=>{throw Error('synthetic cleanup error');};
 await assert.rejects(receiptService.change('482619','594827','730158'),e=>e.code==='MIGRATION_CLEANUP_REQUIRED'&&e.committed===true&&e.masterChanged===true&&e.useNewMaster===true&&Number.isSafeInteger(e.revision));DeviceRoot.lock();await assert.rejects(DeviceRoot.prepareUnlock('482619'),e=>e.code==='UNLOCK_FAILED');const newAuthority=await DeviceRoot.prepareUnlock('594827');assert.equal(newAuthority.identity.deviceId,retainedId);newAuthority.dispose();receiptService.dispose();a.close();b.close();
 // A syntactically valid but unstable KDF result must not produce a
 // canonical replacement that neither old nor new master can reopen.
 ({a,b}=await stores(await legacy()));DeviceRoot.credentialKdf=null;
 const stable=await a.get(),prepared=await DeviceRoot.prepareUnlock('482619');let unstableCalls=0;
 DeviceRoot.credentialKdf={derive:async p=>{const hash=(await global.argon2.hash(p)).hash;if(++unstableCalls===1)hash[0]^=1;return hash;}};
 await assert.rejects(DeviceRoot.commitPreparedCredentials(prepared,'594827',{version:1,state:'ready',legacyCleanup:'complete',wipe:null,wipeDisabledReason:'not-configured'}));assert.deepEqual(await a.get(),stable);prepared.dispose();DeviceRoot.credentialKdf=null;
 const reopen=await DeviceRoot.prepareUnlock('482619');reopen.dispose();a.close();b.close();
 ({a,b}=await stores());unstableCalls=0;DeviceRoot.credentialKdf={derive:async p=>{const hash=(await global.argon2.hash(p)).hash;if(++unstableCalls===1)hash[0]^=1;return hash;}};
 await assert.rejects(DeviceRoot.prepareSetup('482619',{assertEmpty:async()=>true}));assert.equal(await a.get(),null);DeviceRoot.credentialKdf=null;a.close();b.close();
 // Same-root reauthentication preserves live ownership and does not trigger
 // the service's lock cancellation listener during its own publication.
 ({a,b}=await stores(await legacy()));const reauth=new LocalCredentialService({root:DeviceRoot,storage:memoryStorage(),kdf,lock});await reauth.unlock('482619');const live=DeviceRoot.state;let locks=0;const off=DeviceRoot.onLock(()=>locks++);await reauth.unlock('482619');assert.strictEqual(DeviceRoot.state,live);assert.equal(locks,0);off();reauth.dispose();a.close();b.close();
 // Worker cancellation terminates the active expensive job and unblocks next.
 let active=0,max=0,terminated=0;class FakeWorker{constructor(){active++;max=Math.max(max,active);}postMessage(){this.timer=setTimeout(()=>this.onmessage({data:{hash:new Uint8Array(32).buffer}}),25);}terminate(){clearTimeout(this.timer);active--;terminated++;}}
 const port=new CredentialWorkerKdf({Worker:FakeWorker}),abort=new AbortController();const first=port.derive({}, {signal:abort.signal});await new Promise(setImmediate);const second=port.derive({});abort.abort();await assert.rejects(first,e=>e.code==='CREDENTIAL_CANCELLED');assert.equal((await second).length,32);assert.equal(max,1);assert.equal(terminated,2);DeviceRoot.lock();
 console.log('PASS credential legacy profiles, versioned same-root wrap, prepared cancellation, native IDB cross-store CAS/metadata races, setup restart, atomic migration/cleanup retry and worker serialization/cancel');
})().catch(e=>{console.error(e);process.exitCode=1;});
