'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {IDBFactory}=require('fake-indexeddb');
const context={WebAssembly,TextEncoder,TextDecoder,Uint8Array,Int8Array,Uint16Array,Int16Array,Uint32Array,Int32Array,Float32Array,Float64Array,ArrayBuffer,Promise,Math,Date,console,atob,btoa,setTimeout,clearTimeout};context.window=context;context.self=context;vm.createContext(context);
vm.runInContext(fs.readFileSync(require.resolve('../js/vendor/argon2-bundled.min.js'),'utf8'),context);
global.argon2=context.argon2;global.nacl=require('../js/vendor/nacl-fast.min.js');
const {DeviceRoot,IndexedDbDeviceRootStore}=require('../js/device_root.js');
const pass='synthetic-only-master',salt=new Uint8Array(16).fill(3),root=new Uint8Array(32).fill(7),iv=new Uint8Array(12).fill(4);
// Frozen vectors generated from the actual deployed bundled WASM before the
// fix. Salt is UTF8(base64(random16)), NOT the raw sixteen octets.
const vectors={d:'5564f7006653f1592f41f5cc70074135d716c2f4967be0f18ee869412ebfbe34',id:'b890ec8c8f2b3217ced9eb117fa46330b80d0795d1ee6e44bf3d10320283cb45'};
(async()=>{
 assert.equal(argon2.argon2id,undefined);assert.equal(argon2.ArgonType.Argon2id,2);
 const key=await crypto.subtle.importKey('raw',Buffer.from(vectors.d,'hex'),'AES-GCM',false,['encrypt']);
 const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode('dmash/device-root-wrap/v1')},key,root);
 const record={id:'root',version:1,wrap:'argon2id-aes-256-gcm-v1',wrapSalt:Buffer.from(salt).toString('base64'),iv:Buffer.from(iv).toString('base64'),wrappedRoot:Buffer.from(encrypted).toString('base64'),materials:{opaque:{ciphertext:'retained synthetic encrypted slot'}}};
 assert.deepEqual(await DeviceRoot._decryptRoot(record,pass),root,'real WASM legacy-d reader matches frozen independent vector');
 const wrapped=await DeviceRoot._encryptRoot(root,pass,salt);
 assert.equal(wrapped.wrap,'argon2id-aes-256-gcm-v2');
 const idKey=await crypto.subtle.importKey('raw',Buffer.from(vectors.id,'hex'),'AES-GCM',false,['decrypt']);
 assert.deepEqual(new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(wrapped.iv,'base64'),additionalData:new TextEncoder().encode('dmash/device-root-wrap/v2')},idKey,Buffer.from(wrapped.wrappedRoot,'base64'))),root,'new wrap matches real explicit-id vector');
 const store=new IndexedDbDeviceRootStore(new IDBFactory());await store.put(record);DeviceRoot.setStoreForTests(store);
 const expectedId=(await DeviceRoot.deviceIdentity(root)).deviceId,handle=await DeviceRoot.prepareUnlock(pass);
 await DeviceRoot.commitPreparedCredentials(handle,'synthetic-only-new-master',{version:1,state:'ready',legacyCleanup:'complete',wipe:null,wipeDisabledReason:'not-configured'});handle.dispose();
 const changed=await store.get();assert.deepEqual(changed.materials,record.materials);assert.equal(changed.version,1);
 const next=await DeviceRoot.prepareUnlock('synthetic-only-new-master');assert.equal(next.identity.deviceId,expectedId);await DeviceRoot.publishPrepared(next);next.dispose();assert.deepEqual(DeviceRoot.state.root,root);
 const malformed={...changed,wrapKdf:{...changed.wrapKdf,mem:8}};await assert.rejects(DeviceRoot._decryptRoot(malformed,'synthetic-only-new-master'),e=>e.code==='STORAGE_CORRUPT');
 DeviceRoot.lock();store.close();console.log('PASS actual bundled WASM legacy Argon2d vector, explicit Argon2id v2 vector, same-root/identity/material migration and strict profile rejection');
})().catch(e=>{console.error(e);process.exitCode=1;});
