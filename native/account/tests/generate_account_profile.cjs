'use strict';
// Synthetic retained Account fixture only; actual shipped Argon2 WASM derives identity.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {webcrypto,createHash}=require('node:crypto');
const repo=path.resolve(__dirname,'../../..');
const context={WebAssembly,TextEncoder,TextDecoder,Uint8Array,Int8Array,Uint16Array,Int16Array,Uint32Array,Int32Array,Float32Array,Float64Array,ArrayBuffer,Promise,Math,Date,console,atob,btoa,setTimeout,clearTimeout};context.window=context;context.self=context;vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(repo,'D-MASH PWA/not_messenger/js/vendor/argon2-bundled.min.js'),'utf8'),context);
const nacl=require(path.join(repo,'D-MASH PWA/not_messenger/js/vendor/nacl-fast.min.js'));
(async()=>{
 const identity='native-synthetic-account',password='synthetic-account-password';
 const full=(await context.argon2.hash({pass:password,salt:identity+'D_MASH_GAMMA_V1_STABLE',type:0,time:3,mem:65536,hashLen:128})).hash;
 const sign=nacl.sign.keyPair.fromSeed(full.slice(64,96)),box=nacl.box.keyPair.fromSecretKey(full.slice(96,128));
 const pk=Buffer.concat([Buffer.from(sign.publicKey),Buffer.from(box.publicKey)]).toString('hex');
 const master=await webcrypto.subtle.importKey('raw',full.slice(0,32),'AES-GCM',false,['encrypt']);
 const alias=(base,level)=>{const input=Buffer.concat([Buffer.from(base+level),Buffer.from(full.slice(32,64))]);return createHash('sha256').update(Array.from(input).join(',')).digest('hex');};
 async function encrypted(key,data){const iv=webcrypto.getRandomValues(new Uint8Array(12)),cipher=await webcrypto.subtle.encrypt({name:'AES-GCM',iv},master,new TextEncoder().encode(JSON.stringify(data)));return {alias:key,blob:Buffer.concat([Buffer.from(iv),Buffer.from(cipher)]).toString('base64')};}
 const saved='local:saved-messages:v1',a=alias(saved,'L1'),remote='a'.repeat(64);
 const records={blind_peers:[await encrypted(a,{id:saved,name:'Избранное'}),await encrypted(alias(remote,'L1'),{id:remote,name:'Друг',transportProfile:'NODE_ACCOUNT_V4'})],blind_secrets:[await encrypted(a,{msgCount:1})],blind_messages:[await encrypted(alias(a+'1','L3'),{text:'retained Saved text',ts:1700000000000,inbound:false,transportState:'LOCAL',wireId:'b'.repeat(64)})],pairing_material:[],blind_outbox:[],blind_files:[],blind_file_owners:[]};
 const brokerFixture=JSON.parse(fs.readFileSync(path.join(repo,'native/broker/tests/compatibility.json')));
 const root=brokerFixture.records.modern_id;
 global.nacl=nacl;
 const {DeviceRoot}=require(path.join(repo,'D-MASH PWA/not_messenger/js/device_root.js'));
 const registryRaw=new Uint8Array(32).fill(11),materialIv=webcrypto.getRandomValues(new Uint8Array(12));
 const materialKey=await webcrypto.subtle.importKey('raw',await DeviceRoot.derive(new Uint8Array(32).fill(7),'dmash/device-mlkem-seed-root',1,'account-registry-v1'),'AES-GCM',false,['encrypt']);
 root.materials['account-registry-v1']={iv:Buffer.from(materialIv).toString('base64'),ciphertext:Buffer.from(await webcrypto.subtle.encrypt({name:'AES-GCM',iv:materialIv,additionalData:new TextEncoder().encode('dmash/device-material/v1|account-registry-v1')},materialKey,registryRaw)).toString('base64')};
 const registryKey=await webcrypto.subtle.importKey('raw',registryRaw,'AES-GCM',false,['encrypt']);
 const registryHmac=await webcrypto.subtle.importKey('raw',registryRaw,{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const registryAlias=Buffer.from(await webcrypto.subtle.sign('HMAC',registryHmac,new TextEncoder().encode(identity))).toString('base64'),registryIv=webcrypto.getRandomValues(new Uint8Array(12));
 const registryBlob=Buffer.concat([Buffer.from(registryIv),Buffer.from(await webcrypto.subtle.encrypt({name:'AES-GCM',iv:registryIv,additionalData:new TextEncoder().encode('dmash/account-registry/v1')},registryKey,new TextEncoder().encode(JSON.stringify({id:identity,pk}))))]).toString('base64');
 const profile={version:1,inventoryComplete:true,root,ancillary:{synthetic:true},databases:[{name:'dmash_device_root_v1',stores:[{name:'device_root',records:[root]}]},{name:'dm_registry_secure_v1',stores:[{name:'accounts',records:[{alias:registryAlias,blob:registryBlob}]},{name:'meta',records:[{key:'legacy-migrated',done:true,at:1700000000000}]}]},{name:'dm_gamma_vault',stores:Object.entries(records).map(([name,records])=>({name,records}))}]};
 const output={synthetic:true,identity,password,rootPin:brokerFixture.pin,accountPublicId:Buffer.from(sign.publicKey).toString('hex'),profile};
 fs.writeFileSync(path.join(__dirname,'account_profile.json'),JSON.stringify(output,null,2)+'\n');full.fill(0);sign.secretKey.fill(0);box.secretKey.fill(0);
 console.log('Generated synthetic retained Account ciphertext/history fixture with actual Argon2d128 identity');
})().catch(e=>{console.error(e);process.exitCode=1;});
