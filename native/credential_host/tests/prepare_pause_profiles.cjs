'use strict';
// Only newly generated public-test synthetic profiles are copied/modified.
// Source retained fixtures and accepted native databases are never rewritten.
const fs=require('node:fs'),path=require('node:path'),{webcrypto}=require('node:crypto');
const repo=path.resolve(__dirname,'../../..');
global.nacl=require(path.join(repo,'D-MASH PWA/not_messenger/js/vendor/nacl-fast.min.js'));
const {DeviceRoot}=require(path.join(repo,'D-MASH PWA/not_messenger/js/device_root.js'));
const [source,seedFile,output]=process.argv.slice(2),seeds=JSON.parse(fs.readFileSync(seedFile));
const known=JSON.parse(fs.readFileSync(path.join(repo,'native/account/tests/account_profile.json')));
(async()=>{
 for(let i=0;i<2;i++){
  const fixture=JSON.parse(fs.readFileSync(path.join(source,'account-'+i+'.json')));
  if(fixture.synthetic!==true||fixture.profile.root.wrappedRoot!==known.profile.root.wrappedRoot)throw Error('Synthetic Root fixture required');
  const root=fixture.profile.root;
  for(const [name,plain] of [['node-ed25519-pow-v4',seeds[i].seed],['node-base-ncrh-v4',seeds[i].baseNcrh]]){
   const raw=await DeviceRoot.derive(new Uint8Array(32).fill(7),'dmash/device-mlkem-seed-root',1,name);
   const key=await webcrypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt']);raw.fill(0);
   const iv=webcrypto.getRandomValues(new Uint8Array(12));
   root.materials[name]={iv:Buffer.from(iv).toString('base64'),ciphertext:Buffer.from(await webcrypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode('dmash/device-material/v1|'+name)},key,Buffer.from(plain,'hex'))).toString('base64')};
  }
  const rows=fixture.profile.databases.find(d=>d.name==='dmash_device_root_v1').stores.find(s=>s.name==='device_root');
  rows.records=[{key:'root',value:root}];
  fs.writeFileSync(path.join(output,'account-'+i+'.json'),JSON.stringify(fixture),{mode:0o600});
 }
 console.log('PASS independent test Node identities wrapped into fresh synthetic profile copies');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
