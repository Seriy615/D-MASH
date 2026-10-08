'use strict';
// Synthetic Chromium/IndexedDB fixture. Never opens a user profile or deployed origin.
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..'),storage=fs.readFileSync(path.join(root,'D-MASH PWA/not_messenger/js/storage.js'));
(async()=>{
 const server=http.createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/storage.js'?'application/javascript':'text/html');res.end(req.url==='/storage.js'?storage:'<script src="/storage.js"></script>');});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({headless:true,executablePath:process.env.DMASH_CHROME});const context=await browser.newContext(),page=await context.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  const observed=await page.evaluate(async()=>{
   const hex=x=>Array.from(x,b=>b.toString(16).padStart(2,'0')).join('');
   window.Core={blindSalt:new Uint8Array(32).fill(7),fastHash:async input=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',input)))};
   window.nacl={randomBytes:n=>crypto.getRandomValues(new Uint8Array(n))};
   await Storage.initGamma(new Uint8Array(32).fill(9));
   const target='a'.repeat(64),other='b'.repeat(64),targetAlias=await Storage.getAlias(target,'L1'),otherAlias=await Storage.getAlias(other,'L1');
   await Storage.saveMessageGamma(target,'synthetic history',false,true,'SENT','synthetic-wire');
   await Storage.savePeerGamma(other,'Other synthetic peer');
   const knownAlias=await Storage.getAlias('node-peer-v4:'+target,'L2');
   const publicAlias='c'.repeat(64),journalAlias='d'.repeat(64);
   const iv=crypto.getRandomValues(new Uint8Array(12)),plain=new TextEncoder().encode(JSON.stringify({schema:2,kind:'journal',account:'e'.repeat(64),alias:journalAlias,payload:{peer:other}}));
   const sealed=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},Storage.masterKey,plain)),packed=new Uint8Array(12+sealed.length);packed.set(iv);packed.set(sealed,12);
   await new Promise((resolve,reject)=>{const tx=Storage.db.transaction('pairing_material','readwrite'),store=tx.objectStore('pairing_material');store.put({alias:knownAlias,blob:'corrupt legacy owner row'});store.put({alias:publicAlias,blob:'opaque versioned row'});store.put({alias:journalAlias,blob:Storage.uint8ToBase64(packed)});tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);});
   let error=null;try{await Storage.deleteChatGamma(target);}catch(e){error=e.message;}
   const row=async(table,alias)=>new Promise((resolve,reject)=>{const tx=Storage.db.transaction(table,'readonly');const req=tx.objectStore(table).get(alias);req.onsuccess=()=>resolve(req.result??null);req.onerror=()=>reject(req.error);});
   const messageAlias=await Storage.getAlias(targetAlias+1,'L3');
   const state={error,targetPeer:!!await row('blind_peers',targetAlias),targetHistory:!!await row('blind_messages',messageAlias),otherPeer:!!await row('blind_peers',otherAlias),corruptKnown:!!await row('pairing_material',knownAlias),unknownVersioned:!!await row('pairing_material',publicAlias),journalVersioned:!!await row('pairing_material',journalAlias)};
   const normal='f'.repeat(64),normalAlias=await Storage.getAlias(normal,'L1'),normalRouteAlias=await Storage.getAlias('node-peer-v4:'+normal,'L2'),normalMappingAlias=await Storage.getAlias('node-route-v4:'+'1'.repeat(64),'L2');
   await Storage.saveMessageGamma(normal,'synthetic normal deletion',false,true,'SENT','synthetic-normal');
   await Storage.putBox('pairing_material',{alias:normalRouteAlias,data:{certificate:{synthetic:true},localRouteId:'1'.repeat(64)}});
   await Storage.putBox('pairing_material',{alias:normalMappingAlias,data:{peerId:normal}});
   const normalResult=await Storage.deleteChatGamma(normal),normalMessageAlias=await Storage.getAlias(normalAlias+1,'L3');
   state.normal={peerGone:!await row('blind_peers',normalAlias),historyGone:!await row('blind_messages',normalMessageAlias),routeGone:!await row('pairing_material',normalRouteAlias),mappingGone:!await row('pairing_material',normalMappingAlias),otherPeer:!!await row('blind_peers',otherAlias),unknownVersioned:!!await row('pairing_material',publicAlias),journalVersioned:!!await row('pairing_material',journalAlias),unknownCount:normalResult.unknownPairingRows};
   Storage.db.close();return state;
  });
  console.log(JSON.stringify({stage:'observed',observed}));
  assert(observed.error&&observed.targetPeer&&observed.targetHistory&&observed.corruptKnown,'corrupt known owner row must fail before any chat/history deletion');
  assert(observed.otherPeer&&observed.unknownVersioned&&observed.journalVersioned,'unrelated and versioned rows must survive');
  assert(Object.entries(observed.normal).every(([key,value])=>key==='unknownCount'?value>=2:value===true),'valid peer deletion must be complete while versioned/unrelated rows survive');
  console.log(JSON.stringify({scope:'BROWSER synthetic IndexedDB migration-safe peer deletion',browser:await browser.version(),sourceSha256:crypto.createHash('sha256').update(storage).digest('hex'),observed}));
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
