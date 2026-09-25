'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const source=fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js/node_relationships_v4.js'));
 const rootSource=fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js/device_root.js'));
 const server=http.createServer((request,response)=>{response.setHeader('Content-Type',request.url.endsWith('.js')?'application/javascript':'text/html');response.end(request.url==='/store.js'?source:request.url==='/root.js'?rootSource:'<script src="/store.js"></script><script src="/root.js"></script>');});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 let browser;
 try {
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const context=await browser.newContext();
  const pages=await Promise.all([context.newPage(),context.newPage()]);
  await Promise.all(pages.map(page=>page.goto(`http://127.0.0.1:${server.address().port}/`)));
  const results=await Promise.all(pages.map(page=>page.evaluate(async()=>{
   const store=await DmashNodeRelationshipsV4.open(new Uint8Array(32).fill(42),'aa'.repeat(32),{maxRelationships:1});
   try{return await Promise.all(Array.from({length:6},()=>store.relationship('bb'.repeat(32),{inbound:'cd'.repeat(16)})));}
   finally{store.close();}
  })));
  assert(results.flat().every(result=>JSON.stringify(result)===JSON.stringify(results[0][0])));
  await pages[0].reload();
  const evidence=await pages[0].evaluate(async expected=>{
   const key=new Uint8Array(32).fill(42),local='aa'.repeat(32),peer='bb'.repeat(32);
   const rejects=async fn=>{try{await fn();return false;}catch(_){return true;}};
   const wrongKey=await rejects(()=>DmashNodeRelationshipsV4.open(new Uint8Array(32).fill(43),local));
   const wrongIdentity=await rejects(()=>DmashNodeRelationshipsV4.open(key,'cc'.repeat(32)));
   let current=true;
   const store=await DmashNodeRelationshipsV4.open(key,local,{maxRelationships:1,isCurrent:()=>current});
   const reloaded=JSON.stringify(await store.relationship(peer))===JSON.stringify(expected);
   const changed=await rejects(()=>store.relationship(peer,{inbound:'ef'.repeat(16)}));
   const quota=await rejects(()=>store.relationship('cc'.repeat(32)));
   const preserved=JSON.stringify(await store.relationship(peer))===JSON.stringify(expected);
   const rows=await store.transaction('readonly',(os,done)=>{os.getAll().onsuccess=event=>done(event.target.result);});
   const encoded=JSON.stringify(rows);
   const privateLookup=![peer,local,expected.outbound,expected.inbound].some(value=>encoded.includes(value));
   current=false;
   const locked=await rejects(()=>store.relationship(peer));
   store.close();
   const reopened=await DmashNodeRelationshipsV4.open(key,local);
   const target=rows.find(row=>row.key!=='binding');
   await reopened.transaction('readwrite',(os,done)=>{os.put({...target,ciphertext:new Uint8Array([1,2,3])});done(true);});
   const corrupt=await rejects(()=>reopened.relationship(peer));
   const corruptPreserved=(await reopened.read(target.key)).ciphertext.byteLength===3;
   reopened.close();
   DeviceRoot.state={root:crypto.getRandomValues(new Uint8Array(32))};
   const copy=DeviceRoot.state.root.slice();
   const deviceStore=await DmashNodeRelationshipsV4.openForDevice(DeviceRoot,local,{databaseName:'device-bound-test'});
   const original=await deviceStore.relationship(peer);
   DeviceRoot.lock();
   const deviceLock=await rejects(()=>deviceStore.relationship(peer));
   deviceStore.close();
   DeviceRoot.state={root:copy};
   const deviceReload=await DmashNodeRelationshipsV4.openForDevice(DeviceRoot,local,{databaseName:'device-bound-test'});
   const rootReload=JSON.stringify(await deviceReload.relationship(peer))===JSON.stringify(original);
   deviceReload.close();DeviceRoot.lock();
   return {wrongKey,wrongIdentity,reloaded,changed,quota,preserved,privateLookup,locked,corrupt,corruptPreserved,deviceLock,rootReload};
  },results[0][0]);
  for(const [name,result] of Object.entries(evidence)) assert.equal(result,true,name);
  console.log('PASS real browser IndexedDB: concurrent tabs, persistent directions, wrong key/identity, quota, corruption preservation, session lock, opaque lookups');
 } finally {if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
