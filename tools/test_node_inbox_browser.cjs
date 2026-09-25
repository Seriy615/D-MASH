'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const names=['vendor/nacl-fast.min.js','route_discovery_v4.js','recipient_payload_v4.js','node_inbox_v4.js'];
const sources=new Map(names.map(name=>['/js/'+name,fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js',name))]));
(async()=>{
 const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(names.map(name=>'<script src="/js/'+name+'"></script>').join(''));}else if(sources.has(req.url)){res.setHeader('Content-Type','application/javascript');res.end(sources.get(req.url));}else{res.statusCode=404;res.end();}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const context=await browser.newContext(),pages=await Promise.all([context.newPage(),context.newPage()]);
  await Promise.all(pages.map(page=>page.goto('http://127.0.0.1:'+server.address().port+'/')));
  const blob=await pages[0].evaluate(()=>DmashRecipientPayloadV4.sealPayload(nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(7)).publicKey,'opaque-slot-A'));
  const results=await Promise.all(pages.map(page=>page.evaluate(async blob=>{
   const box=nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(7));
   const inbox=await DmashNodeInboxV4.open(new Uint8Array(32).fill(42),'a'.repeat(64),{maxRecords:2,maxBytes:4096});
   try{return await Promise.all(Array.from({length:8},()=>inbox.receive('b'.repeat(64),'slot-A',blob,[box.secretKey])));}finally{inbox.close();box.secretKey.fill(0);}
  },blob)));
  assert.equal(results.flat().filter(result=>result.inserted).length,1);
  await pages[0].reload();
  const evidence=await pages[0].evaluate(async()=>{
   const rejects=async action=>{try{await action();return false;}catch(_){return true;}};
   const key=new Uint8Array(32).fill(42),local='a'.repeat(64),route='b'.repeat(64),box=nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(7));
   let now=Date.now();
   const open=()=>DmashNodeInboxV4.open(key,local,{maxRecords:2,maxBytes:4096,clock:()=>now});
   let inbox=await open();
   const persisted=(await inbox.list('slot-A')).records[0].payload==='opaque-slot-A';
   await inbox.receive(route,'slot-B',DmashRecipientPayloadV4.sealPayload(box.publicKey,'opaque-slot-B'),[box.secretKey]);
   const quota=await rejects(()=>inbox.receive(route,'slot-C',DmashRecipientPayloadV4.sealPayload(box.publicKey,'quota'),[box.secretKey]));
   const privateRows=JSON.stringify(await inbox.store.all());
   const privateLookup=!['slot-A','slot-B',route,'opaque-slot-A'].some(value=>privateRows.includes(value));
   const broken=(await inbox.list('slot-A')).records[0],raw=await inbox.store.read(broken.handle);
   await inbox.store.transaction('readwrite',(store,done)=>{store.delete(raw.key);store.put({...raw,key:'0'.repeat(64),ciphertext:new Uint8Array([1,2,3])});done(true);});
   inbox.close();inbox=await open();
   const list=await inbox.list('slot-B');
   const isolation=list.unreadable===1&&list.records.length===1&&list.records[0].payload==='opaque-slot-B';
   const wrongSlot=await rejects(()=>inbox.acknowledge(list.records[0].handle,'slot-A'));
   await inbox.acknowledge(list.records[0].handle,'slot-B');
   const retired=(await inbox.list('slot-B')).records.length===0;
   const damaged=await inbox.store.read('0'.repeat(64));await inbox.store.cas(damaged.key,damaged.revision,null);
   now+=30*86400000+1;const pruned=await inbox.pruneSeen()===1;
   const bytesQuota=await rejects(()=>inbox.receive(route,'slot-C',DmashRecipientPayloadV4.sealPayload(box.publicKey,'x'.repeat(8000)),[box.secretKey]));
   const candidate=await inbox.encrypt('c'.repeat(64),{kind:'pending',payload:'must not persist'});
   const pending=inbox.store.cas('c'.repeat(64),null,candidate);const cancelled=rejects(()=>pending);inbox.close();
   const aborted=await cancelled;
   inbox=await open();const noLateWrite=await inbox.store.read('c'.repeat(64))===null;inbox.close();
   const wrongKey=await rejects(()=>DmashNodeInboxV4.open(new Uint8Array(32).fill(43),local));
   const wrongIdentity=await rejects(()=>DmashNodeInboxV4.open(key,'d'.repeat(64)));
   const full=await DmashNodeInboxV4.open(key,local,{databaseName:'full-deferred-inbox',maxRecords:1,maxBytes:4096});
   await full.receive(route,'slot-A',DmashRecipientPayloadV4.sealPayload(box.publicKey,'promote without a free row'),[]);
   const bindingRoom=await full.saveBinding(route,{accountSlot:'slot-A',test:'separate metadata quota'});
   const promoted=await full.retryDeferred(route,'slot-A',[box.secretKey])===1;
   const fullQueueDelivery=(await full.list('slot-A')).records[0].payload==='promote without a free row';full.close();
   box.secretKey.fill(0);key.fill(0);
   return {persisted,quota,privateLookup,isolation,wrongSlot,retired,pruned,bytesQuota,aborted,noLateWrite,wrongKey,wrongIdentity,bindingRoom,promoted,fullQueueDelivery};
  });
  for(const [name,value] of Object.entries(evidence))assert.equal(value,true,name);
  console.log('PASS real IndexedDB Inbox: concurrent tabs, atomic duplicate/quota, encrypted slot isolation, malformed-first recovery, receipt/tombstone retention and lock-aborted write');
 }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
