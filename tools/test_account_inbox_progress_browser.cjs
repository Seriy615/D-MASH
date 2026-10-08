'use strict';
// Local synthetic browser/IndexedDB checkpoint test. No Node mining or user vault.
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..'),source=fs.readFileSync(path.join(root,'D-MASH PWA/not_messenger/js/account_inbox_progress_v4.js'));
(async()=>{
 const server=http.createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/progress.js'?'application/javascript':'text/html');res.end(req.url==='/progress.js'?source:'<script src="/progress.js"></script>');});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({headless:true,executablePath:process.env.DMASH_CHROME});const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  const checks=await page.evaluate(async()=>{
   const db=await new Promise((resolve,reject)=>{const req=indexedDB.open('dmash_n4_progress_synthetic',1);req.onupgradeneeded=()=>req.result.createObjectStore('pairing_material',{keyPath:'alias'});req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);});
   const key=await crypto.subtle.importKey('raw',new Uint8Array(32).fill(9),'AES-GCM',false,['encrypt','decrypt']),abort=new AbortController(),accountId='synthetic-A';
   const session={accountId,signal:abort.signal,db,masterKey:key,blindSalt:new Uint8Array(32).fill(7),keys:{sign:{publicKey:new Uint8Array(32).fill(13)}},assertCurrent(){if(abort.signal.aborted)throw Error('revoked');}};
   const managed=await DmashAccountInboxProgressV4.open({session,kind:'managed'}),first=await managed.load();
   const state={next:1,peers:[{peer:'a'.repeat(64),digest:'b'.repeat(64),generation:2,after:{receivedAt:99,handle:'c'.repeat(64)}}]};
   const revision=await managed.save(first.revision,state);managed.close();
   const reopened=await DmashAccountInboxProgressV4.open({session,kind:'managed'}),saved=await reopened.load(),competitor=await DmashAccountInboxProgressV4.open({session,kind:'managed'}),stale=await competitor.load();
   await reopened.save(saved.revision,{next:0,peers:[]});let conflict=false;try{await competitor.save(stale.revision,state);}catch(error){conflict=error.code==='PROGRESS_CONFLICT';}
   const legacy=await DmashAccountInboxProgressV4.open({session}),legacyEmpty=await legacy.load();
   const other=await DmashAccountInboxProgressV4.open({session:{...session,accountId:'synthetic-B'},kind:'managed'}),otherEmpty=await other.load();
   const alias=reopened.alias;await new Promise((resolve,reject)=>{const tx=db.transaction('pairing_material','readwrite');tx.objectStore('pairing_material').put({alias,revision,blob:'corrupt'});tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);});
   let corrupt=false;try{await reopened.load();}catch(error){corrupt=error.code==='CORRUPT_PROGRESS';}
   abort.abort();let revoked=false;try{await other.load();}catch(_){revoked=true;}
   reopened.close();competitor.close();legacy.close();other.close();db.close();
   return {empty:first.cursor===null,reopened:JSON.stringify(saved.cursor)===JSON.stringify(state),conflict,legacyIsolated:legacyEmpty.cursor===null,otherAccountIsolated:otherEmpty.cursor===null,corrupt,revoked};
  });
  assert(Object.values(checks).every(Boolean));console.log(JSON.stringify({scope:'BROWSER synthetic encrypted managed Inbox cursor/IDB',browser:await browser.version(),sourceSha256:crypto.createHash('sha256').update(source).digest('hex'),checks}));
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
