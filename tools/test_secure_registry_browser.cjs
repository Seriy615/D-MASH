'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http'),path=require('node:path');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 let source=fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js/acceptance_v51.js'));
 if(process.env.DMASH_REGISTRY_RUNTIME_URL){const response=await fetch(process.env.DMASH_REGISTRY_RUNTIME_URL);if(!response.ok)throw Error('Public registry runtime unavailable');source=Buffer.from(await response.arrayBuffer());}
 const server=http.createServer((request,response)=>{response.setHeader('Content-Type',request.url==='/runtime.js'?'application/javascript; charset=utf-8':'text/html; charset=utf-8');response.end(request.url==='/runtime.js'?source:'<!doctype html><meta charset="utf-8">');});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  await page.evaluate(async()=>{
   const db=await new Promise((resolve,reject)=>{const r=indexedDB.open('dm_registry_v1',1);r.onupgradeneeded=()=>r.result.createObjectStore('accounts',{keyPath:'id'});r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
   const tx=db.transaction('accounts','readwrite');tx.objectStore('accounts').put({id:'Alice',pk:'a'.repeat(64),privateRoutes:[{routeId:'preserved'}]});tx.objectStore('accounts').put({id:'Bob',pk:'b'.repeat(64)});
   await new Promise((resolve,reject)=>{tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);});db.close();
   window.failMaterial=true;window.DeviceRoot={state:{root:new Uint8Array(32).fill(7)},deviceMaterial:async()=>{await new Promise(resolve=>setTimeout(resolve,25));if(window.failMaterial)throw Error('injected key read failure');return new Uint8Array(32).fill(9);}};
   window.DMashStorage={getAllRegistryAccounts:async()=>[]};
   const sign=crypto.subtle.sign.bind(crypto.subtle);crypto.subtle.sign=async(...args)=>{await new Promise(resolve=>setTimeout(resolve,25));return sign(...args);};
   window.legacyRows=async()=>{const db=await new Promise(resolve=>{const r=indexedDB.open('dm_registry_v1');r.onsuccess=()=>resolve(r.result);});try{return await new Promise((resolve,reject)=>{const r=db.transaction('accounts').objectStore('accounts').getAll();r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});}finally{db.close();}};
  });
  await page.addScriptTag({url:'/runtime.js'});
  const result=await page.evaluate(async()=>{
   let rejected=false;try{await DMashStorage.getAllRegistryAccounts();}catch(_){rejected=true;}
   if(!rejected||(await legacyRows()).length!==2)throw Error('Failed migration erased legacy registry');
   window.failMaterial=false;const migrated=await DMashStorage.getAllRegistryAccounts();
   if(migrated.length!==2||(await legacyRows()).length)throw Error('Successful migration did not preserve/retire expected accounts');
   if((await DMashStorage.getRegistryAccount('Alice')).privateRoutes[0].routeId!=='preserved')throw Error('Migration lost route metadata');
   await DMashStorage.registerAccount('Charlie','c'.repeat(64));
   await DMashStorage.updateAccountAuth('Charlie',{notification:true});
   if((await DMashStorage.getRegistryAccount('Charlie')).notification!==true)throw Error('Registry update failed');
   await DMashStorage.removeAccountFromRegistry('Charlie');
   if(await DMashStorage.getRegistryAccount('Charlie'))throw Error('Registry delete failed');
   return {migrated:2,retainedOnFailure:true,slowCryptoCrud:true};
  });
  assert.deepEqual(result,{migrated:2,retainedOnFailure:true,slowCryptoCrud:true});
  console.log('PASS real Chrome IndexedDB + delayed WebCrypto: registry get/register/update/delete; failed migration retains legacy data and successful retry preserves accounts/routes');
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
