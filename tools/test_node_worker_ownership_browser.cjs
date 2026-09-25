'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const scripts=['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','vendor/argon2-bundled.min.js','device_root.js','node_runtime_host_v4.js'];
const names=[...scripts,'node_runtime_worker_v4.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js','resource_pow.js','node_socket_v4.js','node_channel_v4.js','probe_primitives_v4.js','route_discovery_v4.js','recipient_payload_v4.js','node_routing_v4.js','node_inbox_v4.js','node_local_delivery_v4.js','vendor/argon2.wasm'];
const sources=new Map(names.map(name=>['/js/'+name,fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js',name))]));
(async()=>{
 const server=http.createServer((req,res)=>{
  if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(scripts.map(name=>'<script src="/js/'+name+'"></script>').join(''));}
  else if(sources.has(req.url)){res.setHeader('Content-Type',req.url.endsWith('.wasm')?'application/wasm':'application/javascript');res.end(sources.get(req.url));}
  else{res.statusCode=404;res.end();}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const context=await browser.newContext(),one=await context.newPage(),two=await context.newPage();
  const url='http://127.0.0.1:'+server.address().port+'/';
  await Promise.all([one.goto(url),two.goto(url)]);
  const unlock=page=>page.evaluate(()=>DeviceRoot.unlock('Ownership-fixture-only-2026').then(()=>true));
  const start=page=>page.evaluate(async()=>{window.owner=await DmashNodeRuntimeHostV4.startForDevice(DeviceRoot);return owner.identity.nodeId;});
  const vacant=async page=>{
   const until=Date.now()+5000;
   while(await page.evaluate(async()=>(await navigator.locks.query()).held.some(lock=>lock.name==='dmash-node-runtime-v4'))){
    if(Date.now()>until)throw Error('Node ownership not released');await new Promise(resolve=>setTimeout(resolve,25));
   }
  };
  await unlock(one);const id=await start(one);await unlock(two);
  await assert.rejects(start(two),/Node worker operation failed/);
  assert.equal(await one.evaluate(async()=>(await owner.stats()).worker),true,'losing actor must not close the winner');
  await two.evaluate(()=>DeviceRoot.lock());
  assert.equal(await one.evaluate(async()=>(await owner.stats()).worker),true,'locking an inactive tab must not close another tab');
  // Closing the owner page kills its Worker, without relying on host cleanup.
  await one.close();await vacant(two);await unlock(two);assert.equal(await start(two),id);
  // Hard Worker termination also releases the browser lock automatically.
  await two.evaluate(()=>{owner.worker.terminate();DeviceRoot.lock();});
  await vacant(two);await unlock(two);assert.equal(await start(two),id);
  await two.evaluate(()=>DeviceRoot.lock());await vacant(two);
  await unlock(two);assert.equal(await start(two),id);
  // A same-origin reload cannot leave a lease or actor behind.
  await two.reload();await vacant(two);await unlock(two);assert.equal(await start(two),id);
  await two.evaluate(()=>DeviceRoot.lock());await vacant(two);
  await unlock(two);
  for(const apiVersion of [null,1,3])assert.equal(await two.evaluate(async apiVersion=>{
   const identity=await DmashNodeIdentity.unlockDeviceIdentity(DeviceRoot),actor=new Worker('/js/node_runtime_worker_v4.js');let timer;
   try{
    const seed=identity.signing.secretKey.slice(0,32);
    return await new Promise((resolve,reject)=>{
     timer=setTimeout(()=>reject(Error('Mixed API refusal deadline')),5000);
     actor.onmessage=({data})=>resolve(data.id===1&&data.ok===false);
     actor.onerror=()=>reject(Error('Unexpected mixed API Worker crash'));
     const packet={id:1,type:'INIT',seed,storageKey:new Uint8Array(32).fill(7),baseNcrh:new Uint8Array(32).fill(8)};
     if(apiVersion!==null)packet.apiVersion=apiVersion;
     actor.postMessage(packet,[seed.buffer,packet.storageKey.buffer,packet.baseNcrh.buffer]);
    });
   }finally{clearTimeout(timer);actor.terminate();identity.signing.secretKey.fill(0);}
  },apiVersion),true,'Worker must reject missing/unknown local API version');
  await vacant(two);assert.equal(await start(two),id);
  await two.evaluate(()=>DeviceRoot.lock());await vacant(two);
  console.log('PASS real Worker ownership: cross-tab rejection, unaffected winner, tab close, hard termination, root lock and reload; mixed API refusal and persistent Node identity');
 }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
