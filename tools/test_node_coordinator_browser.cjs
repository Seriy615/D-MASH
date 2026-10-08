'use strict';
// Inactive-module fixture: real DeviceRoot/Worker/IDB. Not ordinary UI cutover.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const scripts=['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','vendor/argon2-bundled.min.js','device_root.js','node_runtime_host_v4.js','node_runtime_coordinator_v4.js'];
const names=[...scripts,'node_runtime_worker_v4.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js','resource_pow.js','node_socket_v4.js','node_channel_v4.js','probe_primitives_v4.js','route_discovery_v4.js','recipient_payload_v4.js','node_routing_v4.js','node_inbox_v4.js','node_local_delivery_v4.js','vendor/argon2.wasm'];
const sources=new Map(names.map(name=>['/js/'+name,fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js',name))]));
(async()=>{const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(scripts.map(name=>'<script src="/js/'+name+'"></script>').join(''));}else if(sources.has(req.url)){res.setHeader('Content-Type',req.url.endsWith('.wasm')?'application/wasm':'application/javascript');res.end(sources.get(req.url));}else{res.statusCode=404;res.end();}});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;try{
 browser=await chromium.launch({executablePath:process.env.DMASH_CHROME,headless:true});const p=await browser.newPage();await p.goto('http://127.0.0.1:'+server.address().port+'/');
 const result=await p.evaluate(async()=>{
  const vacant=async()=>{const until=Date.now()+5000;while((await navigator.locks.query()).held.some(lock=>lock.name==='dmash-node-runtime-v4')){if(Date.now()>until)throw Error('Worker root ownership did not release');await new Promise(resolve=>setTimeout(resolve,25));}};
  await DeviceRoot.unlock('Coordinator-fixture-only-2026');const coordinator=new DmashNodeRuntimeCoordinatorV4(DeviceRoot);const [first,second]=await Promise.all([coordinator.start(),coordinator.start()]);if(first!==second)throw Error('Duplicate Worker startup');
  const capture=coordinator.capture(),identity=first.identity.nodeId;const worker=(await first.stats()).worker===true,noAccount=!window.Core;
  DeviceRoot.lock();let closed=false;try{await first.stats();}catch(_){closed=true;}const stale=!capture.current()&&!coordinator.isCurrentToken(capture.token);await vacant();
  await DeviceRoot.unlock('Coordinator-fixture-only-2026');const replacement=await coordinator.start();const stable=replacement.identity.nodeId===identity,rootSession=DeviceRoot.state;
  const current=coordinator.capture();coordinator.stop();await vacant();const stopped=coordinator.status().state==='STOPPED'&&!current.current()&&DeviceRoot.state===rootSession;
  const third=await coordinator.start();const restarted=third.identity.nodeId===identity;coordinator.close();await vacant();let refused=false;try{await coordinator.start();}catch(e){refused=e.code==='NODE_COORDINATOR_CLOSED';}DeviceRoot.lock();
  return {worker,noAccount,closed,stale,stable,stopped,restarted,refused};
 });for(const [name,value]of Object.entries(result))assert.equal(value,true,name);
 console.log('PASS real browser inactive Node coordinator: shared Worker start, no Account, root-lock close/token invalidation, persisted identity across root unlock, stop preserving unlocked root, restart and permanent close');
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}})().catch(error=>{console.error(error);process.exitCode=1;});
