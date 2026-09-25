'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),{spawn}=require('node:child_process');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..');
const scripts=['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js','resource_pow.js','node_socket_v4.js','node_channel_v4.js','probe_primitives_v4.js','route_discovery_v4.js','recipient_payload_v4.js','node_routing_v4.js','node_runtime_host_v4.js','vendor/argon2-bundled.min.js','device_root.js'];
const allowed=new Set([...scripts,'node_runtime_worker_v4.js','vendor/argon2.wasm'].map(name=>'/js/'+name));
(async()=>{
 const helper=spawn(path.join(root,'.venv/bin/python'),[path.join(__dirname,'node_transit_v4_browser_server.py')],{stdio:['pipe','pipe','pipe']});
 const lines=[],waiters=[];let input='',exited=false;
 helper.stdout.on('data',data=>{input+=data;while(input.includes('\n')){const at=input.indexOf('\n'),line=JSON.parse(input.slice(0,at));input=input.slice(at+1);if(waiters.length)waiters.shift().resolve(line);else lines.push(line);}});
 helper.stderr.on('data',()=>{});
 const helperExit=new Promise(resolve=>helper.once('exit',code=>{exited=true;for(const waiter of waiters.splice(0))waiter.reject(Error('Transit fixture exited'));resolve(code);}));
 const next=async()=>{
  if(lines.length)return lines.shift();if(exited)throw Error('Transit fixture exited');let timer;
  try{return await new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(Error('Transit fixture deadline')),240000);waiters.push({resolve,reject});});}finally{clearTimeout(timer);}
 };
 const server=http.createServer((request,response)=>{
  if(request.url==='/'){response.setHeader('Content-Type','text/html');response.end(scripts.map(name=>'<script src="/js/'+name+'"></script>').join(''));}
  else if(allowed.has(request.url)){response.setHeader('Content-Type',request.url.endsWith('.wasm')?'application/wasm':'application/javascript');response.end(fs.readFileSync(path.join(root,'D-MASH PWA/not_messenger',request.url)));}
  else{response.statusCode=404;response.end();}
 });
 let browser;
 try{
  const info=await next();info.useWorker=process.env.DMASH_TRANSIT_WORKER==='1';await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.evaluate(async info=>{
   if(window.Core)throw Error('Unexpected Account runtime');
   if(info.useWorker){
    await DeviceRoot.unlock('Worker-root-test-only-2026');
    const host=await DmashNodeRuntimeHostV4.startForDevice(DeviceRoot);
    window.transit={host};
    for(const node of info.nodes)await host.connect({url:`ws://127.0.0.1:${node.port}/mesh/v4`,nodeId:node.nodeId});
    window.transitStats=()=>host.stats();window.transitInject=size=>host.injectCoverOnce(size);
    window.transitClose=()=>DeviceRoot.lock();
   }else{
    const seed=await DmashNodeIdentity.mine({timeoutMs:180000});
    const storageKey=crypto.getRandomValues(new Uint8Array(32)),base=crypto.getRandomValues(new Uint8Array(32));
    const signing=nacl.sign.keyPair.fromSeed(seed);seed.fill(0);
    const localId=Array.from(signing.publicKey,b=>b.toString(16).padStart(2,'0')).join('');
    const store=await DmashNodeRelationshipsV4.open(storageKey,localId);storageKey.fill(0);
    const runtime=new DmashNodeRoutingV4(base);base.fill(0);window.transit={runtime,store,signing};
    for(const node of info.nodes){
     const secure=await DmashNodeSocketV4.connect(`ws://127.0.0.1:${node.port}/mesh/v4`,signing,node.nodeId);
     const channel=await DmashNodeChannelV4.authorize(secure,store,{difficulty:20});await runtime.addPeer(node.nodeId,channel);
    }
    window.transitStats=async()=>({...runtime.stats,owned:runtime.owned.length,peers:runtime.peers.size,
     queued:[...runtime.queues.values()].reduce((n,q)=>n+q.length,0),sending:runtime.senders.size,cover:runtime.coverHistory.length,worker:false});
    window.transitInject=async size=>runtime.injectCoverOnce(size);
    window.transitClose=async()=>{await runtime.close();store.close();signing.secretKey.fill(0);};
   }
   const stats=await transitStats();if(stats.owned||stats.peers!==2||stats.worker!==info.useWorker)throw Error('Invalid browser transit topology');
   window.transitTicks=0;window.transitTimer=setInterval(()=>window.transitTicks++,20);
   window.transitDrain=async()=>{
    const until=Date.now()+5000;
    while(true){const state=await transitStats();if(!state.sending&&!state.queued)return;
     if(Date.now()>until)throw Error('Cover queue did not drain');await new Promise(resolve=>setTimeout(resolve,20));}
   };

  },info);
  helper.stdin.write('start\n');const early=await next();assert.equal(early.event,'early_probe');
  await page.evaluate(async()=>{
   await transitDrain();
   if(!await transitInject(1024))throw Error('Early cover injection rejected');
   await new Promise(resolve=>setTimeout(resolve,800));
  });
  helper.stdin.write('bind\n');const delivered=await next();assert.equal(delivered.event,'delivered');assert(delivered.onlyBrowserPath&&delivered.labelRewrite&&delivered.lateBinding);
  const injected=await page.evaluate(async()=>{
   for(let i=0;i<3;i++){await transitDrain();if(!await transitInject(1024))throw Error('Granted cover injection rejected');}
   if(await transitInject(1024))throw Error('Cover budget exceeded');
   return (await transitStats()).cover;
  });
  assert.equal(injected,4);helper.stdin.write('cover\n');const covered=await next();assert.equal(covered.event,'cover');assert(covered.discarded>=1);assert.equal(covered.accepted,2);
  const result=await page.evaluate(async()=>{
   const result={...await transitStats(),noAccount:!window.Core,uiTicks:window.transitTicks};
   if(window.transit.host)await window.transit.host.coverPolicy(true);
   await transitClose();clearInterval(window.transitTimer);return result;
  });
  assert.equal(result.worker,info.useWorker);assert(result.uiTicks>=20);assert(result.noAccount);assert.equal(result.owned,0);assert.equal(result.forwarded,3);assert(result.probes>=1);
  helper.stdin.write('disconnected\n');const disconnected=await next();assert(disconnected.unavailable);
  if(info.useWorker){
   const lifecycle=await page.evaluate(async node=>{
    const previous=window.transit.host.identity.nodeId;
    let rejected=false;try{await window.transit.host.stats();}catch(_){rejected=true;}
    await DeviceRoot.unlock('Worker-root-test-only-2026');
    const replacement=await DmashNodeRuntimeHostV4.startForDevice(DeviceRoot);
    const stable=replacement.identity.nodeId===previous;
    const connecting=replacement.connect({url:`ws://127.0.0.1:${node.port}/mesh/v4`,nodeId:node.nodeId});
    DeviceRoot.lock();let cancelled=false;try{await connecting;}catch(_){cancelled=true;}
    return {rejected,stable,cancelled};
   },info.nodes[0]);assert(lifecycle.rejected&&lifecycle.stable&&lifecycle.cancelled);
  }
  helper.stdin.end('stop\n');assert.equal(await helperExit,0);
  console.log((info.useWorker?'WORKER + encrypted DeviceRoot persistence, root-lock cancellation and UI heartbeat ':'')+'PASS Python N1 -> real Chrome Node B -> Python N2: genuine discovery, signed route proof, random TTL/NCRH rewriting, late local route binding after cached Probe, opaque payload and label rewrite, no Account or route keys at B, no bypass, cover during pending discovery and after route installation silently discarded, real payload after cover, disconnect becomes unavailable');
 }finally{
  if(browser)await browser.close();if(server.listening)await new Promise(resolve=>server.close(resolve));
  if(!exited){helper.stdin.end('stop\n');const timer=setTimeout(()=>helper.kill('SIGKILL'),5000);await helperExit;clearTimeout(timer);}
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
