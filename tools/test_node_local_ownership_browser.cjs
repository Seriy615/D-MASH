'use strict';
// Inactive-module fixture: real DeviceRoot/Worker/IDB. Not ordinary UI cutover.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const scripts=['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','vendor/argon2-bundled.min.js','device_root.js','node_runtime_host_v4.js','node_runtime_coordinator_v4.js','route_discovery_v4.js'];
const names=[...scripts,'node_runtime_worker_v4.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js','resource_pow.js','node_socket_v4.js','node_channel_v4.js','probe_primitives_v4.js','route_discovery_v4.js','recipient_payload_v4.js','node_routing_v4.js','node_inbox_v4.js','node_local_delivery_v4.js','node_local_ownership_v4.js','vendor/argon2.wasm'];
const sources=new Map(names.map(name=>['/js/'+name,fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js',name))]));
(async()=>{const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(scripts.map(name=>'<script src="/js/'+name+'"></script>').join(''));}else if(sources.has(req.url)){res.setHeader('Content-Type',req.url.endsWith('.wasm')?'application/wasm':'application/javascript');res.end(sources.get(req.url));}else{res.statusCode=404;res.end();}});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;try{
 browser=await chromium.launch({executablePath:process.env.DMASH_CHROME,headless:true});const p=await browser.newPage();await p.goto('http://127.0.0.1:'+server.address().port+'/');
 const result=await p.evaluate(async()=>{
  const vacant=async()=>{const until=Date.now()+5000;while((await navigator.locks.query()).held.some(lock=>lock.name==='dmash-node-runtime-v4')){if(Date.now()>until)throw Error('Worker root ownership did not release');await new Promise(resolve=>setTimeout(resolve,25));}};
  await DeviceRoot.unlock('Ownership-fixture-only');
  let host=await DmashNodeRuntimeHostV4.startForDevice(DeviceRoot,{localOwnership:'managed'});
  const nodeId=host.identity.nodeId,account=nacl.sign.keyPair(),route=nacl.sign.keyPair(),sign=nacl.sign.keyPair(),box=nacl.box.keyPair(),recipient=nacl.box.keyPair(),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),now=Math.floor(Date.now()/1000),signal=new AbortController();
  const certificate=DmashRouteDiscoveryV4.issueCertificate(route,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600});
  async function register(){const c=await host.challengeLocalOwner(hex(account.publicKey),certificate);return host.registerLocalOwner(c.challenge,nacl.sign.detached(new TextEncoder().encode(c.transcript),account.secretKey),{accountPublic:hex(account.publicKey),isAccountCurrent:()=>true,signal:signal.signal});}
  let owner=await register();
  const data=()=>({migrationId:'b'.repeat(64),bindingDigest:'c'.repeat(64),expectedGeneration:1,certificate,discoverySeed:sign.secretKey.slice(0,32),discoveryBox:box.secretKey.slice(),recipientKeys:[recipient.secretKey.slice()]});
  const material=data(),prepared=await host.prepareLocalBinding(owner,material),tuple=await host.verifyPreparation(prepared);
  const consumed=material.discoverySeed.every(v=>v===0)&&material.recipientKeys[0].every(v=>v===0),notAdvertised=(await host.stats()).owned===0;
  let forgedDenied=false,activationDenied=false,legacyDenied=false,rpcDenied=false,getterDenied=false;
  try{await host.call('STATS',{type:'OWNER_ACTIVATE'});}catch(_){rpcDenied=true;}
  try{await host.call('STATS',{get extra(){throw Error('getter ran');}});}catch(e){getterDenied=e.message==='Invalid worker RPC fields';}
  try{await host.verifyPreparation({});}catch(_){forgedDenied=true;}
  try{await host.activateLocalBinding(owner,prepared,{digest:tuple.bindingDigest});}catch(_){activationDenied=true;}
  try{await host.bindLocal({...data(),accountSlot:'fake'});}catch(_){legacyDenied=true;}
  host.close();await vacant();host=await DmashNodeRuntimeHostV4.startForDevice(DeviceRoot,{localOwnership:'managed'});owner=await register();
  const query=await host.queryLocalBinding(owner,'b'.repeat(64));
  const persisted=query.state==='NODE_PREPARED'&&query.preparationDigest===tuple.preparationDigest&&(await host.stats()).owned===0,identity=host.identity.nodeId===nodeId;
  signal.abort();let staleDenied=false;try{await host.verifyPreparation(query.handle);}catch(_){staleDenied=true;}
  const transitAlive=(await host.stats()).worker===true;DeviceRoot.lock();await vacant();let rootDenied=false;try{await host.stats();}catch(_){rootDenied=true;}
  return {rpcDenied,getterDenied,consumed,notAdvertised,forgedDenied,activationDenied,legacyDenied,persisted,identity,staleDenied,transitAlive,rootDenied};
 });for(const [name,value]of Object.entries(result))assert.equal(value,true,name);
 console.log('PASS real Worker/IndexedDB managed ownership: signed local owner, consumed keys, PREPARED crash/reopen, no advertisement, forged activation/legacy blocked, Account abort preserves Node, root lock closes. Account receipt activation/bootstrap NOT tested.');
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}})().catch(error=>{console.error(error);process.exitCode=1;});
