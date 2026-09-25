'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),{spawn}=require('node:child_process');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..');
const scripts=['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js','resource_pow.js','node_socket_v4.js','node_channel_v4.js','probe_primitives_v4.js','route_discovery_v4.js','node_routing_v4.js'];
const allowed=new Set(scripts.map(name=>'/js/'+name));
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
  else if(allowed.has(request.url)){response.setHeader('Content-Type','application/javascript');response.end(fs.readFileSync(path.join(root,'D-MASH PWA/not_messenger',request.url)));}
  else{response.statusCode=404;response.end();}
 });
 let browser;
 try{
  const info=await next();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.evaluate(async info=>{
   if(window.Core)throw Error('Unexpected Account runtime');
   const seed=await DmashNodeIdentity.mine({timeoutMs:180000}),signing=nacl.sign.keyPair.fromSeed(seed);seed.fill(0);
   const localId=Array.from(signing.publicKey,b=>b.toString(16).padStart(2,'0')).join(''),storageKey=crypto.getRandomValues(new Uint8Array(32));
   const store=await DmashNodeRelationshipsV4.open(storageKey,localId);storageKey.fill(0);
   const base=crypto.getRandomValues(new Uint8Array(32)),runtime=new DmashNodeRoutingV4(base);base.fill(0);
   window.transit={runtime,store,signing};
   for(const node of info.nodes){
    const secure=await DmashNodeSocketV4.connect(`ws://127.0.0.1:${node.port}/mesh/v4`,signing,node.nodeId);
    const channel=await DmashNodeChannelV4.authorize(secure,store,{difficulty:20});
    await runtime.addPeer(node.nodeId,channel);
   }
   if(runtime.owned.length||runtime.peers.size!==2)throw Error('Invalid browser transit topology');
  },info);
  helper.stdin.write('start\n');const delivered=await next();assert.equal(delivered.event,'delivered');assert(delivered.onlyBrowserPath&&delivered.labelRewrite&&delivered.lateBinding);
  const result=await page.evaluate(async()=>{
   const {runtime,store,signing}=window.transit;const result={...runtime.stats,owned:runtime.owned.length,noAccount:!window.Core};
   await runtime.close();store.close();signing.secretKey.fill(0);return result;
  });
  assert(result.noAccount);assert.equal(result.owned,0);assert.equal(result.forwarded,2);assert(result.probes>=1);
  helper.stdin.write('disconnected\n');const disconnected=await next();assert(disconnected.unavailable);
  helper.stdin.end('stop\n');assert.equal(await helperExit,0);
  console.log('PASS Python N1 -> real Chrome Node B -> Python N2: genuine discovery, signed route proof, random TTL/NCRH rewriting, late local route binding after cached Probe, opaque payload and label rewrite, no Account or route keys at B, no bypass, disconnect becomes unavailable');
 }finally{
  if(browser)await browser.close();if(server.listening)await new Promise(resolve=>server.close(resolve));
  if(!exited){helper.stdin.end('stop\n');const timer=setTimeout(()=>helper.kill('SIGKILL'),5000);await helperExit;clearTimeout(timer);}
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
