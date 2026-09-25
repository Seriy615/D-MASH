'use strict';
const assert=require('node:assert/strict');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const url=process.env.DMASH_REMOTE_V4_URL,nodeId=process.env.DMASH_REMOTE_NODE_ID;
if(!/^wss:\/\//.test(url||'')||!/^[0-9a-f]{64}$/.test(nodeId||''))throw Error('Explicit WSS URL and pinned NodeID required');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 try{
  const page=await browser.newPage();
  await page.exposeFunction('remoteStage',stage=>console.log(stage));
  const base=process.env.DMASH_PWA_URL||'https://messenger.d-mash.ru/not_messenger/';
  await page.goto(base);
  for(const name of ['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','vendor/argon2-bundled.min.js','device_root.js','node_runtime_host_v4.js'])await page.addScriptTag({url:new URL('js/'+name,base).href});
  const result=await page.evaluate(async({url,nodeId})=>{
   if(window.Core?.keys)throw Error('Account unexpectedly unlocked');
   let identity;
   for(let attempt=0;attempt<2;attempt++){
    await DeviceRoot.unlock('Remote-Worker-test-only-2026');
    await window.remoteStage('DeviceRoot unlocked: attempt '+(attempt+1));
    const host=await DmashNodeRuntimeHostV4.startForDevice(DeviceRoot);
    if(identity&&host.identity.nodeId!==identity)throw Error('Node identity changed');
    identity=host.identity.nodeId;
    await window.remoteStage('Node identity ready: attempt '+(attempt+1));
    await host.connect({url,nodeId});
    await window.remoteStage('Mutual WSS authorization ready: attempt '+(attempt+1));
    const stats=await host.stats();
    if(stats.peers!==1||stats.owned!==0||!stats.worker)throw Error('Invalid remote worker state');
    DeviceRoot.lock();
    let rejected=false;try{await host.stats();}catch(_){rejected=true;}
    if(!rejected)throw Error('Root lock did not close host');
    await new Promise(resolve=>setTimeout(resolve,1000));
   }
   return {connected:true,reconnected:true,locked:!DeviceRoot.state,noAccount:!window.Core?.keys};
  },{url,nodeId});
  assert.deepEqual(result,{connected:true,reconnected:true,locked:true,noAccount:true});
  console.log('PASS real public WSS v4: pinned NodeID, mutual Node authorization, Worker reconnect with persisted identity, root lock; no Account login');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
