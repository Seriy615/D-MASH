'use strict';
const assert = require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
const base = process.argv[2] || 'https://messenger.d-mash.ru/not_messenger/';
(async () => {
 const browser = await chromium.launch({executablePath:process.env.DMASH_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,
  args:(process.env.DMASH_TEST_CALL==='1'||process.env.DMASH_TEST_MEDIA==='1')?['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream','--autoplay-policy=no-user-gesture-required']:[]});
 const pages=[]; const failures=[];
 const eventually=async(page,fn,arg,timeout=120000)=>{const end=Date.now()+timeout;while(Date.now()<end){if(await page.evaluate(fn,arg)) return;await page.waitForTimeout(500);}throw Error('Async state did not converge');};
 try {
  for (const name of ['Alice','Bob']) {
   const context=await browser.newContext({...(process.env.DMASH_TEST_CALL==='1'||process.env.DMASH_TEST_MEDIA==='1'?{permissions:['microphone','camera']}:{}),...(process.env.DMASH_TEST_PWA_ROOT?{serviceWorkers:'block'}:{})});
   if(process.env.DMASH_TEST_PWA_ROOT){
    const root=path.resolve(process.env.DMASH_TEST_PWA_ROOT);
    await context.route('**/not_messenger/**',async route=>{
     const suffix=decodeURIComponent(new URL(route.request().url()).pathname.split('/not_messenger/')[1]||'index.html'),file=path.resolve(root,suffix);
     if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile())return route.continue();
     const type={'.js':'application/javascript','.html':'text/html','.json':'application/json','.css':'text/css','.wasm':'application/wasm'}[path.extname(file)]||'application/octet-stream';
     return route.fulfill({path:file,contentType:type});
    });
   }
   const page=await context.newPage();pages.push(page);
   page.on('pageerror',error=>failures.push(name+': '+error.message));
   page.on('console',message=>{if(/WARN|ERR|failed/i.test(message.text())) console.log(name,message.text());});
   await page.goto(base);
   if (process.env.DMASH_EXPECT_RELEASE) {
    await page.waitForFunction(expected => window.DMASH_RELEASE?.id === expected, process.env.DMASH_EXPECT_RELEASE);
    await page.evaluate(() => navigator.serviceWorker.ready);
    await page.waitForFunction(() => Boolean(navigator.serviceWorker.controller));
    const worker = context.serviceWorkers()[0];
    assert.equal(await worker.evaluate(() => RELEASE_ID), process.env.DMASH_EXPECT_RELEASE, 'active SW generation must match the page');
   }
   const digits=async value=>{for(const digit of value) await page.getByRole('button',{name:digit,exact:true}).click();await page.getByRole('button',{name:'=',exact:true}).click();};
   await page.getByText('УСТАНОВКА MASTER-КОДА',{exact:true}).waitFor();await digits('3333');
   await page.getByText('УСТАНОВКА WIPE-КОДА',{exact:true}).waitFor();await digits('9876');
   await page.getByText('СИСТЕМА ГОТОВА',{exact:true}).waitFor();await page.waitForTimeout(1200);await digits('3333');
   await page.locator('#p1').fill('two-account-'+name+'-'+Date.now());
   await page.locator('#p2').fill('Browser-test-only-2026!');await page.getByRole('button',{name:'ВОЙТИ',exact:true}).click();
   await page.getByText('Избранное',{exact:true}).waitFor({timeout:30000});
   await page.getByRole('button',{name:'Настройки',exact:true}).click();
   await page.getByRole('button',{name:'УЗЛЫ И ПОДКЛЮЧЕНИЕ',exact:true}).click();
   await page.getByRole('button',{name:'ЗАПРОСИТЬ УЗЕЛ',exact:true}).click();
   console.log(name,'logged in; real EMS registration started');
  }
  await Promise.all(pages.map(page=>page.waitForFunction(()=>[...NodeManager.connections.values()].some(c=>c.dnssReadyState==='ready'),null,{timeout:600000})));
  console.log('PASS both Devices authenticated and DNSS registered');
  const packages=await Promise.all(pages.map(page=>page.evaluate(async()=>({type:'DMASH_PAIRING_V1',version:1,user_id:Core.bytesToHex(Core.keys.sign.publicKey),contribution:await Core.ensurePairingContribution()}))));
  if(process.env.DMASH_CONTACT_MODE==='public') {
   const descriptor=await pages[1].evaluate(async()=>{
    Core.closeModal();const route=await DeviceRoutes.issue({type:'public-contact',allowedAccounts:[]});
    await NodeManager.probeActivePublicDeviceRoutes();return {v:1,r:route.routeId,c:route.certificate};
   });
   if(process.env.DMASH_DROP_INITIAL_CONTACT==='1'){
    await pages[0].evaluate(()=>{const submit=NodeManager.submitDeviceEnvelopeV3.bind(NodeManager);window.initialContactDropped=0;
     NodeManager.submitDeviceEnvelopeV3=async(...args)=>{if(args[1]==='CONN_REQUEST'&&!window.initialContactDropped++){return {state:'NODE_ACCEPTED'};}return submit(...args);};});
   }
   await pages[0].evaluate(async descriptor=>{Core.closeModal();await Core.sendPublicContactRequest(descriptor,'Alice','Two-browser acceptance');},descriptor);
   if(process.env.DMASH_DROP_INITIAL_CONTACT==='1'){
    await eventually(pages[1],async()=>(await Core.getPendingContactRequestStore().list()).some(r=>r.status==='pending'));
    assert(await pages[0].evaluate(()=>window.initialContactDropped>=2));
    console.log('PASS dropped initial public request retransmitted autonomously from durable state');
   }
   if(process.env.DMASH_TEST_CONTACT_UI==='1'){
    await pages[0].evaluate(()=>{Core.closeModal();const flow=Core.getContactFlowV3();window.resumeContactAcceptance=flow.resume.bind(flow);flow.resume=async()=>({paused:true});});
    await pages[0].locator('#contact-list .contact-progress-item').waitFor({state:'visible',timeout:10000});
   }
   await eventually(pages[1],async()=>(await Core.getPendingContactRequestStore().list()).some(r=>r.status==='pending'));
   await pages[1].evaluate(async()=>{const request=(await Core.getPendingContactRequestStore().list()).find(r=>r.status==='pending');await Core.acceptPendingContactRequest(request.id,'Bob',Core.bytesToHex(Core.keys.sign.publicKey));});
   if(process.env.DMASH_TEST_CONTACT_UI==='1'){
    await pages[1].evaluate(()=>Core.closeModal());
    await pages[1].locator('#contact-list .contact-progress-item').waitFor({state:'visible',timeout:10000});
    await pages[0].evaluate(async()=>{Core.getContactFlowV3().resume=window.resumeContactAcceptance;delete window.resumeContactAcceptance;await Core.getContactFlowV3().resume();});
    console.log('PASS outgoing and accepted public requests remain visible while remote confirmation is held');
   }
   await Promise.all(pages.map((page,i)=>eventually(page,async peer=>Boolean((await Storage.getBox('blind_peers',await Storage.getAlias(peer,'L1')))?.kyberPub),packages[1-i].user_id,600000)));
   console.log('PASS public contact request/accept/confirm with real Account key bundles');
   await Promise.all(pages.map(page=>page.evaluate(()=>Core.closeModal())));
  } else if(process.env.DMASH_LATE_PAIRING==='1') {
   await pages[0].evaluate(async peer=>{Core.closeModal();await Core.addPeerFlow(JSON.stringify(peer));},packages[1]);
   const earlyRoute=await pages[0].evaluate(async peer=>{
    const pair=await PrivateRoutesV3.pair(await Core.ensurePairingContribution(),peer.contribution);
    try{return pair.backRouteLocator;}finally{pair.close();}
   },packages[1]);
   await eventually(pages[0],async route=>Boolean(await NodeManager.routeStatus(route)),earlyRoute,600000);
   assert.equal(await pages[1].evaluate(peer=>Boolean(NodeManager.getMeshRoute(peer)),packages[0].user_id),false);
   console.log('PASS early route advertisement at Entry before Bob imports pairing package');
   await pages[1].evaluate(async peer=>{Core.closeModal();await Core.addPeerFlow(JSON.stringify(peer));},packages[0]);
  } else {
   await Promise.all(pages.map((page,i)=>page.evaluate(async peer=>{Core.closeModal();await Core.addPeerFlow(JSON.stringify(peer));},packages[1-i])));
  }
  await Promise.all(pages.map((page,i)=>page.waitForFunction(peer=>Boolean(NodeManager.getMeshRoute(peer)),packages[1-i].user_id,{timeout:20000})));
  console.log('PASS pairing contacts persisted and local Device routes installed');
  if(process.env.DMASH_TEST_CONTACT_UI==='1'){
   for(let i=0;i<pages.length;i++){
    const peer=packages[1-i].user_id;
    const name=await pages[i].evaluate(async peer=>(await Storage.getBox('blind_peers',await Storage.getAlias(peer,'L1'))).name,peer);
    const item=pages[i].locator('#contact-list .peer-item').filter({hasText:name});
    await item.waitFor({state:'visible',timeout:30000});await item.click();
    await pages[i].waitForFunction(peer=>Core.activePeerId===peer,peer);
   }
   console.log('PASS both contacts visible in sidebar and chat opens through an actual click');
  }else await Promise.all(pages.map((page,i)=>page.evaluate(peer=>Core.selectPeer(peer),packages[1-i].user_id)));
  await pages[0].getByRole('button',{name:'ОБМЕНЯТЬСЯ КЛЮЧАМИ',exact:true}).click();
  console.log('Alice requested key exchange');
  await Promise.all(pages.map((page,i)=>eventually(page,async peer=>Boolean((await Storage.getBox('blind_secrets',await Storage.getAlias(peer,'L1')))?.staticShared),packages[1-i].user_id,600000)));
  console.log('PASS initial Account key exchange');
  await Promise.all(pages.map((page,i)=>page.evaluate(async peer=>{
   const messages=await Storage.loadMessagesGamma(peer,50,0);
   if(messages.some(m=>m.text?.type==='pqc_confirm'))throw Error('Handshake confirmation entered user history');
  },packages[1-i].user_id)));
  console.log('PASS handshake confirmations excluded from user history');
  const send=async(index,text,wait=true)=>{
   await pages[index].evaluate(async peer=>{Core.closeModal();await Core.selectPeer(peer);},packages[1-index].user_id);
   await pages[index].locator('#msgInput').fill(text);await pages[index].getByRole('button',{name:'SEND',exact:true}).click();
   if(wait) await eventually(pages[1-index],async ({peer,text})=>(await Storage.loadMessagesGamma(peer,50,0)).some(m=>m.inbound&&m.text===text),{peer:packages[index].user_id,text});
  };
  await send(0,'Alice to Bob before ratchet');await send(1,'Bob to Alice before ratchet');console.log('PASS bidirectional messages before ratchet update');
  for(const epoch of [1,2]) {
   const delayed=epoch===2?await pages[0].evaluate(async peer=>{
    const ciphertext=await Core.encrypt(JSON.stringify({type:'dmash_message',id:crypto.randomUUID(),body:'Delayed epoch-one packet'}),peer);
    return {version:1,packet_id:crypto.randomUUID(),ciphertext,sender_proof:Core.bytesToHex(nacl.sign.detached(Core.hexToBytes(ciphertext),Core.keys.sign.secretKey))};
   },packages[1].user_id):null;
   await pages[(epoch-1)%2].evaluate(()=>Core.initHandshake());
   await Promise.all(pages.map((page,i)=>eventually(page,async ({peer,epoch})=>{const s=await Storage.getBox('blind_secrets',await Storage.getAlias(peer,'L1'));return s?.ratchetEpoch===epoch&&!s.ratchetPending;},{peer:packages[1-i].user_id,epoch})));
   if(delayed) {
    await pages[0].evaluate(({peer,envelope})=>NodeManager.submitEnvelope(NodeManager.getMeshRoute(peer).routeLocator,envelope),{peer:packages[1].user_id,envelope:delayed});
    await eventually(pages[1],async peer=>(await Storage.loadMessagesGamma(peer,50,0)).some(m=>m.inbound&&m.text==='Delayed epoch-one packet'),packages[0].user_id);
    console.log('PASS delayed prior-epoch packet after initiator ACK');
   }
   await send(0,'Alice to Bob epoch '+epoch);await send(1,'Bob to Alice epoch '+epoch);console.log('PASS ratchet epoch '+epoch+' and bidirectional messages');
  }
  await pages[1].evaluate(()=>NodeManager.disconnect(false));
  await send(0,'Queued while Bob disconnected',false);
  await pages[1].evaluate(()=>NodeManager.connect());
  await eventually(pages[1],async peer=>(await Storage.loadMessagesGamma(peer,50,0)).some(m=>m.inbound&&m.text==='Queued while Bob disconnected'),packages[0].user_id);
  console.log('PASS recipient reconnect and queued message delivery');
  if(process.env.DMASH_TEST_MEDIA==='1'){
   for(const [index,type] of [[0,'voice'],[1,'video_note']]){
    const peer=packages[1-index].user_id;
    await pages[index].evaluate(async({peer,type})=>{
     Core.closeModal();await Core.selectPeer(peer);
     if(!window.DmashAccountRecordedMedia)throw Error('Recorded-note module missing');
     if(type==='voice')await Core.uiVoice();else await Core.startCircleRecording(null);
     if(!Core.isRecording)throw Error('Actual recording UI did not start');
    },{peer,type});
    await pages[index].waitForTimeout(type==='voice'?1200:3500);
    await pages[index].getByRole('button',{name:'SEND',exact:true}).click();
    await eventually(pages[index],async({peer,type})=>(await Storage.loadMessagesGamma(peer,50,0)).some(m=>!m.inbound&&m.text?.type===type),{peer,type});
    const source=await pages[index].evaluate(async({peer,type})=>{
     const row=(await Storage.loadMessagesGamma(peer,50,0)).find(m=>!m.inbound&&m.text?.type===type);
     return {wireId:row.wireId,length:row.text.data.length};
    },{peer,type});
    if(type==='video_note')assert(source.length>32768,'actual video must exceed a single Device frame');
    await eventually(pages[1-index],async({peer,type})=>(await Storage.loadMessagesGamma(peer,50,0)).some(m=>m.inbound&&m.text?.type===type),{peer:packages[index].user_id,type},600000);
    await pages[1-index].evaluate(async({peer,type})=>{
     const rows=(await Storage.loadMessagesGamma(peer,50,0)).filter(m=>m.inbound&&m.text?.type===type);
     if(rows.length!==1)throw Error('Recorded-note history duplicated');
     const stub=document.createElement('div');stub.id='stub-media-acceptance';document.body.appendChild(stub);
     await Core.decryptMedia('media-acceptance',rows[0].text);
     const player=stub.querySelector(type==='voice'?'audio':'video');if(!player)throw Error('Receiving player absent');
     await player.play();await new Promise(resolve=>setTimeout(resolve,300));
     if(!(player.currentTime>0))throw Error('Received recording playback did not advance');player.pause();stub.remove();
    },{peer:packages[index].user_id,type});
    await eventually(pages[index],async peer=>!(await Storage.getAllBoxes('blind_outbox')).some(row=>row.record==='media_outbound'&&row.peerID===peer&&row.status!=='failed'),peer);
    console.log('PASS actual recorded '+type+': '+source.length+' encoded bytes through EMS, single receiving history, playable Blob and durable final receipt');
   }
  }
  if(process.env.DMASH_TEST_CALL==='1'){
   for(const page of pages)await page.evaluate(()=>{
    Core.closeModal();const Native=window.RTCPeerConnection;
    window.RTCPeerConnection=class extends Native{constructor(config){super({...config,iceTransportPolicy:'relay'});}};
   });
   await pages[0].locator('#voip-btn').click();
   await pages[1].locator('#accept-call').waitFor({state:'visible',timeout:90000});
   await pages[1].locator('#accept-call').click();
   await Promise.all(pages.map(page=>page.waitForFunction(()=>Core.callState==='connected'&&Core.peerConnection?.connectionState==='connected',null,{timeout:60000})));
   for(const page of pages)await eventually(page,async()=>{
    const stats=await Core.peerConnection.getStats();let pair,received=false;
    for(const row of stats.values()){
     if(row.type==='transport'&&row.selectedCandidatePairId)pair=stats.get(row.selectedCandidatePairId);
     if(row.type==='inbound-rtp'&&(row.kind==='audio'||row.mediaType==='audio')&&row.bytesReceived>0)received=true;
    }
    if(!pair)return false;
    return received&&stats.get(pair.localCandidateId)?.candidateType==='relay'&&stats.get(pair.remoteCandidateId)?.candidateType==='relay';
   });
   console.log('PASS real public call UI: encrypted Account invitation, authenticated signaling, temporary TURN credentials, forced relay both sides and inbound audio RTP');
   await pages[0].evaluate(()=>Core.endCall());
   await eventually(pages[1],()=>Core.callState==='idle');
  }
  await Promise.all(pages.map(page=>eventually(page,async()=>{
   const inbox=NodeManager.deviceInboxV3();await inbox.drain();
   for(const row of await inbox.store.all()) {const r=await inbox._open(row);if(r.record!=='pending'||r.policy?.scope!=='ACCOUNT')continue;
    const p=JSON.parse(r.envelope.account_payload);if(/^0[123]/.test(p.ciphertext||''))return false;
   }return true;
  })));
  console.log('PASS completed handshake controls retired from Device Inbox');
  if(process.env.DMASH_TEST_DELETE==='1'){
   await pages[0].evaluate(async peer=>{
    const route=NodeManager.getMeshRoute(peer),confirm=Core.customConfirm,alert=Core.customAlert;
    let task,outcome;const remove=NodeManager.removeMeshRoute.bind(NodeManager);
    NodeManager.removeMeshRoute=async id=>{outcome=await remove(id);return outcome;};
    Core.customConfirm=(_title,_message,action)=>{task=action();};Core.customAlert=()=>{};
    try{
     Core.deleteChatFlow(peer,'Acceptance contact');await task;
     if(!outcome?.nodeRemoved)throw Error('Entry did not confirm private route revocation');
     if(NodeManager.getMeshRoute(peer))throw Error('Deleted route remained in local config');
     if(await NodeManager.deviceInboxV3().policyByAlias(route.backRouteLocator))throw Error('Deleted local delivery policy remained');
     if(await Storage.getBox('blind_peers',await Storage.getAlias(peer,'L1')))throw Error('Deleted contact remained in vault');
     if((await Storage.loadMessagesGamma(peer,50,0)).length)throw Error('Deleted history remained');
    }finally{NodeManager.removeMeshRoute=remove;Core.customConfirm=confirm;Core.customAlert=alert;}
   },packages[1].user_id);
   console.log('PASS signed private contact deletion: Entry confirmation, local delivery policy, peer/history and route removal');
  }
  assert.deepEqual(failures,[]);
 } catch(error) {
  for(let i=0;i<pages.length;i++) console.error('DIAGNOSTIC',i,await pages[i].evaluate(()=>({accountUnlocked:Boolean(window.Core?.keys),deviceUnlocked:Boolean(window.DeviceRoot?.state?.root),routeCount:Object.keys(NodeManager.getRouteConfig()).length,pendingRequests:NodeManager.pendingRequests.size,connections:[...NodeManager.connections.values()].map(c=>({state:c.state,dnss:c.dnssReadyState,hasError:Boolean(c.error)}))})).catch(()=>null));
  throw error;
 } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
