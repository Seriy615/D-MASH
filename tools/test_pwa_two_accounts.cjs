'use strict';
const assert = require('node:assert/strict');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
const base = process.argv[2] || 'https://messenger.d-mash.ru/not_messenger/';
(async () => {
 const browser = await chromium.launch({executablePath:process.env.DMASH_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 const pages=[]; const failures=[];
 const eventually=async(page,fn,arg,timeout=120000)=>{const end=Date.now()+timeout;while(Date.now()<end){if(await page.evaluate(fn,arg)) return;await page.waitForTimeout(500);}throw Error('Async state did not converge');};
 try {
  for (const name of ['Alice','Bob']) {
   const context=await browser.newContext(); const page=await context.newPage();pages.push(page);
   page.on('pageerror',error=>failures.push(name+': '+error.message));
   page.on('console',message=>{if(/WARN|ERR|failed/i.test(message.text())) console.log(name,message.text());});
   await page.goto(base);
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
   await pages[0].evaluate(async descriptor=>{Core.closeModal();await Core.sendPublicContactRequest(descriptor,'Alice','Two-browser acceptance');},descriptor);
   await eventually(pages[1],async()=>(await Core.getPendingContactRequestStore().list()).some(r=>r.status==='pending'));
   await pages[1].evaluate(async()=>{const request=(await Core.getPendingContactRequestStore().list()).find(r=>r.status==='pending');await Core.acceptPendingContactRequest(request.id,'Bob',Core.bytesToHex(Core.keys.sign.publicKey));});
   await Promise.all(pages.map((page,i)=>eventually(page,async peer=>Boolean((await Storage.getBox('blind_peers',await Storage.getAlias(peer,'L1')))?.kyberPub),packages[1-i].user_id,600000)));
   console.log('PASS public contact request/accept/confirm with real Account key bundles');
   await Promise.all(pages.map(page=>page.evaluate(()=>Core.closeModal())));
  } else {
   await Promise.all(pages.map((page,i)=>page.evaluate(async peer=>{Core.closeModal();await Core.addPeerFlow(JSON.stringify(peer));},packages[1-i])));
  }
  await Promise.all(pages.map((page,i)=>page.waitForFunction(peer=>Boolean(NodeManager.getMeshRoute(peer)),packages[1-i].user_id,{timeout:20000})));
  console.log('PASS pairing contacts persisted and local Device routes installed');
  await Promise.all(pages.map((page,i)=>page.evaluate(peer=>Core.selectPeer(peer),packages[1-i].user_id)));
  await pages[0].getByRole('button',{name:'ОБМЕНЯТЬСЯ КЛЮЧАМИ',exact:true}).click();
  console.log('Alice requested key exchange');
  await Promise.all(pages.map((page,i)=>eventually(page,async peer=>Boolean((await Storage.getBox('blind_secrets',await Storage.getAlias(peer,'L1')))?.staticShared),packages[1-i].user_id,600000)));
  console.log('PASS initial Account key exchange');
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
  await Promise.all(pages.map(page=>eventually(page,async()=>{
   const inbox=NodeManager.deviceInboxV3();await inbox.drain();
   for(const row of await inbox.store.all()) {const r=await inbox._open(row);if(r.record!=='pending'||r.policy?.scope!=='ACCOUNT')continue;
    const p=JSON.parse(r.envelope.account_payload);if(/^0[123]/.test(p.ciphertext||''))return false;
   }return true;
  })));
  console.log('PASS completed handshake controls retired from Device Inbox');
  assert.deepEqual(failures,[]);
 } catch(error) {
  for(let i=0;i<pages.length;i++) console.error('DIAGNOSTIC',i,await pages[i].evaluate(()=>({ui:document.body.innerText.slice(-1500),connections:[...NodeManager.connections.values()].map(c=>({state:c.state,dnss:c.dnssReadyState,error:c.error}))})).catch(()=>null));
  throw error;
 } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
