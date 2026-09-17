const assert=require('node:assert/strict');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 try {
  const context=await browser.newContext({serviceWorkers:"block"}); const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')console.error(m.text());});
  await page.goto(process.argv[2]);await page.waitForFunction(()=>window.DmashChatPassword&&window.DmashSavedMessages);
  await page.evaluate(async()=>{
   if(!await sys.loadAllLibs()) throw Error('PWA loader failed');
   Core.activeIdentity='local-ui-fixture';Core.blindSalt=new Uint8Array(32).fill(17);
   Core.keys={pub_hex:'a'.repeat(64),sign:nacl.sign.keyPair()};
   await Storage.initGamma(new Uint8Array(32).fill(19));
   await Storage.savePeerGamma('b'.repeat(64),'Alice');
   // A stalled Node must not hide persisted contacts or block local chats.
   NodeManager.autoConnect=()=>new Promise(()=>{});Core.restoreAutomaticMeshRoutes=async()=>{};Core.syncNetwork=()=>{};
   for(const name of ['getMeshRoute','startProbe','submitEnvelope']) NodeManager[name]=()=>{throw Error('Saved message accessed transport: '+name);};
  await Core.launchWorkspace();clearInterval(Core.syncInterval);
 });
  assert.equal(await page.locator('.network-card').isVisible(),true,'network card is visible after account login');
  await page.getByRole('button',{name:'Настройки',exact:true}).click();
  await page.getByRole('button',{name:'УЗЛЫ И ПОДКЛЮЧЕНИЕ',exact:true}).click();
  assert.equal(await page.getByRole('heading',{name:'ПОДКЛЮЧЕНИЕ К УЗЛУ'}).count(),1,'account settings exposes node connection controls');
  await page.getByRole('button',{name:'НАЗАД',exact:true}).click();
  await page.getByRole('button',{name:'ЗАКРЫТЬ',exact:true}).click();
  assert.equal(await page.getByText('Alice',{exact:true}).count(),1,'existing contact is rendered after workspace launch');
  await page.getByText('Избранное',{exact:true}).click();
  await page.locator('#msgInput').fill('Private note UI');await page.getByText('SEND',{exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#log').textContent.includes('Private note UI'));
  await page.locator('#chat-header button').filter({hasText:'✎'}).click();
  await page.locator('#p-in').fill('Мои заметки');await page.locator('#p-ok').click();
  await page.waitForFunction(()=>document.querySelector('#chat-title').textContent.includes('ЗАМЕТКИ'));
  await page.locator('#chat-header button[title="Пароль чата"]').click();
  await page.locator('#p-in').fill('notes-password');await page.locator('#p-ok').click();
  await page.locator('#p-in').fill('notes-password');await page.locator('#p-ok').click();
  await page.waitForFunction(()=>Core.activePeerId===null);
  await page.getByText('Мои заметки',{exact:true}).click();
  assert.equal(await page.locator('#log').textContent(),'');
  await page.locator('#p-in').fill('notes-password');await page.locator('#p-ok').click();
  await page.waitForFunction(()=>document.querySelector('#log').textContent.includes('Private note UI'));
  await page.locator('#msgInput').fill('Protected note UI');await page.getByText('SEND',{exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#log').textContent.includes('Protected note UI'));
  const work=await page.evaluate(async()=>{
   const args={nodeId:'aa'.repeat(32),activationType:'DNSS',deviceTransportKey:'bb'.repeat(32),resource:new Uint8Array(16),expiresAt:Math.floor(Date.now()/1000)+900,difficulty:8};
   const proof=await DmashResourcePow.mineActivationPow(args);
   const expected=Array.from(DmashResourcePow.activationDigest(args.nodeId,args.activationType,args.deviceTransportKey,args.resource,proof.nonce,args.expiresAt),b=>b.toString(16).padStart(2,'0')).join('');
   const pending=DmashResourcePow.mineActivationPow({...args,difficulty:256}).catch(e=>e.message);
   await new Promise(r=>setTimeout(r,100));
   DmashResourcePow.cancelAll();
   return {valid:proof.digest===expected,cancelled:await pending};
  });
  assert.equal(work.valid,true);assert.equal(work.cancelled,'PoW cancelled');
  assert.deepEqual(errors,[]);console.log(JSON.stringify({passed:true,scenario:'contacts and local chats with stalled Node; visible node controls; password history; real PoW worker and cancellation; fixture Account'}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
