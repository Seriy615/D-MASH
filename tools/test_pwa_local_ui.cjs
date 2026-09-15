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
   NodeManager.autoConnect=async()=>{};Core.restoreAutomaticMeshRoutes=async()=>{};Core.syncNetwork=()=>{};
   for(const name of ['getMeshRoute','startProbe','submitEnvelope']) NodeManager[name]=()=>{throw Error('Saved message accessed transport: '+name);};
  await Core.launchWorkspace();clearInterval(Core.syncInterval);
 });
  assert.equal(await page.locator('.network-card').count(),1,'network card remains available after account login');
  await page.getByRole('button',{name:'Настройки',exact:true}).click();
  await page.getByRole('button',{name:'УЗЛЫ И ПОДКЛЮЧЕНИЕ',exact:true}).click();
  assert.equal(await page.getByRole('heading',{name:'ПОДКЛЮЧЕНИЕ К УЗЛУ'}).count(),1,'account settings exposes node connection controls');
  await page.getByRole('button',{name:'НАЗАД',exact:true}).click();
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
  assert.deepEqual(errors,[]);console.log(JSON.stringify({passed:true,scenario:'actual PWA loader, saved chat, rename, password setup/unlock and protected send; fixture Account'}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
