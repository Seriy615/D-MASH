'use strict';
// Continuation of actual .30 two-profile UI pairing/history. No console setup.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
module.exports=async function({pages,accounts,report,step,click,snap,save,fresh=false,resumeConnected=false}){
 report.scope=fresh?'Actual full-shell fresh Node public controls before Account login, N4 and text; no V3 pairing fallback':'Actual legacy baseline then same-profile explicit Node migration; history and identities preserved';
 const root=path.resolve(process.env.DMASH_NODE_CANDIDATE_ROOT||'');if(!fs.existsSync(path.join(root,'js/node_account_ui_v4.js')))throw Error('Candidate source required');
 const fileMap=new Map();function scan(dir){for(const d of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,d.name);if(d.isDirectory())scan(file);else fileMap.set(path.relative(root,file),fs.readFileSync(file));}}scan(root);
 const digest=bytes=>crypto.createHash('sha256').update(bytes).digest('hex'),observed=[],tasks=[],baseline=[];report.nodeCandidate={sw:'BLOCKED',loaded:observed,scope:'Partial actual UI candidate audit; no PASS until final assertions'};
 for(const page of pages)baseline.push(await page.evaluate(async()=>{const hash=async value=>Core.bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(value))))),session=Core.captureAccountSessionV4(),peer=Core.activePeerId;const read=store=>new Promise((resolve,reject)=>{const tx=session.db.transaction(store),r=tx.objectStore(store).getAll();r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});return {account:Core.bytesToHex(Core.keys.sign.publicKey),peer,messageHash:await hash(await read('blind_messages')),secretHash:await hash(await read('blind_secrets'))};}));
 if(!resumeConnected)for(const [i,page]of pages.entries())await step('node-candidate-same-profile-'+i,page,async()=>{
  await page.context().unroute('**/not_messenger/**');await page.context().route('**/not_messenger/**',async route=>{const rel=decodeURIComponent(new URL(route.request().url()).pathname.split('/not_messenger/')[1]||'index.html'),bytes=fileMap.get(rel);if(!bytes)return route.abort();await route.fulfill({body:bytes,contentType:{'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.wasm':'application/wasm'}[path.extname(rel)]||'application/octet-stream'});});
  page.on('response',response=>{const rel=decodeURIComponent(new URL(response.url()).pathname.split('/not_messenger/')[1]||'index.html');if(!fileMap.has(rel)||!(/\.js$/.test(rel)||rel==='index.html'))return;tasks.push(response.body().then(bytes=>observed.push({profile:i,path:rel,match:digest(bytes)===digest(fileMap.get(rel)),actualSha256:digest(bytes),expectedSha256:digest(fileMap.get(rel))})));});
  await page.reload();for(const d of '3333')await click(page,d);await click(page,'=');await click(page,accounts[i]);await page.locator('#p2').fill('Synthetic-only-2026!');await click(page,'ВОЙТИ');await page.getByText('Избранное',{exact:true}).waitFor({timeout:90000});assert(await page.evaluate(old=>Core.bytesToHex(Core.keys.sign.publicKey)===old,baseline[i].account));
  await click(page,'Настройки');await click(page,'КОНТАКТЫ NODE');await click(page,'Подключить Node');await page.getByText('Node подключена',{exact:true}).waitFor({timeout:180000});
 });
 const [a,b]=pages;let address;
 await step('node-public-address',b,async()=>{await click(b,'Создать / показать публичный адрес');await b.getByText('Публичный адрес готов. Он не раскрывает выбранный аккаунт.',{exact:true}).waitFor();await click(b,'Копировать публичный адрес');await b.getByText('Адрес скопирован',{exact:true}).waitFor();address=await b.evaluate(()=>navigator.clipboard.readText());assert.equal(JSON.parse(address).type,'DMASH_PUBLIC_NODE_V4');});
 if(fresh)await step('node-recipient-logout-keeps-root',b,async()=>{await click(b,'ЗАКРЫТЬ');await click(b,'[ ВЫХОД ]');await b.locator('#global-settings-button').click();await click(b,'КОНТАКТЫ NODE');await click(b,'Подключить Node');await b.getByText('Node подключена',{exact:true}).waitFor();assert(await b.evaluate(()=>!Core.keys?.sign));});
 await step('node-neutral-request',a,async()=>{await a.getByLabel('Публичный адрес Node',{exact:true}).fill(address);await a.getByLabel('Ваше имя для запроса',{exact:true}).fill('Migration Alice');await a.getByLabel('Сообщение для знакомства',{exact:true}).fill('Preserve existing conversation');await click(a,'Отправить запрос');});
 const until=async(page,label,timeout=180000)=>{const end=Date.now()+timeout;for(;;){if(await page.getByRole('button',{name:label,exact:true}).isVisible())return;if(Date.now()>end)throw Error('Visible Node action timeout: '+label);await click(page,'Обновить запросы');await page.waitForTimeout(500);}};
 if(fresh)await step('node-neutral-visible-before-account',b,async()=>{await until(b,'Выбрать аккаунт для принятия');assert(await b.evaluate(()=>!Core.keys?.sign));await click(b,'Выбрать аккаунт для принятия');await click(b,accounts[1]);await b.locator('#p2').fill('Synthetic-only-2026!');await click(b,'ВОЙТИ');await b.getByText('Избранное',{exact:true}).waitFor({timeout:90000});await click(b,'Настройки');await click(b,'КОНТАКТЫ NODE');await click(b,'Подключить Node');await b.getByText('Node подключена',{exact:true}).waitFor();});
 await step('node-existing-accept',b,async()=>{await until(b,'Принять в текущий аккаунт');await click(b,'Принять в текущий аккаунт');});
 await step('node-existing-confirm',a,async()=>{await until(a,'Подтвердить собеседника');assert((await a.locator('body').innerText()).includes(fresh?baseline[1].account:baseline[0].peer));await click(a,'Подтвердить собеседника');});
 // Each participant progresses independently: waiting for A's route must not
 // prevent B from retrying its already-signed public receipt completion.
 await Promise.all(pages.map((page,i)=>step('node-complete-key-exchange-'+i,page,async()=>{
  const end=Date.now()+180000;
  for(;;){
   if(await page.getByText('Ключи подтверждены',{exact:true}).isVisible())return;
   if(Date.now()>end)throw Error('Visible N4 confirmation deadline participant '+i);
   const button=page.getByRole('button',{name:'Завершить обмен ключами',exact:true});
   if(await button.evaluateAll(es=>es.some(e=>e.getClientRects().length&&!e.disabled)))await button.click();
   else if(!await button.isVisible())await click(page,'Обновить запросы');
   await page.waitForTimeout(500);
  }
 })));
 report.confirmedSessions=[];
 for(const [i,page]of pages.entries()){
  const result=await page.evaluate(async peer=>{const adapter=await Core._publicAccountNodeV4.promise,status=await adapter.sessionStatus(peer);return {established:status.phase==='ESTABLISHED',routeReady:status.sessionEstablished===true};},baseline[1-i].account);
  assert(result.established&&result.routeReady,'Visible completion must match genuine N4/Host proof');report.confirmedSessions.push(result);
 }
 if(!fresh){
 for(const [i,page]of pages.entries())await step('node-authenticated-migration-'+i,page,async()=>{await click(page,'Перевести существующий контакт на Node');await click(page,'ДА');await page.locator('[data-node-account-panel]').waitFor({state:'hidden'});const unchanged=await page.evaluate(async old=>{const session=Core.captureAccountSessionV4(),hash=async value=>Core.bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(value))))),read=store=>new Promise((resolve,reject)=>{const tx=session.db.transaction(store),r=tx.objectStore(store).getAll();r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});const peer=await Storage.getBox('blind_peers',await Storage.getAlias(old.peer,'L1'));return {identity:Core.bytesToHex(Core.keys.sign.publicKey)===old.account,messages:await hash(await read('blind_messages'))===old.messageHash,secrets:await hash(await read('blind_secrets'))===old.secretHash,managed:peer.transportProfile==='NODE_ACCOUNT_V4'};},baseline[i]);assert(Object.values(unchanged).every(Boolean),JSON.stringify(unchanged));report['migrationPreserved'+i]=unchanged;await page.locator('#contact-list .peer-item').filter({hasNotText:'Избранное'}).first().click();await page.locator('#log .m-txt').filter({hasText:'UI contact message 0'}).waitFor();await page.locator('#log .m-txt').filter({hasText:'UI contact message 1'}).waitFor();});
 }else{for(const page of pages){await click(page,'ЗАКРЫТЬ');await page.locator('#contact-list .peer-item').filter({hasNotText:'Избранное'}).first().click();}}
 for(const [i,page]of pages.entries())await step('node-send-text-'+i,page,async()=>{const text='Node migrated text '+i;await page.locator('#msgInput').fill(text);await click(page,'SEND');await pages[1-i].locator('#log .m-txt').filter({hasText:text}).waitFor({timeout:180000});});
 await Promise.all(tasks);assert(!report.errors.length,JSON.stringify(report.errors));assert((resumeConnected||observed.length)&&observed.every(r=>r.match));report.nodeCandidate={release:await a.evaluate(()=>DMASH_RELEASE.id),sw:'BLOCKED',loaded:observed,scope:fresh?'Actual full-shell fresh Node public pairing/text; E2EE ACK separate':'Actual full-shell same-profile migration/text; E2EE ACK separate'};save();await snap(a,'node-candidate-migrated-text');
};
