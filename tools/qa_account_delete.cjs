'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),cp=require('node:child_process');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'/tmp/dmash-browser-tools/node_modules/playwright');
(async()=>{
 const fixed=process.env.DMASH_DELETE_MODE==='fixed',resume=process.env.DMASH_QA_RESUME==='1',root=path.resolve(process.env.DMASH_TEST_PWA_ROOT||'D-MASH PWA/not_messenger');
 const profile=process.env.DMASH_QA_PROFILE||'/tmp/dmash-account-delete-synthetic-'+Date.now(),output=process.env.DMASH_QA_OUTPUT||'/tmp/qa-account-delete.json';
 const report={scope:'BROWSER actual UI, synthetic Accounts only; full source overlay, no Node connection',baseSHA:cp.execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),mode:fixed?'fail-closed retest':'baseline',steps:[],sourceHashes:{},pageErrors:[],limits:['No physical secure erase claim','No user profiles accessed','Readonly encrypted-database hashes supplement actual clicks']};
 const context=await chromium.launchPersistentContext(profile,{headless:true,serviceWorkers:'block',executablePath:process.env.DMASH_CHROME||'/home/jcode/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome'});report.browser=context.browser().version();
 await context.route('**/not_messenger/**',async route=>{const suffix=decodeURIComponent(new URL(route.request().url()).pathname.split('/not_messenger/')[1]||'index.html'),file=path.resolve(root,suffix);if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile())return route.continue();report.sourceHashes[suffix]=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');return route.fulfill({path:file,contentType:({'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css','.wasm':'application/wasm','.json':'application/json'})[path.extname(file)]||'application/octet-stream'});});
 const page=context.pages()[0]||await context.newPage();page.setDefaultTimeout(15000);page.on('pageerror',e=>report.pageErrors.push(e.message));const save=()=>fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');const click=label=>page.getByRole('button',{name:label,exact:true}).click();
 const step=async(id,fn)=>{try{await fn();report.steps.push({id,status:'PASS'});}catch(e){report.steps.push({id,status:'FAIL',error:e.message.split('\n')[0]});throw e;}finally{save();}};
 const digits=async value=>{for(const d of value)await click(d);await click('=');};const names=['synthetic-delete-a','synthetic-delete-b'],password='Synthetic-delete-only-2026!';const saved=()=>page.locator('#contact-list').getByText('Избранное',{exact:true});
 const enter=async(name,pass=password)=>{await page.locator('#p1').fill(name);await page.locator('#p2').fill(pass);await click('ВОЙТИ');};
 const history=async i=>{await saved().click({timeout:60000});await page.locator('#log .m-txt').filter({hasText:'Synthetic deletion history '+i}).waitFor();};
 const manager=async()=>{await page.locator('#global-settings-button').click();await page.locator('button[onclick="Core.openAccountManager()"]').click();};
 const remove=()=>page.locator('button[onclick*="removeAccountFlow"][onclick*="synthetic-delete-b"]');
 const snapshot=()=>page.evaluate(async()=>{const result={};for(const meta of await indexedDB.databases()){const db=await new Promise((resolve,reject)=>{const q=indexedDB.open(meta.name);q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);});const stores={};try{for(const name of db.objectStoreNames){const rows=await new Promise((resolve,reject)=>{const q=db.transaction(name).objectStore(name).getAll();q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);});stores[name]={count:rows.length,hash:Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(rows)))),b=>b.toString(16).padStart(2,'0')).join('')};}}finally{db.close();}result[meta.name]=stores;}return result;});
 try{
  await page.goto('https://messenger.d-mash.ru/not_messenger/');report.page=await page.evaluate(()=>DMASH_RELEASE.id);report.sw='BLOCKED full source overlay';
  if(!resume){await page.getByText('УСТАНОВКА MASTER-КОДА',{exact:true}).waitFor();await digits('3333');await page.getByText('УСТАНОВКА WIPE-КОДА',{exact:true}).waitFor();await digits('9876');await page.getByText('СИСТЕМА ГОТОВА',{exact:true}).waitFor();await page.waitForTimeout(1300);}
  await digits('3333');if(!resume)await page.locator('#p1').waitFor();else await page.locator('#global-settings-button').waitFor();
  if(!resume)for(let i=0;i<2;i++)await step('create-save-history-'+i,async()=>{if(i){await click('[ ВЫХОД ]');await click('+ НОВЫЙ ВХОД');}await page.locator('#save-in-registry').check();await enter(names[i]);await saved().click({timeout:60000});await page.locator('#msgInput').fill('Synthetic deletion history '+i);await click('SEND');await page.locator('#log .m-txt').filter({hasText:'Synthetic deletion history '+i}).waitFor();});
  if(!resume)await click('[ ВЫХОД ]');
  await step('account-manager-two-accounts',async()=>{await manager();await page.waitForFunction(()=>document.querySelectorAll('button[onclick*="removeAccountFlow"]').length===2);});
  report.before=await snapshot();
  if(!fixed){
   await step('delete-cancel-preserves',async()=>{await remove().click();await page.getByText(/Вся история будет стерта/).waitFor();await click('ОТМЕНА');await page.locator('button[onclick="Core.openAccountManager()"]').click();await page.waitForFunction(()=>document.querySelectorAll('button[onclick*="removeAccountFlow"]').length===2);assert.deepEqual(await snapshot(),report.before);});
   await step('delete-confirm-removes-registry',async()=>{await remove().click();await page.locator('#p-in').fill('УДАЛИТЬ');await page.locator('#p-ok').click();await page.waitForFunction(()=>document.querySelectorAll('button[onclick*="removeAccountFlow"]').length===1);report.after=await snapshot();});
  }else{
   await step('delete-refused-truthfully-no-mutation',async()=>{await remove().click();await page.getByText('УДАЛЕНИЕ НЕДОСТУПНО',{exact:true}).waitFor();await page.getByText(/ключи и история сохранены/).waitFor();assert.equal(await page.locator('#p-in').count(),0);assert.deepEqual(await snapshot(),report.before);await click('OK');});
   await step('registry-pin-remains',async()=>{await page.locator('button[onclick="Core.openAccountManager()"]').click();await page.waitForFunction(()=>document.querySelectorAll('button[onclick*="removeAccountFlow"]').length===2);});
  }
  await click('НАЗАД');await click('НАЗАД К АККАУНТАМ');await click('+ НОВЫЙ ВХОД');
  if(fixed)await step('same-name-wrong-key-refused',async()=>{await enter(names[1],'Wrong-Synthetic-deletion-key');await page.waitForFunction(()=>document.getElementById('gate-status-text')?.textContent.includes('ОШИБКА'),null,{timeout:60000});assert(await page.locator('#p2').isVisible());});
  await step(fixed?'same-name-correct-key-history-preserved':'same-name-recreation-old-history-visible',async()=>{await page.locator('#save-in-registry').check();await enter(names[1]);await history(1);});
  if(!fixed)report.productBug={id:'ACCOUNT-DELETE-01',status:'FAIL reproduced',claim:'UI promises full history/key erasure',actual:'Same-name credential recreation shows original history'};
  await step('other-account-history-preserved',async()=>{await click('[ ВЫХОД ]');await click(names[0]);await page.locator('#p2').fill(password);await click('ВОЙТИ');await history(0);assert.equal(await page.locator('#log .m-txt').filter({hasText:'Synthetic deletion history 1'}).count(),0);});
  await click('[ ВЫХОД ]');assert.equal(report.pageErrors.length,0);
 }catch(e){report.fatal=e.message.split('\n')[0];}finally{save();await context.close();}
 console.log(JSON.stringify({mode:report.mode,steps:report.steps,productBug:report.productBug,fatal:report.fatal}));process.exitCode=report.fatal?1:0;
})();
