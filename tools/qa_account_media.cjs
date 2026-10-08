'use strict';
// Browser-first audit: synthetic fresh profile, actual UI actions only.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'/tmp/dmash-browser-tools/node_modules/playwright');
const output=path.resolve(process.env.DMASH_QA_OUTPUT||'docs/evidence/2026-10-08/qa-account-media.json');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.DMASH_CHROME||undefined,args:['--no-sandbox','--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']});
 const overlay=process.env.DMASH_TEST_PWA_ROOT;const context=await browser.newContext({permissions:['microphone','camera'],...(overlay?{serviceWorkers:'block'}:{})});const page=await context.newPage();page.setDefaultTimeout(12000);
 const report={time:new Date().toISOString(),target:'https://messenger.d-mash.ru/not_messenger/',limitations:['Fresh synthetic Account only','No real user storage','Local Saved Messages audit; remote media matrix separately required'],steps:[],inventory:[]};
 if(overlay){
  const root=path.resolve(overlay);
  report.source={kind:'uncommitted full PWA source overlay',baseSHA:require('node:child_process').execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),files:{}};
  await context.route('**/not_messenger/**',async route=>{
   const suffix=decodeURIComponent(new URL(route.request().url()).pathname.split('/not_messenger/')[1]||'index.html');
   const file=path.resolve(root,suffix);
   if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile())return route.continue();
   report.source.files[suffix]=require('node:crypto').createHash('sha256').update(fs.readFileSync(file)).digest('hex');
   const contentType={'.js':'application/javascript','.html':'text/html','.css':'text/css','.json':'application/json','.wasm':'application/wasm'}[path.extname(file)]||'application/octet-stream';
   return route.fulfill({path:file,contentType});
  });
 }

 const save=()=>fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
 const inventory=async(state)=>report.inventory.push({state,controls:await page.locator('button,input,textarea,[onclick]').evaluateAll(es=>es.filter(e=>e.getClientRects().length).map(e=>({tag:e.tagName,id:e.id,label:(e.getAttribute('aria-label')||e.textContent||e.getAttribute('placeholder')||'').trim().slice(0,100),type:e.type,disabled:e.disabled,onclick:e.getAttribute('onclick')})))});
 const step=async(id,action,fn)=>{try{await fn();report.steps.push({id,action,status:'PASS'});}catch(e){report.steps.push({id,action,status:'FAIL',error:e.message.split('\n')[0],visibleText:(await page.locator('body').innerText()).replace(/[0-9a-f]{16,}/g,'[REDACTED]').slice(-3500)});}save();};
 const click=label=>page.getByRole('button',{name:label,exact:true}).click();
 const prompt=async(value)=>{await page.locator('#p-in').fill(value);await page.locator('#p-ok').click();};
 try{
 await page.goto(report.target);if(!overlay){await page.evaluate(()=>navigator.serviceWorker.ready);await page.waitForFunction(()=>!!navigator.serviceWorker.controller);}
 report.page=await page.evaluate(()=>window.DMASH_RELEASE?.id);report.sw=overlay?'BLOCKED: uncommitted source overlay':await context.serviceWorkers()[0].evaluate(()=>RELEASE_ID);report.browser=browser.version();
 const digits=async(s)=>{for(const d of s)await click(d);await click('=');};
 await page.getByText('УСТАНОВКА MASTER-КОДА',{exact:true}).waitFor();await digits('3333');await page.getByText('УСТАНОВКА WIPE-КОДА',{exact:true}).waitFor();await digits('9876');await page.getByText('СИСТЕМА ГОТОВА',{exact:true}).waitFor();await page.waitForTimeout(1300);await digits('3333');await page.locator('#p1').waitFor();
 await inventory('Account login');
 await step('UI02-empty','Click ВОЙТИ with empty fields',async()=>{await click('ВОЙТИ');assert(await page.locator('#p1').isVisible());});
 const account='qa-local-'+Date.now();const password='Synthetic-only-2026!';
 await step('UI02-create','Fill fresh Account credentials, check registry and click ВОЙТИ',async()=>{await page.locator('#p1').fill(account);await page.locator('#p2').fill(password);await page.locator('#save-in-registry').check();await click('ВОЙТИ');await page.locator('#contact-list').getByText('Избранное',{exact:true}).waitFor({timeout:60000});});
 await inventory('Workspace');
 await step('UI09-open','Click Избранное',async()=>{await page.locator('#contact-list').getByText('Избранное',{exact:true}).click();await page.locator('#msgInput').waitFor({state:'visible'});});
 await inventory('Saved Messages');
 await step('UI09-empty','Click SEND empty; no message row',async()=>{const n=await page.locator('.msg-del-btn').count();await click('SEND');assert.equal(await page.locator('.msg-del-btn').count(),n);});
 await step('UI09-send','Fill local text and click SEND',async()=>{await page.locator('#msgInput').fill('Synthetic QA local message');await click('SEND');await page.locator('#log .m-txt').filter({hasText:'Synthetic QA local message'}).waitFor();});
 await step('UI09-rename-cancel','Click rename then cancel',async()=>{await page.locator('#chat-header button[onclick*="renameCurrent"]').click();await click('ОТМЕНА');await page.locator('#msgInput').waitFor({state:'visible'});});
 await step('UI09-delete-cancel','Click message delete then НЕТ',async()=>{await page.locator('.msg-del-btn').first().click();await click('НЕТ');await page.locator('#log .m-txt').filter({hasText:'Synthetic QA local message'}).waitFor();});
 await step('UI09-password-cancel','Click chat password then cancel',async()=>{await page.getByTitle('Пароль чата',{exact:true}).click();await click('ОТМЕНА');});
 await step('UI09-password-set','Set and confirm local history password',async()=>{await page.getByTitle('Пароль чата',{exact:true}).click();await prompt('Synthetic-history!');await prompt('Synthetic-history!');await page.locator('#input-area').waitFor({state:'hidden',timeout:60000});});
 await step('UI09-password-wrong','Reopen Saved Messages with wrong password',async()=>{await page.locator('#contact-list').getByText('Избранное',{exact:true}).click();await prompt('wrong');await page.getByText('Неверный пароль или повреждённая защита',{exact:true}).waitFor();await click('OK');});
 await step('UI09-password-unlock','Reopen Saved Messages with correct password and verify history',async()=>{await page.locator('#contact-list').getByText('Избранное',{exact:true}).click();await prompt('Synthetic-history!');await page.locator('#log .m-txt').filter({hasText:'Synthetic QA local message'}).waitFor();});
 await step('UI09-password-remove','Remove local history password preserving message',async()=>{await page.getByTitle('Пароль чата',{exact:true}).click();await prompt('Synthetic-history!');await prompt('');await page.locator('#input-area').waitFor({state:'hidden',timeout:60000});await page.locator('#contact-list').getByText('Избранное',{exact:true}).click();await page.locator('#log .m-txt').filter({hasText:'Synthetic QA local message'}).waitFor();});
 await step('UI09-delete','Delete synthetic local message and verify disappearance',async()=>{await page.locator('.msg-del-btn').first().click();await click('ДА');await page.locator('#log .m-txt').filter({hasText:'Synthetic QA local message'}).waitFor({state:'hidden'});});
 await step('UI10-voice-cancel','Start microphone capture, cancel and verify timer hides',async()=>{await page.locator('#voice-btn').click();await page.locator('#recording-timer').waitFor({state:'visible'});await inventory('Voice recording');await page.locator('#voice-btn').click();await page.locator('#recording-timer').waitFor({state:'hidden'});});
 await step('UI10-voice-send','Start microphone capture and SEND local recording',async()=>{await page.locator('#voice-btn').click();await page.locator('#recording-timer').waitFor({state:'visible'});await page.waitForTimeout(1200);await click('SEND');await page.locator('#recording-timer').waitFor({state:'hidden'});await page.getByRole('button',{name:'РАСШИФРОВАТЬ',exact:true}).waitFor();});
 await step('UI10-voice-play','Click decrypt local audio and play native media control',async()=>{await click('РАСШИФРОВАТЬ');const audio=page.locator('#log audio');await audio.waitFor({state:'visible'});await audio.click({position:{x:20,y:20}});await page.waitForFunction(()=>document.querySelector('#log audio')?.currentTime>0);});
 await step('UI10-circle-cancel','Start circle camera capture and cancel',async()=>{await page.locator('#circle-btn').click();await page.locator('#circle-preview').waitFor({state:'visible'});await inventory('Circle recording');await page.locator('#circle-btn').click();await page.locator('#circle-preview').waitFor({state:'hidden'});});
 await step('UI12-local-file','Select synthetic file in Saved Messages; truthful unsupported message',async()=>{const chooser=page.waitForEvent('filechooser');await page.locator('button[onclick="Core.uiAttach()"]').click();await(await chooser).setFiles({name:'synthetic.txt',mimeType:'text/plain',buffer:Buffer.from('synthetic')});await page.getByText('Локальное сохранение файлов пока недоступно. Текст и записи сохраняются без транспорта.',{exact:true}).waitFor();await click('OK');});
 await step('UI02-logout','Click ВЫХОД and verify registry selector',async()=>{await click('[ ВЫХОД ]');await page.getByText('КТО ЗАХОДИТ?',{exact:true}).waitFor();});
 await inventory('Account selector');
 await step('UI02-select','Select saved Account and verify prefilled identifier',async()=>{await click(account);assert.equal(await page.locator('#p1').inputValue(),account);});
 await step('UI02-return','Click К СПИСКУ',async()=>{await click('К СПИСКУ');await page.getByText('КТО ЗАХОДИТ?',{exact:true}).waitFor();});
 await step('UI02-login','Select saved Account and enter key',async()=>{await click(account);await page.locator('#p2').fill(password);await click('ВОЙТИ');await page.locator('#contact-list').getByText('Избранное',{exact:true}).waitFor({timeout:60000});});
 await step('UI01-master-history','Create retained history before master rotation',async()=>{await page.locator('#contact-list').getByText('Избранное',{exact:true}).click();await page.locator('#msgInput').fill('Synthetic retained history');await click('SEND');await page.locator('#log .m-txt').filter({hasText:'Synthetic retained history'}).waitFor();});
 await step('UI01-master-wrong','Open master reconfiguration and reject wrong old code',async()=>{await click('[ ВЫХОД ]');await page.locator('#global-settings-button').click();await page.locator('button[onclick="ui.startMasterReconfiguration()"]').click();await digits('2222');await page.getByText('НЕВЕРНЫЙ MASTER-КОД',{exact:true}).waitFor();});
 await step('UI01-master-change','Enter old code then new master and wipe codes',async()=>{await digits('3333');await page.getByText('НОВЫЙ MASTER-КОД',{exact:true}).waitFor();await digits('4444');await page.getByText('НОВЫЙ WIPE-КОД',{exact:true}).waitFor();await digits('8765');await page.getByText('КОДЫ ОБНОВЛЕНЫ',{exact:true}).waitFor({timeout:60000});});
 await step('UI01-master-old-deny','Reload and verify old master does not unlock',async()=>{await page.reload();await digits('3333');await page.waitForTimeout(1500);assert.equal(await page.locator('#p1').isVisible(),false);assert.equal(await page.locator('.acc-list-scroll').count(),0);});
 await step('UI01-master-new-retain','New master unlocks same registry Account and history',async()=>{await click('AC');await digits('4444');await click(account);await page.locator('#p2').fill(password);await click('ВОЙТИ');await page.locator('#contact-list').getByText('Избранное',{exact:true}).click({timeout:60000});await page.locator('#log .m-txt').filter({hasText:'Synthetic retained history'}).waitFor();});
 }catch(e){report.fatal=e.message.split('\n')[0];}finally{save();await browser.close();}
 process.exitCode=report.fatal||report.steps.some(s=>s.status==='FAIL')?1:0;
 console.log(JSON.stringify({page:report.page,sw:report.sw,steps:report.steps,fatal:report.fatal}));
})();
