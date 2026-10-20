'use strict';
// Actual browser propagation + actual Core renderer/modal/binder. Synthetic row
// deletion is an in-memory storage stub; retained owning-profile QA is separate.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT||'playwright');
const root=path.resolve(process.argv[2]||path.join(__dirname,'..'));
const source=fs.readFileSync(path.join(root,'D-MASH PWA/not_messenger/js/core_engine.js'),'utf8');
const surface=source.split('\n').find(line=>line.includes("document.querySelector('.chat-main')?.addEventListener('click',"));
assert(surface,'production chat surface guard exists');
(async()=>{
 const server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end('<!doctype html><html><body><div class="chat-main"><button id="back">Back</button><div id="log"></div><button id="media"><b>Open media</b></button><div id="empty">Empty chat surface</div></div><div id="sys-modal" style="display:none"></div></body></html>');});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,...(process.env.DMASH_CHROMIUM?{executablePath:process.env.DMASH_CHROMIUM}:{})});const page=await browser.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
 try{
  await page.route('**/*',route=>route.request().url().startsWith(origin)?route.continue():route.abort());
  await page.goto(origin);await page.addScriptTag({content:source});
  await page.evaluate(surface=>{
   window.qa={deleted:[],media:[],closed:0,outside:0};
   window.Storage={deleteMessageGamma:async(peer,id)=>window.qa.deleted.push([peer,id])};
   Core.activePeerId='synthetic-saved';Core.closeChat=()=>window.qa.closed++;
   Core.decryptMediaEncoded=(...args)=>window.qa.media.push(args);
   document.getElementById('back').onclick=()=>Core.closeChat();
   document.getElementById('log').innerHTML=Core.buildMsgHtml({text:'Synthetic retained row'},1,2);
   const media=document.getElementById('media');media.outerHTML='<button id="media" '+Core.dataActionAttributes('decryptMediaEncoded',['synthetic-media'])+'><b>Open media</b></button>';
   (0,eval)(surface);Core.bindDataActions(document);Core.bindDataActions(document);
   document.addEventListener('click',()=>window.qa.outside++);
  },surface);
  await page.locator('.msg-del-btn').click();
  assert.equal(await page.locator('#sys-modal').isVisible(),true,'chat action must reach delegated listener across chat stopPropagation');
  await page.getByRole('button',{name:'НЕТ',exact:true}).click();
  assert.deepEqual(await page.evaluate(()=>qa.deleted),[],'cancel keeps row');assert.equal(await page.locator('#msg-box-2').count(),1);
  await page.locator('.msg-del-btn').click();await page.getByRole('button',{name:'ДА',exact:true}).click();
  await page.waitForFunction(()=>!document.getElementById('msg-box-2'));
  assert.deepEqual(await page.evaluate(()=>qa.deleted),[['synthetic-saved',2]],'confirm deletes once');
  await page.locator('#media b').click();assert.deepEqual(await page.evaluate(()=>qa.media),[['synthetic-media']],'nested late-rendered action dispatches once');
  const outside=await page.evaluate(()=>qa.outside);await page.locator('#empty').click();assert.equal(await page.evaluate(()=>qa.closed),0,'empty chat click does not close chat');assert.equal(await page.evaluate(()=>qa.outside),outside,'chat guard still suppresses outside bubble handlers');
  await page.locator('#back').click();assert.equal(await page.evaluate(()=>qa.closed),1,'Back closes once');
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({suite:'ui-data-action-real-DOM-propagation',status:'PASS',browser:browser.version(),coreSha256:crypto.createHash('sha256').update(source).digest('hex'),checks:['chat-delete-modal','cancel-preserves-row','confirm-delete-once','nested-media-action-once','repeated-bind-idempotent','empty-surface-preserves-chat','outside-bubble-still-blocked','explicit-back-once','page-errors-zero'],limits:['synthetic DOM/storage fixture','retained Account/DB acceptance separate','not deployed']}));
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exit(1)});
