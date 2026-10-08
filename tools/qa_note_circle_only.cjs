'use strict';
const assert=require('node:assert/strict');
module.exports=async({pages,report,step,click,snap})=>{
 const [a,b]=pages,name=await a.evaluate(()=>Core.activeIdentity);
 const rows=()=>a.evaluate(async()=>{const rt=Core.recordedNoteTurn;return rt?(await rt.rows(rt.capture())).sort((x,y)=>x.createdAt-y.createdAt).map(x=>({status:x.status,retained:!!x.content})):[];});
 const before=await rows();report.switchCircle={before,notRun:['Cancel/retry blocked by missing post-reload controls in original candidate']};
 await step('circle-cancel',a,async()=>{await a.locator('#circle-btn').click();await a.locator('#recording-timer').waitFor({state:'visible'});await a.locator('#circle-btn').click();await a.locator('#recording-timer').waitFor({state:'hidden'});assert.equal((await rows()).length,before.length);});
 await step('circle-send',a,async()=>{await a.locator('#circle-btn').click();await a.locator('#recording-timer').waitFor({state:'visible'});await a.waitForTimeout(2300);await a.locator('#input-area .send-btn').click();await a.locator('#recording-timer').waitFor({state:'hidden'});await a.locator('.note-transfer-state').last().filter({hasText:'Доставлено'}).waitFor({timeout:60000});assert.equal((await rows()).length,before.length+1);});
 await step('circle-decode-ready-no-autoplay',b,async()=>{await b.getByRole('button',{name:'РАСШИФРОВАТЬ КРУЖОК',exact:true}).last().click();await b.locator('#log video').last().waitFor();await b.waitForFunction(()=>[...document.querySelectorAll('#log video')].at(-1)?.readyState>=2);report.switchCircle.video=await b.locator('#log video').last().evaluate(v=>({duration:v.duration,paused:v.paused,autoplay:v.autoplay,readyState:v.readyState}));assert(report.switchCircle.video.paused&&!report.switchCircle.video.autoplay);});
};
