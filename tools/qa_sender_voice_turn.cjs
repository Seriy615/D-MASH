'use strict';
const assert = require('node:assert/strict');
// Invoke only after the candidate is frozen and real S-TURN capability is provisioned.
// All mutations below are actual UI clicks; evaluate is metadata-only observation.
module.exports = async ({pages, report, step, click, observeRelay}) => {
  const [sender, recipient] = pages;
  const result = report.senderVoiceTurn = {scope:'Synthetic microphone; actual UI; real peer/S-TURN required', timeline:[], notRun:[]};
  const snapshot = async label => {
    const value = await sender.evaluate(async () => {
      const runtime=Core.recordedNoteTurn;
      const rows=runtime ? await runtime.rows(runtime.capture()) : [];
      return {notes:rows.sort((a,b)=>a.createdAt-b.createdAt).map(r=>({status:r.status,size:r.size,attempts:r.attempts,retained:!!r.content})),
        visible:[...document.querySelectorAll('#log .msg.out .note-transfer-state')].map(e=>e.textContent),
        receipt:[...document.querySelectorAll('#log .msg.out .m-state')].map(e=>e.title)};
    });
    result.timeline.push({label,at:new Date().toISOString(),...value});
    return value;
  };
  const before=await snapshot('before');
  await step('turn-voice-capture-cancel',sender,async()=>{
    await sender.locator('#voice-btn').click();
    await sender.locator('#recording-timer').waitFor({state:'visible'});
    await sender.locator('#voice-btn').click();
    await sender.locator('#recording-timer').waitFor({state:'hidden'});
    assert.equal((await snapshot('capture-cancel')).notes.length,before.notes.length);
  });
  for(let i=0;i<3;i++) await step('turn-voice-durable-'+i,sender,async()=>{
    await sender.locator('#voice-btn').click();
    await sender.locator('#recording-timer').waitFor({state:'visible'});
    await sender.waitForTimeout(2300);
    const started=Date.now();await sender.locator('#input-area .send-btn').click();
    await sender.locator('#recording-timer').waitFor({state:'hidden'});
    await sender.waitForFunction(n=>document.querySelectorAll('#log .msg.out .note-transfer-state').length>=n,before.notes.length+i+1,{timeout:10000});
    const saved=await snapshot('durable-'+i);result.timeline.at(-1).stopToDurableMs=Date.now()-started;
    assert.equal(saved.notes.length,before.notes.length+i+1,'Each recording must be durably retained');
    assert(!await sender.getByText('Recorded-note queue full',{exact:true}).count());
  });
  await step('turn-voice-delivery-visible',sender,async()=>{
    await sender.waitForFunction(()=>{const r=[...document.querySelectorAll('#log .msg.out .note-transfer-state')].slice(-3);return r.length===3&&r.every(e=>e.textContent==='Доставлено');},null,{timeout:60000});
    const value=await snapshot('delivered');assert(value.notes.slice(-3).every(r=>r.status==='delivered'));
    assert(value.receipt.slice(-3).every(v=>v==='Delivered to device'||v==='Read by account'));
  });
  await step('turn-voice-receiver-ready-no-autoplay',recipient,async()=>{
    for(let i=0;i<10&&await recipient.getByRole('button',{name:'РАСШИФРОВАТЬ',exact:true}).count();i++){await recipient.getByRole('button',{name:'РАСШИФРОВАТЬ',exact:true}).first().click();}
    await recipient.waitForFunction(()=>{const a=[...document.querySelectorAll('#log audio')].slice(-3);return a.length===3&&a.every(e=>e.readyState>=2);},null,{timeout:10000});
    result.receiver=await recipient.locator('#log audio').evaluateAll(a=>a.slice(-3).map(e=>({readyState:e.readyState,duration:e.duration,paused:e.paused,autoplay:e.autoplay})));
    assert(result.receiver.every(e=>e.paused&&!e.autoplay),'Receive must not autoplay');
  });
  await step('turn-voice-content-hash',recipient,async()=>{
    const expected=await sender.evaluate(async()=>{const rt=Core.recordedNoteTurn;return(await rt.rows(rt.capture())).sort((a,b)=>a.createdAt-b.createdAt).slice(-3).map(x=>x.sha256).sort();});
    const actual=await recipient.locator('#log audio').evaluateAll(async elements=>{const out=[];for(const e of elements.slice(-3)){const bytes=await(await fetch(e.currentSrc||e.src)).arrayBuffer();out.push(Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),x=>x.toString(16).padStart(2,'0')).join(''));}return out.sort();});
    assert.deepEqual(actual,expected);result.receiverHashEquality={count:3,equal:true};
  });
  if(observeRelay){result.relay=await observeRelay();
    await step('turn-voice-relay-metadata',sender,async()=>{
      assert(result.relay.messages.some(m=>m.type==='voip_note_request'),'Observed metadata invitations required');
      assert(result.relay.messages.every(m=>!m.containsMedia&&!m.type.startsWith('voip_media_')&&m.type!=='dmash_media_fragment'),'No legacy media frames at observed Account send boundary');
      for(const profile of [0,1])assert(result.relay.relay.some(x=>x.profile===profile&&x.samples.some(s=>s.policy==='relay'&&s.local==='relay'&&s.remote==='relay')),'Both peers require selected relay/relay');
    });
  }
  else result.notRun.push('Independent relay statistics, no-media-bytes-on-Mesh and sender/receiver hash equality require transport observer; UI alone cannot prove them.');
  result.notRun.push('Circle, offline/reload/recovery and durable cancel/retry need dedicated phases; this module only proves online voice slice.');
};
