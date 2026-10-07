'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),http=require('node:http'),path=require('node:path');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
let core=fs.readFileSync(path.join(__dirname,'../D-MASH PWA/not_messenger/js/core_engine.js'));
(async()=>{
 if(process.env.DMASH_MEDIA_CORE_URL){const response=await fetch(process.env.DMASH_MEDIA_CORE_URL);if(!response.ok)throw Error('Public Core unavailable');core=Buffer.from(await response.arrayBuffer());}
 const server=http.createServer((request,response)=>{
  if(request.url==='/core.js'){response.setHeader('Content-Type','application/javascript; charset=utf-8');response.end(core);}
  else{response.setHeader('Content-Type','text/html; charset=utf-8');response.end('<div id="stub-voice"></div><div id="stub-video"></div><div id="stub-bad"></div><script src="/core.js"></script>');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,
   args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']});
  const context=await browser.newContext({permissions:['microphone','camera']});const page=await context.newPage();
  await page.goto('http://127.0.0.1:'+server.address().port+'/');
  const result=await page.evaluate(async()=>{
   Core.shmon=()=>{};
   for(const [id,video] of [['voice',false],['video',true]]){
    const stream=await navigator.mediaDevices.getUserMedia({audio:true,video});
    const recorder=new MediaRecorder(stream),chunks=[];recorder.ondataavailable=e=>chunks.push(e.data);
    const stopped=new Promise(resolve=>recorder.onstop=resolve);recorder.start();await new Promise(resolve=>setTimeout(resolve,700));recorder.stop();await stopped;
    stream.getTracks().forEach(track=>track.stop());
    const data=await new Promise(resolve=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.readAsDataURL(new Blob(chunks,{type:recorder.mimeType}));});
    await Core.decryptMedia(id,{type:video?'video_note':'voice',name:'recorded',data});
    const player=document.querySelector('#stub-'+id+' '+(video?'video':'audio'));
    if(!player||!player.src.startsWith('blob:'))throw Error('Recorded media did not become a Blob player');
    if(player.readyState<1)await new Promise((resolve,reject)=>{player.addEventListener('loadedmetadata',resolve,{once:true});player.addEventListener('error',()=>reject(Error('Recorded '+id+' decoder failed: '+recorder.mimeType+'; '+player.error?.message+'; chunks='+chunks.map(c=>c.size).join(','))),{once:true});setTimeout(()=>reject(Error('Recorded metadata deadline')),10000);});
    await player.play();await new Promise(resolve=>setTimeout(resolve,250));if(player.currentTime<=0)throw Error('Recorded playback did not advance');player.pause();
   }
   await Core.decryptMedia('bad',{type:'voice',name:'damaged',data:'data:audio/webm;base64,AAAA'});
   const until=Date.now()+18000;while(!/БРАУЗЕР|НЕ ЗАГРУЗИЛОСЬ/.test(document.getElementById('stub-bad').textContent)){if(Date.now()>until)throw Error('Invalid recording stayed loading: '+document.getElementById('stub-bad').innerHTML);await new Promise(resolve=>setTimeout(resolve,50));}
   Core.keys={};Core.callState='idle';let locks=0;Core.terminateSession=()=>locks++;Core.initRyvokDetector();localStorage.setItem('cfg_panic_gesture','true');
   const motion=x=>{const event=new Event('devicemotion');Object.defineProperty(event,'accelerationIncludingGravity',{value:{x,y:0,z:0}});window.dispatchEvent(event);};
   Core.isRecording=true;motion(0);motion(100);
   window.dispatchEvent(new DeviceOrientationEvent('deviceorientation',{beta:180}));
   Core.isRecording=false;Core.flipLockSuppressed=true;motion(0);motion(100);
   if(locks)throw Error('Recording/scanning triggered panic lock');
   Core.flipLockSuppressed=false;motion(0);motion(100);if(locks!==1)throw Error('Explicit enabled panic gesture stopped working');
   return {voice:true,video:true,damagedBounded:true,gestures:true};
  });
  assert.deepEqual(result,{voice:true,video:true,damagedBounded:true,gestures:true});
  console.log('PASS real Chrome MediaRecorder audio/video Blob playback; damaged recording terminates loading; recording/scanner gesture suppression and explicit panic preserved');
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
