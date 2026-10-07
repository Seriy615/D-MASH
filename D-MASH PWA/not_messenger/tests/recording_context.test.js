'use strict';
const assert=require('node:assert/strict');
const {createCore}=require('./fixtures/core_vm.cjs');
(async()=>{
 const {core,ctx}=await createCore();core.activeIdentity='A';core.blindSalt=new Uint8Array(32);core.activePeerId='alice';
 core.setRecordingToolbar=core.resetRecordingToolbar=core.startRecordingTimer=()=>{};
 core.customAlert=()=>{throw Error('Unexpected alert');};core.closeModal=()=>{};
 ctx.Blob=Blob;const readers=[],recorders=[],sent=[];
 ctx.FileReader=class{readAsDataURL(blob){this.blob=blob;readers.push(this);}};
 ctx.MediaRecorder=class{
  constructor(stream){this.stream=stream;this.mimeType='audio/webm';this.state='inactive';recorders.push(this);}
  start(){this.state='recording';}
  stop(){this.state='inactive';this.ondataavailable({data:new Blob(['payload'])});this.onstop();}
  static isTypeSupported(){return true;}
 };
 let grants=[];ctx.navigator={mediaDevices:{getUserMedia:()=>new Promise(resolve=>grants.push(resolve))}};
 const stream=()=>{const track={stopped:false,stop(){this.stopped=true;}};return{track,getTracks:()=>[track]};};
 core.sendMessage=async(...args)=>sent.push(args);
 let pending=core.uiVoice(),first=stream();core.activePeerId='bob';grants.shift()(first);await pending;
 assert(first.track.stopped);assert.equal(recorders.length,0,'late permission after chat switch releases hardware');
 core.activePeerId='alice';pending=core.uiVoice();const second=stream();grants.shift()(second);await pending;
 core.commitRecording();core.activePeerId='bob';readers.shift().onload({target:{result:'data:audio/webm;base64,cGF5bG9hZA=='}});
 assert.equal(sent.length,1);assert.equal(sent[0][2],'alice','FileReader callback keeps original recipient');assert(second.track.stopped);
 core.activePeerId='alice';pending=core.uiVoice();grants.shift()(stream());await pending;core.commitRecording();core.keys={...core.keys};
 readers.shift().onload({target:{result:'data:audio/webm;base64,cGF5bG9hZA=='}});assert.equal(sent.length,1,'Account transition suppresses delayed recording send');
 pending=core.uiVoice();const cancelled=stream();core.killAllMedia();grants.shift()(cancelled);await pending;assert(cancelled.track.stopped);assert.equal(recorders.length,2);
 console.log('PASS recording permission/chat race stops hardware; delayed FileReader retains original peer; Account change and cleanup suppress late capture');
})().catch(error=>{console.error(error);process.exitCode=1;});
