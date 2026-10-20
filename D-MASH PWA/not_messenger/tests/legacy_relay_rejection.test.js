'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const input={value:'retained synthetic draft',style:{height:'45px'}};
const document={getElementById:id=>id==='msgInput'?input:null};
const window={addEventListener(){},crypto:webcrypto,NodeManager:{transportMode:'legacy'},nacl:{sign:{detached:()=>new Uint8Array(64)}}};
let calls=0,saved=0,alerts=[],status=410,current=true;
const context={window,document,crypto:webcrypto,console,TextEncoder,Uint8Array,setInterval(){},clearInterval(){},localStorage:{getItem(){return null}},fetch:async()=>{calls++;return {ok:status>=200&&status<300,status}},Storage:{async saveMessageGamma(){saved++;return 'synthetic-message'}}};
vm.runInNewContext(fs.readFileSync(require.resolve('../js/core_engine.js'),'utf8'),context);
const Core=window.Core;Core.activePeerId='synthetic-peer';Core.keys={sign:{secretKey:new Uint8Array(64).fill(7)},server_id:'synthetic-id'};
const keys=Core.keys;Core.encrypt=async()=> '00';Core.fastHash=async()=> 'synthetic-hash';Core.shmon=()=>{};Core.customAlert=(...a)=>alerts.push(a);
(async()=>{
 assert.equal(await Core.sendMessage(),false);assert.equal(calls,1);assert.equal(saved,0,'410 cannot write SENT');assert.equal(input.value,'retained synthetic draft');assert.equal(Core.keys,keys);assert.equal(window.NodeManager.transportMode,'legacy');assert.equal(alerts.length,1);assert.match(alerts[0][1],/Legacy Relay недоступен/);
 status=503;assert.equal(await Core.sendMessage(),false);assert.equal(saved,0);assert.equal(input.value,'retained synthetic draft');
 status=200;context.fetch=async()=>{current=false;return {ok:true,status:200}};assert.equal(await Core.sendMessage(null,false,null,null,false,null,null,()=>current),false);assert.equal(saved,0,'stale completion cannot write history');assert.equal(input.value,'retained synthetic draft');
 console.log('Legacy Relay rejection: HTTP410/503 and stale200 never write SENT/clear draft/reset keys/mode/fallback PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
