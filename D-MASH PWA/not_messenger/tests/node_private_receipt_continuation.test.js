'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
let source=fs.readFileSync(require.resolve('../js/node_bootstrap_runtime_v4.js'),'utf8').replace(' class BootstrapRuntime{',` class BootstrapRuntime{
 static fixture(owner,destination,config,record,send){const x=new BootstrapRuntime();Object.assign(x,{ownership:{owner:()=>owner,read:async()=>({state:'ACTIVE',ownership:owner}),matches(row,expected){if(row.ownership!==expected)throw Error('owner mismatch');}},local:{routes:new Map([['grant',destination]]),bindings:new Map([[owner.routeId,{handler(){}}]])},codec:{fits:x=>x},dispatcher:{key:async()=> 'config',load:async()=>({value:config}),save:async(_t,_k,_p,value)=>Object.assign(config,value),list:async()=>[record],receipt:async(_t,_id,wire)=>{if(!Object.values(record.receipts).includes(wire))throw Error('not verified');}},runtime:{send},inbox:{check(){}},isCurrent:()=>true,closed:false});return x;}
`);
const context={Uint8Array,TextEncoder,Date,console,DmashSecureSession:{canonical:JSON.stringify},DmashRecipientPayloadV4:{sealPayload:(_key,value)=>value,openPayload:(_keys,payload)=>({status:'accepted',payload})}};vm.createContext(context);vm.runInContext(source,context);
(async()=>{const now=Math.floor(Date.now()/1000),token='a'.repeat(64),owner={routeId:'b'.repeat(64)},cert={recipient_box:'c'.repeat(64)},destination={ownerToken:token,certificate:cert,route:{}},config={suspended:true,continuationUntil:now+300,continuationSent:0,continuationReceived:0},record={exchangeId:'d'.repeat(64),state:'SELECTED',direction:'OUTBOUND',targetBundle:JSON.stringify({inbound_certificate:cert}),receipts:{ACCEPT:'signed accept',CONFIRM:'signed confirm'}},Class=context.DmashNodeBootstrapRuntimeV4;let sends=0;const make=()=>Class.fixture(owner,destination,config,record,()=>sends++);let runtime=make();
 await assert.rejects(()=>runtime.submit(token,'grant',{kind:'REQUEST'}),/exact receipt/);
 await assert.rejects(()=>runtime.submit(token,'grant',{kind:'RECEIPT',exchangeId:record.exchangeId,serialized:'substitute'}),/substitution/);
 for(let n=0;n<16;n++){await runtime.submit(token,'grant',{kind:'RECEIPT',exchangeId:record.exchangeId,serialized:record.receipts.CONFIRM});runtime=make();}
 assert.equal(sends,16);await assert.rejects(()=>runtime.submit(token,'grant',{kind:'RECEIPT',exchangeId:record.exchangeId,serialized:record.receipts.CONFIRM}),/exhausted/);
 const packet={payload:JSON.stringify({type:'NODE_BOOTSTRAP_RECEIPT_V4',exchange_id:record.exchangeId,receipt:record.receipts.ACCEPT})};assert.equal(await runtime.receiveFinal(owner.routeId,packet,[]),true);assert.equal(config.continuationReceived,1);
 assert.equal(await runtime.receiveFinal(owner.routeId,{payload:'{"type":"ACCOUNT_APP_V4"}'},[]),false,'ordinary ciphertext proceeds through normal Inbox');
 assert.equal(await runtime.receiveFinal(owner.routeId,{payload:'{"type":"NODE_BOOTSTRAP_REQUEST_V4"}'},[]),true);assert.equal(config.continuationReceived,1);
 config.continuationUntil=now-1;await runtime.receiveFinal(owner.routeId,packet,[]);assert.equal(config.continuationReceived,1);assert.equal(sends,16);
 console.log('PASS ACTIVE exact receipt retry after simulated loss, persisted 16-attempt/300s bound, no new REQUEST, duplicate sink separate from app Inbox; crypto/storage doubles');
})().catch(e=>{console.error(e);process.exitCode=1;});
