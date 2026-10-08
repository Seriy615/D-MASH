'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
let source=fs.readFileSync(require.resolve('../js/node_bootstrap_runtime_v4.js'),'utf8').replace(' class BootstrapRuntime{',` class BootstrapRuntime{
 static fixture(owner,destination,dispatch,send){const x=new BootstrapRuntime();x.#routes.set(owner.routeId,{handler(){}});Object.assign(x,{ownership:{owner:()=>owner},local:{routes:new Map([['grant',destination]])},codec:{inspect:async()=>({remoteAccount:owner.accountPublic})},dispatcher:{request:dispatch},runtime:{send},inbox:{check(){}},isCurrent:()=>true,closed:false});return x;}
`);
const context={Uint8Array,TextEncoder,console,DmashSecureSession:{canonical:JSON.stringify},DmashRecipientPayloadV4:{sealPayload:(_key,value)=>value}};vm.createContext(context);vm.runInContext(source,context);
(async()=>{const token='a'.repeat(64),owner={routeId:'c'.repeat(64),accountPublic:'d'.repeat(64)},cert={recipient_box:'e'.repeat(64)},destination={ownerToken:'b'.repeat(64),certificate:cert,route:{}},control={kind:'REQUEST',targetBundle:JSON.stringify({inbound_certificate:cert}),serialized:'signed request'},Class=context.DmashNodeBootstrapRuntimeV4;let writes=0,sends=0,drop=false,x;x=Class.fixture(owner,destination,async()=>{writes++;if(drop)x.local.routes.delete('grant');},()=>sends++);
 await assert.rejects(()=>x.submit(token,'grant',control),/owner mismatch/);assert.equal(writes,0);assert.equal(sends,0);
 destination.ownerToken=token;drop=true;await assert.rejects(()=>x.submit(token,'grant',control),/released/);assert.equal(sends,0);
 drop=false;x.local.routes.set('grant',destination);assert.equal((await x.submit(token,'grant',control)).queued,true);assert.equal(sends,1);
 console.log('PASS private bootstrap managed grant owner isolation and release-during-persist refusal; routing/codec doubles, no authentication claim');
})().catch(e=>{console.error(e);process.exitCode=1;});
