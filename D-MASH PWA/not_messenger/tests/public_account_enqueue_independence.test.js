'use strict';
// Scheduling-only fixture: inject private state in a VM copy, never a product
// hook. It does not authenticate a peer or replace real browser acceptance.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
let source=fs.readFileSync(require.resolve('../js/public_account_orchestrator_v4.js'),'utf8');
source=source.replace(' class PublicAccountOrchestratorV4{',` class PublicAccountOrchestratorV4{
 static schedulingFixture(runtime,inbox,peer){const x=new PublicAccountOrchestratorV4();x.#session={assertCurrent(){},signal:new AbortController().signal};x.#runtime=runtime;x.#inbox=inbox;x.#transport={getRoute:async()=>({ready:true})};x.#opened.add(peer);return x;}
`);
const context={Uint8Array,TextEncoder,AbortController,setTimeout,clearTimeout};vm.createContext(context);vm.runInContext(source,context);
(async()=>{let release,drains=0,sent=0;const peer='a'.repeat(64),inbox={drain:()=>{drains++;return new Promise(r=>release=r);}},runtime={durableApplicationEnqueue:true,status:async()=>({phase:'ESTABLISHED'}),resumeApplications(){},startRetries(){},sendApplication:async()=>{sent++;return {durable:true,queued:false};}},adapter=context.DmashPublicAccountOrchestratorV4.schedulingFixture(runtime,inbox,peer);
 const poll=adapter.pollSessions();adapter.pollSessions();assert.equal(drains,1);const result=await Promise.race([adapter.sendApplication(peer,{operationId:'b'.repeat(64),plaintext:'offline'}),new Promise((_,reject)=>setTimeout(()=>reject(Error('Local durable enqueue blocked behind network drain')),100))]);assert.equal(result.durable,true);assert.equal(sent,1);release({processed:0});await poll;
 runtime.durableApplicationEnqueue=false;await assert.rejects(()=>adapter.sendApplication(peer,{}),/PUBLIC_OUTBOX_UPGRADE_REQUIRED/);assert.equal(sent,1);console.log('PASS actual orchestrator scheduling: stalled Inbox cannot block local durable enqueue; poll coalesced; old synchronous runtime refused (private-state VM fixture only)');
})().catch(e=>{console.error(e);process.exitCode=1;});
