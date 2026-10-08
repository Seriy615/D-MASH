'use strict';
const assert=require('node:assert/strict');
const {createCore}=require('./fixtures/core_vm.cjs');
(async()=>{
 const {core,ctx}=await createCore();let state=null,accepts=0,prompts=0,pickers=0,modal;
 const request={id:'pending',status:'pending',displayName:'Peer',bootstrap:{contactRequest:{request_id:'request'}}};
 ctx.ContactFlowV3={};ctx.ContactPayloads={validateRequest:x=>x};ctx.DeviceRoot={state:{}};ctx.NodeManager={connectedConnections:()=>[]};ctx.PendingContactRequestStore={normalizeDisplayName:x=>x};
 core.activeIdentity='A';core.getContactFlowV3=()=>({read:async()=>state,accept:async()=>{accepts++;return state.status;}});
 core.getPendingContactRequestStore=()=>({read:async()=>request,accept:async()=>{}});core.openModal=(title,html)=>modal={title,html};core.customAlert=(title,message)=>modal={title,html:message};core.customPrompt=()=>prompts++;core.openPendingContactAccountPicker=()=>pickers++;ctx.DeviceRoutes={resolve:()=>({certificate:{}})};
 assert.equal((await core.pendingContactAcceptanceInfo(request)).kind,'fresh');
 state={role:'caller',slot:'B'};await core.readPendingContactRequest('pending');assert.match(modal.html,/исходящий запрос/);assert(!modal.html.includes('startAcceptPendingContactRequest'));await core.startAcceptPendingContactRequest('pending');assert.equal(prompts,0);
 state={role:'acceptor',slot:'B',status:'accept_prepared'};await core.readPendingContactRequest('pending');assert.match(modal.html,/аккаунта «B»/);assert.match(modal.html,/ВЫЙТИ И ВЫБРАТЬ/);await core.acceptPendingContactRequest('pending','Quick',core.bytesToHex(core.keys.sign.publicKey));assert.equal(accepts,0);
 state.slot='A';state.accept={body:{display_name:'Original',expires_at:Math.floor(Date.now()/1000)+100}};assert.equal((await core.pendingContactAcceptanceInfo(request)).kind,'retry');await core.startAcceptPendingContactRequest('pending');assert.equal(accepts,1);assert.equal(prompts,0);assert.equal(pickers,0);
 state.accept.body.expires_at=1;await core.readPendingContactRequest('pending');assert.match(modal.html,/Срок подписанного принятия истёк/);await core.startAcceptPendingContactRequest('pending');assert.equal(accepts,1);
 state.status='established';await core.startAcceptPendingContactRequest('pending');assert.equal(accepts,2);assert.equal(modal.title,'КОНТАКТ ПОДТВЕРЖДЁН');
 state={role:'acceptor',slot:'<img src=x onerror=bad>'};await core.readPendingContactRequest('pending');assert(!modal.html.includes('<img'));assert.match(modal.html,/&lt;img/);
 core.getContactFlowV3=()=>({read:async()=>{ctx.DeviceRoot.state={};return state;}});await assert.rejects(core.pendingContactAcceptanceInfo(request),/Состояние устройства изменилось/);
 console.log('PASS owner/caller/expiry/retry/established preflight; no owner reassignment, escaped UI, root lifecycle guard');
})().catch(e=>{console.error(e);process.exitCode=1;});
