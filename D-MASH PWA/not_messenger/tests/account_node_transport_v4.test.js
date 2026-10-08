'use strict';
const assert=require('node:assert/strict'),nacl=require('../js/vendor/nacl-fast.min.js');
global.nacl=nacl;global.DmashRouteDiscoveryV4=require('../js/route_discovery_v4.js');
const recipient=require('../js/recipient_payload_v4.js'),Adapter=require('../js/account_node_transport_v4.js');
(async()=>{
 const keys=nacl.sign.keyPair(),receiver=nacl.box.keyPair(),peer='ab'.repeat(32),digest='cd'.repeat(32),now=Math.floor(Date.now()/1000);
 const certificate=global.DmashRouteDiscoveryV4.issueCertificate(nacl.sign.keyPair(),nacl.sign.keyPair().publicKey,nacl.box.keyPair().publicKey,receiver.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600});
 const proof={ownerSlot:'01'.repeat(32),routeAuthorityDigest:'02'.repeat(32),routeId:'03'.repeat(32),migrationId:'04'.repeat(32),bindingDigest:digest,generation:1,preparationDigest:'05'.repeat(32),accountPublic:Buffer.from(keys.publicKey).toString('hex')};
 let snapshot={peer,digest,generation:1,preparation:proof,readiness:'NODE_PROOF_REQUIRED',localCertificate:{route_id:proof.routeId},remoteCertificate:certificate};
 const owner={capability:Object.freeze({}),preparation:Object.freeze({})},calls=[],controller=new AbortController(),db={},masterKey={};
 const session={db,masterKey,signal:controller.signal,assertCurrent(){if(controller.signal.aborted)throw Error('session changed');}};
 const core={captureAccountSessionV4:()=>session},storage={db,masterKey};
 const host={closed:false,verifyPreparation:async handle=>{assert.equal(handle,owner.preparation);return {...proof,state:'ACTIVE'};},ownerDiscover:async(cap,cert)=>{calls.push({type:'discover',cert});return{handle:'06'.repeat(32),expiresAt:now+600};},ownerSubmitSealed:async(cap,handle,sealed)=>{assert.equal(cap,owner.capability);calls.push({type:'send',handle,sealed});return{queued:true};}};
 const payload='authenticated synthetic frame',signature=Buffer.from(nacl.sign.detached(new TextEncoder().encode(payload),keys.secretKey)).toString('hex');
 const frame=JSON.stringify({payload,signature}),intent={operationId:'07'.repeat(32),peer,bindingDigest:digest,generation:1,frame};
 let blob;const sealedStore={materialize:async input=>({operationId:input.operationId,peer,bindingDigest:digest,generation:1,state:'DURABLE_SEALED_OPERATION',certificateDigest:'08'.repeat(32),blob:blob??=recipient.sealPayload(receiver.publicKey,input.frame)})};
 const adapter=new Adapter(host,core,storage,{journal:{readRouteSnapshot:async()=>snapshot},sealedStore,resolveOwner:async()=>owner});
 await assert.rejects(adapter.configurePeer(peer,certificate,proof.routeId),/SIGNED_PAIRING_V2_REQUIRED/);
 await assert.rejects(adapter.prepare({routeLocator:certificate.route_id}),/UNVERIFIED_ACCOUNT_ROUTE/);
 const route=await adapter.getRoute(peer);await assert.rejects(adapter.submit(route,{version:1,ciphertext:'ff'}),/AUTHENTICATED_DURABLE_INTENT_REQUIRED/);
 assert.equal((await adapter.submit(route,intent)).queued,true);await adapter.prepareAndSubmitIntent(intent);assert.equal(await adapter.getRoute(peer),route);
 const sent=calls.filter(x=>x.type==='send');assert.equal(sent.length,2);assert.equal(sent[0].sealed.blob,sent[1].sealed.blob);
 const opened=recipient.openPayload([receiver.secretKey],sent[0].sealed.blob);assert.equal(opened.payload,frame);assert(nacl.sign.detached.verify(new TextEncoder().encode(payload),Buffer.from(signature,'hex'),keys.publicKey));
 assert(!JSON.stringify(calls.filter(x=>x.type==='discover')).includes(peer));
 const discoverCount=calls.filter(x=>x.type==='discover').length;
 const realNow=Date.now;try{Date.now=()=>realNow()+14000;await adapter.submit(route,intent);}finally{Date.now=realNow;}
 assert.equal(calls.filter(x=>x.type==='discover').length,discoverCount,'young grant should be reused');
 try{Date.now=()=>realNow()+16000;await adapter.submit(route,intent);}finally{Date.now=realNow;}
 assert.equal(calls.filter(x=>x.type==='discover').length,discoverCount+1,'repeat submit must rediscover before a still-unexpired stale grant can trap recovery traffic');
 assert.equal(calls.filter(x=>x.type==='send').at(-1).sealed.blob,sent[0].sealed.blob,'grant refresh changed the durable recipient ciphertext');
 host.ownerSubmitSealed=async()=>{throw Error('network failure');};await assert.rejects(adapter.submit(route,intent),/network failure/);host.ownerSubmitSealed=async()=>({queued:true});await adapter.submit(route,intent);assert.equal(calls.filter(x=>x.type==='discover').length,discoverCount+3);
 snapshot={...snapshot,digest:'09'.repeat(32)};await assert.rejects(adapter.prepare(route),/ACCOUNT_ROUTE_CHANGED/);snapshot={...snapshot,digest};
 host.verifyPreparation=async()=>({...proof,state:'NODE_PREPARED'});await assert.rejects(adapter.getRoute(peer),/NODE_ROUTE_NOT_ACTIVE/);host.verifyPreparation=async()=>({...proof,state:'ACTIVE'});
 host.ownerSubmitSealed=async()=>{throw Error('invalidate grant');};await assert.rejects(adapter.submit(route,intent),/invalidate grant/);
 let release,entered;const start=new Promise(r=>entered=r);host.ownerDiscover=async()=>{entered();return new Promise(r=>release=r);};const lateRoute=await adapter.getRoute(peer),pending=adapter.prepare(lateRoute);await start;controller.abort();release({handle:'10'.repeat(32),expiresAt:now+600});await assert.rejects(pending,/UNAVAILABLE|session changed/);await assert.rejects(adapter.getRoute(peer),/UNAVAILABLE/);
 assert.throws(()=>new Adapter(host,core,storage),/AUTHENTICATED_NODE_ADAPTER_REQUIRED/);
 console.log('PASS managed Account adapter: real recipient crypto, branded routes, authenticated ownership gating, durable intent only, exact bytes, no configurePeer fallback, generation/Account cancellation');
})().catch(error=>{console.error(error);process.exitCode=1;});
