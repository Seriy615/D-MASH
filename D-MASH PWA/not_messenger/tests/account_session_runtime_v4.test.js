'use strict';
const assert=require('node:assert/strict'),{createCore,nacl}=require('./fixtures/core_vm.cjs');global.nacl=nacl;
const discovery=require('../js/route_discovery_v4.js'),profile=require('../js/account_handshake_v4.js'),Session=require('../js/account_session_v4.js'),Runtime=require('../js/account_session_runtime_v4.js');
let now=1800000000;
(async()=>{
 const [a,b]=await Promise.all([createCore({kyber:true}),createCore({kyber:true})]);
 const rows=new Map();let opened=0;
 const Store={async open({owner,signal}){opened++;const c=owner.context(),alias=c.local+c.peer+c.bindingDigest;let closed=false;const check=()=>{owner.assertCurrent();if(closed||signal.aborted)throw Error('CLOSED');};return {async load(){check();const old=rows.get(alias);return {revision:old?.revision||0,value:structuredClone(old?.value||null)};},async commit(revision,value,guard){check();guard();assert.equal(rows.get(alias)?.revision||0,revision);rows.set(alias,{revision:revision+1,value:structuredClone(value)});},close(){closed=true;}};}};
 for(const [local,peer,n]of [[a,b,1],[b,a,2]]){
  local.controller=new AbortController();local.routeId=String(n).repeat(64);local.sent=[];local.current=true;local.snapshots=0;local.failSend=false;local.statuses=[];
  const capture={signal:local.controller.signal,keys:local.core.keys,blindSalt:new Uint8Array(32).fill(n),masterKey:{},db:{},assertCurrent(){if(!local.current||local.controller.signal.aborted)throw Error('STALE');}};local.core.captureAccountSessionV4=()=>capture;
  local.snapshot={peer:peer.core.keys.pub_hex,digest:'aa'.repeat(32),generation:1,localAccountKeys:{signing:local.core.keys.pub_hex},remoteAccountKeys:{signing:peer.core.keys.pub_hex},localCertificate:{route_id:local.routeId},remoteCertificate:{route_id:String(3-n).repeat(64)}};
  local.transport={async readRouteSnapshot(pid){assert.equal(pid,peer.core.keys.pub_hex);local.snapshots++;return structuredClone(local.snapshot);},async prepareAndSubmitIntent(intent){if(local.failSend)return {queued:false};assert.equal(intent.peer,peer.core.keys.pub_hex);assert.equal(intent.bindingDigest,local.snapshot.digest);assert.equal(intent.operationId,await local.runtime.codec.frameDigest(intent.frame));local.sent.push(intent);return {queued:true,state:'LOCAL_NODE_QUEUED'};}};
  const App={open:async()=>({receiveApplication:async()=>assert.fail('pre-confirmation application reached cipher'),close(){}})};
  local.runtime=new Runtime({core:local.core,transport:local.transport,Store,Session,App,profile,nacl,kem:local.ctx.DmashKyberWasm,discovery,persistAuthenticated:async()=>({persisted:true}),persistControl:async()=>assert.fail('pre-confirmation control reached dispatcher'),controlSchema:{validate:()=>assert.fail('pre-confirmation control reached schema')},clock:()=>now,onStatus:(peer,status)=>local.statuses.push(status)});
 }
 const peerA=b.core.keys.pub_hex,peerB=a.core.keys.pub_hex;
 await assert.rejects(()=>a.runtime.openPeer(peerA),/SUITE_REQUIRED/);
 await Promise.all([a.runtime.openPeer(peerA,{requiredSuite:profile.SUITE}),a.runtime.openPeer(peerA,{requiredSuite:profile.SUITE})]);assert.equal(opened,1,'coalesced store construction');await b.runtime.openPeer(peerB,{requiredSuite:profile.SUITE});
 assert.deepEqual(await b.runtime.receive({peer:peerB,frame:JSON.stringify({type:'ACCOUNT_APP_V4'}),localRouteId:b.routeId}),{persisted:false,deferred:true},'application received before confirmed session stays in Inbox');
 assert.deepEqual(await b.runtime.receive({peer:peerB,frame:JSON.stringify({type:'ACCOUNT_CONTROL_V4'}),localRouteId:b.routeId}),{persisted:false,deferred:true},'control received before confirmed session stays in Inbox');
 await a.runtime.initiate(peerA);assert.equal(a.sent.length,1);assert.equal((await a.runtime.status(peerA)).phase,'INIT_PREPARED');
 const deliver=async(to,from)=>{const intent=from.sent.shift();return to.runtime.receive({peer:from.core.keys.pub_hex,frame:intent.frame,localRouteId:to.routeId});};
 await assert.rejects(()=>b.runtime.receive({peer:peerB,frame:a.sent[0].frame,localRouteId:'ff'.repeat(32)}),/DELIVERY_ROUTE_MISMATCH/);
 await deliver(b,a);await deliver(a,b);assert.equal((await a.runtime.status(peerA)).phase,'INITIATOR_CONFIRM_PENDING');assert.equal((await b.runtime.status(peerB)).phase,'RESPONDER_PENDING');await deliver(b,a);assert.equal((await b.runtime.status(peerB)).phase,'ESTABLISHED');await deliver(a,b);assert.equal((await a.runtime.status(peerA)).phase,'ESTABLISHED');
 assert.equal((await a.runtime.status(peerA)).sessionId,(await b.runtime.status(peerB)).sessionId);assert(a.snapshots>10,'verified route reread');
 a.failSend=true;await assert.rejects(()=>a.runtime.initiate(peerA,{recover:true}),/LOCAL_NODE_REFUSED/);assert.equal((await a.runtime.status(peerA)).phase,'INIT_PREPARED');a.failSend=false;now+=5;await a.runtime.resume();assert(a.sent.length>0,'durable retry survives unavailable sender');
 a.snapshot.digest='bb'.repeat(32);a.snapshot.generation=2;await assert.rejects(()=>a.runtime.status(peerA),/BINDING_MIGRATION_REQUIRED/);assert(rows.size===2,'binding mismatch did not create new state');
 b.runtime.startRetries();b.controller.abort();await assert.rejects(()=>b.runtime.status(peerB),/SESSION_CHANGED/);a.runtime.close();assert(rows.size===2,'close preserved durable state');
 console.log('Account session runtime V4 UNIT: explicit suite, coalesced peer, real crypto4phase through injected transport, ACK-only establishment, route mismatch/change, durable failed-send retry, lifecycle close PASS; no real Node/ordinary UI claim');
})().catch(e=>{console.error(e);process.exitCode=1;});
