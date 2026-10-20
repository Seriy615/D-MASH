'use strict';
const assert=require('node:assert/strict'),Inbox=require('../js/account_managed_inbox_v4.js');
const key=n=>n.toString(16).padStart(64,'0');
function fixture(){
 const controller=new AbortController(),peer=key(1),slot=key(2),route=key(3),cap=Object.freeze({}),acks=[],rows=[];
 let snapshot={peer,digest:key(4),generation:1,readiness:'NODE_PROOF_REQUIRED',preparation:{ownerSlot:slot},localCertificate:{route_id:route}};
 const session={signal:controller.signal,assertCurrent(){if(controller.signal.aborted)throw Error('Account revoked');}};
 const host={closed:false,ownerInboxList:async(owner,limit,after)=>{assert.equal(owner,cap);return{records:rows.filter(r=>!acks.includes(r.handle)&&(!after||r.receivedAt>after.receivedAt)).slice(0,limit)};},ownerAcknowledgeInbox:async(owner,handle)=>{assert.equal(owner,cap);acks.push(handle);return true;}};
 const options={session,journal:{readRouteSnapshot:async()=>snapshot},resolveOwners:async()=>[{peer,capability:cap}],consume:async()=>({persisted:false})};
 return{controller,peer,slot,route,cap,acks,rows,host,options,get snapshot(){return snapshot;},set snapshot(value){snapshot=value;},row:(n,payload)=>({handle:key(100+n),receivedAt:n,accountSlot:slot,routeId:route,payload})};
}
(async()=>{
 const f=fixture();for(let i=1;i<=35;i++)f.rows.push(f.row(i,i===35?'valid':'unknown'));
 f.options.consume=async frame=>{if(frame.frame==='unknown')throw Error('Unrecognized signed frame');return{persisted:true};};
 const inbox=new Inbox(f.host,f.options),first=await inbox.drain();assert.equal(first.processed,1);assert.equal(first.failed,34);assert.deepEqual(f.acks,[key(135)]);
 const second=await inbox.drain();assert(second.failed>0,'retained rejects revisited, never silently discarded');assert.equal(f.acks.length,1);inbox.close();
 const archived=fixture();archived.snapshot={...archived.snapshot,readiness:'ROUTE_EXPIRED'};archived.rows.push(archived.row(1,'retained'));
 archived.options.consume=async()=>({persisted:true});assert.equal((await new Inbox(archived.host,archived.options).drain()).processed,1,'historical inbox does not require outbound permission');
 const changed=fixture();changed.rows.push(changed.row(1,'frame'));changed.options.consume=async()=>{changed.snapshot={...changed.snapshot,digest:key(9),generation:2};return{persisted:true};};
 const result=await new Inbox(changed.host,changed.options).drain();assert.equal(result.resync,1);assert.equal(changed.acks.length,0);
 const foreign=fixture();foreign.rows.push({...foreign.row(1,'foreign slot'),accountSlot:key(10)},{...foreign.row(2,'foreign route'),routeId:key(11)});foreign.options.consume=async()=>{throw Error('Must not reach consumer');};
 assert.equal((await new Inbox(foreign.host,foreign.options).drain()).failed,2);assert.equal(foreign.acks.length,0);
 const revoked=fixture();revoked.rows.push(revoked.row(1,'frame'));revoked.options.consume=async()=>{revoked.controller.abort();return{persisted:true};};await assert.rejects(new Inbox(revoked.host,revoked.options).drain(),/UNAVAILABLE|revoked/);assert.equal(revoked.acks.length,0);
 const restarted=fixture();for(let i=1;i<=130;i++)restarted.rows.push(restarted.row(i,i===130?'valid':'poison'));
 let stored={revision:null,cursor:null},saves=0,failSave=false;
 restarted.options.progress={kind:'managed',load:async()=>structuredClone(stored),save:async(revision,cursor)=>{
  assert.equal(revision,stored.revision,'checkpoint CAS');if(failSave)throw Error('checkpoint disk failure');
  stored={revision:key(++saves),cursor:structuredClone(cursor)};return stored.revision;
 }};
 restarted.options.consume=async frame=>{if(frame.frame==='poison')throw Error('poison');return {persisted:true};};
 const before=new Inbox(restarted.host,restarted.options),firstPass=await before.drain();assert.equal(firstPass.failed,128);assert.equal(firstPass.processed,0);assert.equal(stored.cursor.peers[0].after.receivedAt,128);before.close();
 const after=new Inbox(restarted.host,restarted.options),secondPass=await after.drain();assert.equal(secondPass.failed,1);assert.equal(secondPass.processed,1);assert.deepEqual(restarted.acks,[key(230)]);after.close();
 const disk=fixture();disk.rows.push(disk.row(1,'keep'));disk.options.progress={kind:'managed',load:async()=>structuredClone(stored),save:restarted.options.progress.save};let diskReady=false;disk.options.consume=async()=>({persisted:diskReady});
 // Start this fixture at its own durable position and fail the checkpoint. A
 // later instance must reload that position, not inherit a skipped in-memory row.
 stored={revision:null,cursor:null};failSave=true;await assert.rejects(new Inbox(disk.host,disk.options).drain(),/checkpoint disk failure/);failSave=false;diskReady=true;
 const replay=await new Inbox(disk.host,disk.options).drain();assert.equal(replay.processed,1);
 console.log('PASS managed inbox: bounded retained rejection retry, durable 128-poison restart progress, checkpoint-failure replay, historical archive READ/ACK, peer/route/slot checks, persist-before-ACK, binding change resync and Account abort');
})().catch(error=>{console.error(error);process.exitCode=1;});
