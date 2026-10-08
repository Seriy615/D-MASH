'use strict';
// Runs the production Worker connect function with a controlled channel boundary.
// This is a focused UNIT check; genuine Worker/socket acceptance remains required.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../js/node_runtime_worker_v4.js'),'utf8'),start=source.indexOf('async function connect(data){'),end=source.indexOf('self.onmessage=',start);
(async()=>{
 const id='a'.repeat(64),url='wss://example.invalid/mesh/v4';let checks=0,auth=0,release;
 const peer={secure:{socket:{url},check(){checks++;}},async requireAuthorized(){auth++;}};
 const ctx={ready:true,closed:false,connecting:new Set(),runtime:{peers:new Map([[id,peer]])},URL,TextEncoder};vm.createContext(ctx);vm.runInContext(source.slice(start,end),ctx);
 assert.equal((await ctx.connect({url,nodeId:id})).reused,true);assert.equal(auth,1);assert.equal(checks,1);
 await assert.rejects(ctx.connect({url:'wss://other.invalid/mesh/v4',nodeId:id}));await assert.rejects(ctx.connect({url,nodeId:id,password:'new-secret'}));assert.equal(auth,1,'reused connection never accepts changed endpoint/password');
 peer.requireAuthorized=()=>new Promise(resolve=>{release=resolve;});const task=ctx.connect({url,nodeId:id});ctx.runtime.peers.delete(id);release();await assert.rejects(task);
 ctx.runtime.peers.set(id,peer);const stopped=ctx.connect({url,nodeId:id});ctx.closed=true;release();await assert.rejects(stopped);
 console.log('PASS Worker connect reuse UNIT: exact endpoint, existing authorization, password refusal, peer removal/root close races; no fresh socket fabricated');
})().catch(e=>{console.error(e);process.exitCode=1;});
