'use strict';
const assert=require('node:assert/strict'),Local=require('../js/node_local_delivery_v4.js');
(async()=>{
 const a='a'.repeat(64),b='b'.repeat(64),pending=[];
 const runtime={clock:()=>100,peers:new Map(),discover:(cert,{signal})=>new Promise((resolve,reject)=>{pending.push({signal,resolve,reject});signal.addEventListener('abort',()=>reject(Error('Node discovery cancelled')),{once:true});})};
 const local=new Local(runtime,{check(){}}),one=local.discover({}, {ownerToken:a}),two=local.discover({}, {ownerToken:b});
 const rejected=assert.rejects(one,/cancelled/);assert.equal(local.releaseOwnerGrants(a),0);await rejected;
 assert.equal(pending[0].signal.aborted,true);assert.equal(pending[1].signal.aborted,false);assert.equal(local.pending,1);assert.equal(local.routes.size,0);
 pending[1].resolve({expires_at:200});await two;assert.equal(local.routes.size,1);assert.equal(local.discoveries.size,0);
 const three=local.discover({}, {ownerToken:b}),closed=assert.rejects(three,/cancelled/);local.close();await closed;assert.equal(local.pending,0);assert.equal(local.routes.size,0);assert.equal(local.discoveries.size,0);
 // A late reply from an adapter ignoring cancellation still cannot mint a grant.
 let finish;const late=new Local({clock:()=>100,peers:new Map(),discover:()=>new Promise(resolve=>{finish=resolve;})},{check(){}});
 const operation=late.discover({}, {ownerToken:a}),refused=assert.rejects(operation,/cancelled/);late.releaseOwnerGrants(a);finish({expires_at:200});await refused;assert.equal(late.routes.size,0);assert.equal(late.pending,0);
 console.log('PASS owner-scoped pending discovery cancellation, foreign owner isolation, close cleanup and late-reply refusal');
})().catch(error=>{console.error(error);process.exitCode=1;});
