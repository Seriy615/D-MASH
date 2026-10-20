'use strict';
const assert=require('node:assert/strict'),{DeviceRoot:root}=require('../js/device_root.js'),Lifecycle=require('../js/node_root_lifecycle_v4.js');
(async()=>{
 root.lock();let starts=0,connections=0,stops=0,release,fail=false,hold=false;
 const coordinator={start:async()=>{starts++;if(hold)await new Promise(r=>release=r);if(fail)throw Error('PIN_MISMATCH');},peers:()=>[{token:{}}],connect:async()=>{connections++;},capture:()=>({rootState:root.state})};
 const off=root.onLock(()=>stops++),lifecycle=Lifecycle.attach(root,{coordinator:()=>coordinator});assert.equal(lifecycle.status().state,'LOCKED');
 const first={root:new Uint8Array(32).fill(7)};root._replaceState(first);await lifecycle.start();assert.equal(starts,1);assert.equal(connections,1);assert.equal(lifecycle.status().state,'READY');
 // Account logout is intentionally not an input to this root-only owner.
 const captured=await lifecycle.start();assert.equal(captured.rootState,first);assert.equal(starts,1);
 root.lock();assert.equal(stops,1);assert.equal(lifecycle.status().state,'LOCKED');assert(first.root.every(x=>x===0));
 hold=true;root._replaceState({root:new Uint8Array(32).fill(8)});const pending=lifecycle.start();await Promise.resolve();root.lock();release();await assert.rejects(pending,/SESSION_CHANGED/);assert.equal(connections,1);assert.equal(lifecycle.status().state,'LOCKED');
 hold=false;fail=true;root._replaceState({root:new Uint8Array(32).fill(9)});await assert.rejects(lifecycle.start(),/PIN_MISMATCH/);assert.equal(lifecycle.status().state,'UNAVAILABLE');assert.equal(connections,1);assert(root.state.root.every(x=>x===9),'network failure must preserve root');
 fail=false;await lifecycle.start();assert.equal(lifecycle.status().state,'READY');lifecycle.close();off();root.lock();console.log('PASS genuine DeviceRoot unlock/lock observers: root-only auto startup, coalescing, late-start invalidation, unavailable fail-closed, retained root and explicit retry; coordinator stub');
})().catch(e=>{console.error(e);process.exitCode=1;});
