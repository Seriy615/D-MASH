'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const now=100000,day=86400000,calls=[],timers=new Map();let serial=0,next=null,due=[];
const routing={peers:new Map(),send(){},enqueue(){}};
const ctx=vm.createContext({Map,Set,WeakMap,TextEncoder,TextDecoder,Uint8Array,Uint32Array,Date:{now:()=>now},Math,JSON,Error,Promise,crypto:require('node:crypto').webcrypto,
 setTimeout(fn,delay){const id=++serial;timers.set(id,{fn,delay});return id;},clearTimeout(id){timers.delete(id);}});
vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../js/job_runtime.js'),'utf8'),ctx);
const host=(op,...args)=>{calls.push([op,...args]);if(op==='jobsNext')return next;if(op==='jobsDue')return due;if(op==='jobsClaim')return null;};
const runtime=new ctx.NativeJobRuntime({host,routing,local:{releaseOwnerGrants(){}},inbox:{},ownership:{},current:()=>true,report(){}});
runtime.tick();assert(calls.some(c=>c[0]==='jobsPrune'));assert.equal(timers.size,0);assert.equal(calls.find(c=>c[0]==='jobsDue')[2],false);
next=now+8*day;runtime.arm();assert.equal([...timers.values()][0].delay,8*day);
calls.length=0;due=[{id:'job',destination:'dest',revision:1,expiresAt:now+day}];next=now+day;runtime.tick();
assert.deepEqual(calls.find(c=>c[0]==='jobsDefer'),['jobsDefer','job',1,'WAITING_BOOTSTRAP',now+day]);
routing.peers.set('peer',{});calls.length=0;runtime.tick();assert.equal(calls.find(c=>c[0]==='jobsDue')[2],true);assert.deepEqual(calls.find(c=>c[0]==='jobsClaim'),['jobsClaim','job',1,true]);
runtime.close();assert.equal(timers.size,0);
console.log('native jobs: retention prune, single deadline, no offline poll, peer-driven wake, close PASS');
