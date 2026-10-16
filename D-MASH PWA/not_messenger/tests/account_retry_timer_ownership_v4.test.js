'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../js/account_session_runtime_v4.js'),'utf8');
const settle=async()=>{for(let i=0;i<12;i++)await Promise.resolve();};
function fixture(){
 let now=0,next=0,calls=0,active=0,maxActive=0;const timers=new Map(),releases=[];
 const ctx={Uint8Array,Promise,Map,Set,WeakMap,crypto,module:{exports:{}},setTimeout(fn,delay){const id=++next;timers.set(id,{fn,due:now+delay});return id;},clearTimeout(id){timers.delete(id);}};
 vm.runInNewContext(source,ctx);const Runtime=ctx.module.exports,abort=new AbortController(),root={alive:true};
 const capture={signal:abort.signal,keys:{sign:{publicKey:new Uint8Array(32).fill(1)}},blindSalt:new Uint8Array(32),masterKey:{},db:{},assertCurrent(){if(abort.signal.aborted||!root.alive)throw Error('STALE_SYNTHETIC_ACCOUNT');}};
 const runtime=new Runtime({core:{captureAccountSessionV4:()=>capture},transport:{readRouteSnapshot(){assert.fail('scheduler test must not access routes');},prepareAndSubmitIntent(){assert.fail('scheduler test must not access network');}},profile:{createCodec:()=>({})},Session:{},Store:{},nacl:{},kem:{},discovery:{}});
 runtime.resume=async()=>{calls++;active++;maxActive=Math.max(maxActive,active);await new Promise(resolve=>releases.push(resolve));active--;};
 const advance=async ms=>{now+=ms;for(const [id,task]of [...timers])if(task.due<=now){timers.delete(id);void task.fn();}await settle();};
 const releaseAll=async()=>{for(const release of releases.splice(0))release();await settle();};
 return {runtime,abort,root,timers,advance,releaseAll,get calls(){return calls;},get maxActive(){return maxActive;}};
}
(async()=>{
 // Baseline cadence and cancellation stay covered even while the overlap case is RED.
 const normal=fixture();normal.runtime.startRetries();normal.runtime.startRetries();assert.equal(normal.timers.size,1);
 await normal.advance(4999);assert.equal(normal.calls,0);await normal.advance(1);assert.equal(normal.calls,1);
 await normal.releaseAll();assert.equal(normal.timers.size,1);await normal.advance(4999);assert.equal(normal.calls,1);await normal.advance(1);assert.equal(normal.calls,2);
 normal.abort.abort();await normal.releaseAll();assert.equal(normal.timers.size,0);await normal.advance(100000);assert.equal(normal.calls,2,'abort prevents any further resume');
 const closing=fixture();closing.runtime.startRetries();await closing.advance(5000);closing.runtime.close();await closing.releaseAll();assert.equal(closing.timers.size,0,'late completion after close must not resurrect retry timer');
 // Model actual pollSessions/startRetries calls while a long resume is in flight.
 const overlap=fixture();overlap.runtime.startRetries();await overlap.advance(5000);assert.equal(overlap.calls,1);
 for(let i=0;i<8;i++)overlap.runtime.startRetries();await overlap.advance(5000);
 await overlap.releaseAll();const pendingAfterSettlement=overlap.timers.size;overlap.runtime.close();const pendingAfterClose=overlap.timers.size;
 await overlap.advance(100000);assert.equal(overlap.calls,overlap.maxActive,'closed leaked wakeups cannot perform protocol work');
 console.log(JSON.stringify({scope:'scheduler only; deferred resume, fake timer clock, no storage/network/crypto acceptance',normalCadenceAndAbort:'PASS',lateCloseCompletion:'PASS',maxConcurrentResume:overlap.maxActive,pendingAfterSettlement,pendingAfterClose}));
 assert.deepEqual({maxConcurrentResume:overlap.maxActive,pendingAfterSettlement,pendingAfterClose},{maxConcurrentResume:1,pendingAfterSettlement:1,pendingAfterClose:0},'repeated startRetries during an awaited resume must preserve one retry train and close must own every timer');
 console.log('PASS Account retry scheduler keeps one resume train across repeated starts and cancels owned timers on abort/close');
})().catch(error=>{console.error(error);process.exitCode=1;});
