'use strict';
// IPC/lifecycle tests use a controlled Worker adapter. Real Worker crypto/socket
// acceptance is tools/test_node_transit_browser.cjs with DMASH_TRANSIT_WORKER=1.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const instances=[];
class WorkerAdapter{
 constructor(){this.messages=[];this.hold=false;this.terminated=false;instances.push(this);}
 postMessage(message,transfer=[]){
  const copy=structuredClone(message,{transfer});this.messages.push(copy);
  if(copy.type==='STOP'||this.hold)return;
  queueMicrotask(()=>this.onmessage?.({data:{id:copy.id,ok:true,result:copy.type==='INIT'?{nodeId:'ab'.repeat(32),worker:true}:{}}}));
 }
 terminate(){this.terminated=true;}
}
const context={document:{currentScript:{src:'https://example.invalid/js/node_runtime_host_v4.js'}},Worker:WorkerAdapter,
 Uint8Array,URL,WeakMap,Map,AbortController,crypto:global.crypto,setTimeout,clearTimeout,
 DmashNodeIdentity:{async unlockDeviceIdentity(){return {signing:{secretKey:new Uint8Array(64).fill(7)}};}}};
vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../js/node_runtime_host_v4.js'),'utf8'),context);
const Host=context.DmashNodeRuntimeHostV4;
const materials=()=>({seed:new Uint8Array(32).fill(1),storageKey:new Uint8Array(32).fill(2),baseNcrh:new Uint8Array(32).fill(3)});
(async()=>{
 const backing=new Uint8Array(256).fill(99),input={...materials(),seed:backing.subarray(0,32)};
 const host=await Host.startMaterials(input),worker=instances.at(-1),init=worker.messages[0];
 assert.equal(init.seed.buffer.byteLength,32,'unrelated bytes from a backing buffer must never reach the actor');
 assert(backing.subarray(32).every(b=>b===99));assert(input.seed.every(b=>b===0));assert(input.storageKey.every(b=>b===0));
 worker.hold=true;const pending=Array.from({length:16},()=>host.stats());
 await assert.rejects(host.stats(),/quota/);host.close();
 assert((await Promise.allSettled(pending)).every(row=>row.status==='rejected'));await assert.rejects(host.stats(),/closed/);
 const controller=new AbortController(),starting=Host.startMaterials(materials(),{signal:controller.signal});controller.abort();
 await assert.rejects(starting);
 const watchers=new Set(),root={state:{root:new Uint8Array(32).fill(4)},
  onLock(fn){watchers.add(fn);return()=>watchers.delete(fn);},async derive(){return new Uint8Array(32).fill(8);},
  async deviceMaterial(name,create){assert.equal(name,'node-base-ncrh-v4');return create();}};
 const owned=await Host.startForDevice(root);assert.equal(watchers.size,1);
 await assert.rejects(Host.startForDevice(root),/already owns/);assert.equal(watchers.size,1);
 root.state=null;for(const notify of [...watchers])notify();assert(owned.closed);assert.equal(watchers.size,0);
 await assert.rejects(owned.stats(),/closed/);
 await new Promise(resolve=>setTimeout(resolve,300));assert(instances.every(instance=>instance.terminated));
 console.log('PASS Worker material isolation, RPC quotas, pending cancellation, single root-session ownership and lock cleanup');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
