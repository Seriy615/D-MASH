'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
(async()=>{
 const events=[],attempts=[],waiting=[],timers=new Map();let timerId=0,active=0,maxActive=0,enabled=true;
 const ctx=vm.createContext({Uint8Array,Map,Set,Promise,AbortController,Error,Number,String,Object,Array,
  setTimeout(fn,delay){assert(delay>=0&&delay<=30000);const id=++timerId;timers.set(id,fn);return id;},clearTimeout(id){timers.delete(id);},
  NativePlatform:{host(op,payload){if(op==='report')events.push(JSON.parse(payload));if(op==='jobsOpen')return {ownerGeneration:1};if(op==='jobsPolicy')return {enabled,transportGeneration:1};if(op==='jobsSetPolicy'){enabled=payload===2;return {enabled};}},close(){}},
  nacl:{sign:{keyPair:{fromSeed:()=>({publicKey:new Uint8Array(32),secretKey:new Uint8Array(64)})}}},
  DmashNodeInboxV4:{open:async()=>({close(){}})},DmashNodeLocalDeliveryV4:class{async restore(){return {};}close(){}},DmashNodeLocalOwnershipV4:class{close(){}},NativeJobRuntime:class{wake(){}close(){}wrapChannel(ch){return ch;}},DmashNodeIdentity:{verify:()=>true},DmashNodeRelationshipsV4:{open:async()=>({close(){}})},
  DmashNodeRoutingV4:class{constructor(){this.peers=new Map();}async addPeer(id,ch){assert(!this.peers.has(id));this.peers.set(id,ch);}removePeer(id){this.peers.delete(id);}close(){}},
  DmashNodeSocketV4:{connect(url,signing,id){attempts.push({url,id});maxActive=Math.max(maxActive,++active);return new Promise((resolve,reject)=>waiting.push({url,id,resolve,reject}));}},
  DmashNodeChannelV4:{authorize:async secure=>({secure,close(){}})}});
 vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../js/runtime_entry.js'),'utf8'),ctx);
 const flush=async()=>{for(let i=0;i<12;i++)await Promise.resolve();};
 ctx.NativeNode.initialize({seed:new Uint8Array(32),storageKey:new Uint8Array(32),baseNcrh:new Uint8Array(32),transportGeneration:1,policyRevision:1,directEnabled:false});await flush();
 for(const [index,nodeId,url] of [[0,'A','a1'],[1,'A','a2'],[2,'B','b1'],[3,'C','c1']])ctx.NativeNode.connect({index,nodeId,url});
 await flush();assert.equal(waiting.length,2);assert.equal(maxActive,2);assert.equal(attempts.filter(a=>a.id==='A').length,1);
 const a=waiting.find(a=>a.id==='A');active--;a.reject(Error('offline'));await flush();
 assert(attempts.some(a=>a.id==='C'));assert(!attempts.some(a=>a.url==='a2'));
 const retry=[...timers.values()][0];timers.clear();retry();await flush();assert(!attempts.some(a=>a.url==='a2'));
 const b=waiting.find(a=>a.id==='B');active--;b.resolve({signal:new AbortController().signal,session:{peerRole:'NODE',version:4},close(){}});await flush();
 assert(attempts.some(a=>a.url==='a2'));assert.equal(maxActive,2);
 // Repeated outages must not permanently exhaust the configured identity.
 const c=waiting.find(a=>a.id==='C');active--;c.reject(Error('offline'));await flush();
 let failed=0;
 for(let n=0;n<12;n++){
  const callbacks=[...timers.values()];timers.clear();for(const fn of callbacks)fn();await flush();
  for(const pending of waiting.splice(0))if(![a,b,c].includes(pending)){active--;pending.reject(Error('offline'));failed++;}
  await flush();
 }
 assert(failed>6,'reconnect continues beyond three attempts per URL');assert(timers.size>0);
 enabled=false;const before=attempts.length;
 for(const callback of timers.values())callback();timers.clear();await flush();assert.equal(attempts.length,before);assert.equal(timers.size,0);
 ctx.NativeNode.openLocal({connectionId:'a'.repeat(64),role:'broker'});
 ctx.NativeNode.dispatchLocal({connectionId:'a'.repeat(64),id:'b'.repeat(64),method:'broker.policy',params:{generation:1,revision:2,transportEnabled:true,directEnabled:false}});await flush();
 assert(attempts.length>before,'explicit policy resume restarts recovery');
 ctx.NativeNode.stop();assert.equal(timers.size,0);assert(!events.some(e=>e.event==='error'));
 console.log('endpoint scheduler: max2 active, identity dedupe, alternate URL retry, queued3rd, persistent bounded recovery, policy pause/resume, close PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
