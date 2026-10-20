'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
(async()=>{
 const slot='c'.repeat(64),routeId='d'.repeat(64),handle='e'.repeat(64),authority='f'.repeat(64),responses=[];
 const binding={state:'ACTIVE',certificate:{generation:1},ownership:{ownerSlot:slot,routeAuthorityDigest:authority,generation:1}};
 let record={kind:'pending',accountSlot:slot,routeId,payload:'opaque fixture'},revision=1,failCommit=false;
 const inbox={close(){},store:{async read(id){return id===handle?{revision,value:record}:null;},async cas(id,expected,row,{guard}){assert.equal(id,handle);guard();if(failCommit)throw Error('simulated failed transaction');assert.equal(expected,revision);record=row;revision++;return true;}},async decrypt(row){return row.value;},async encrypt(id,value){assert.equal(id,handle);return value;}};
 const ctx=vm.createContext({Uint8Array,Map,Set,Promise,AbortController,Error,Number,String,Object,Array,Date,setTimeout,clearTimeout,
  NativePlatform:{host(op,...args){if(op==='jobsOpen')return {ownerGeneration:1};if(op==='jobsPolicy')return {enabled:true};if(op==='localReply')responses.push(JSON.parse(args[1]));},close(){}},
  nacl:{sign:{keyPair:{fromSeed:()=>({publicKey:new Uint8Array(32),secretKey:new Uint8Array(64)})}}},
  DmashNodeInboxV4:{open:async()=>inbox},DmashNodeLocalDeliveryV4:class{async restore(){return {};}close(){}},
  DmashNodeLocalOwnershipV4:class{constructor(){this.owners=new Map();}async register(){return {token:'owner'};}owner(){return {ownerSlot:slot,routeId,routeAuthorityDigest:authority};}async read(){return binding;}matches(row,owner){assert.equal(row.ownership.ownerSlot,owner.ownerSlot);assert.equal(row.ownership.routeAuthorityDigest,owner.routeAuthorityDigest);}close(){}},
  NativeJobRuntime:class{wake(){}close(){}},DmashNodeIdentity:{verify:()=>true},DmashNodeRelationshipsV4:{open:async()=>({close(){}})},DmashNodeRoutingV4:class{constructor(){this.peers=new Map();}close(){}}});
 vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../js/runtime_entry.js'),'utf8'),ctx);
 const flush=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};
 ctx.NativeNode.initialize({seed:new Uint8Array(32),storageKey:new Uint8Array(32),baseNcrh:new Uint8Array(32),transportGeneration:1,policyRevision:1,directEnabled:false});await flush();
 const connectionId='a'.repeat(64);ctx.NativeNode.openLocal({connectionId,role:'owner'});
 const call=async(method,params)=>{ctx.NativeNode.dispatchLocal({connectionId,id:'b'.repeat(64),method,params});await flush();assert.equal(responses.length,1);return responses.pop();};
 assert((await call('owner.register',{challenge:'unused',signature:'0'.repeat(128)})).ok);
 const params={recordHandle:handle,applicationCommitToken:'saved-message-1'};
 failCommit=true;assert.equal((await call('inbox.commitConsumption',params)).ok,false);assert.equal(record.kind,'pending');
 failCommit=false;const done=await call('inbox.commitConsumption',params);assert(done.ok);assert.equal(record.kind,'seen');assert.equal(record.applicationCommitToken,params.applicationCommitToken);assert.equal(revision,2);
 assert.deepEqual(await call('inbox.commitConsumption',params),done);assert.equal(revision,2);
 assert.equal((await call('inbox.commitConsumption',{...params,applicationCommitToken:'saved-message-2'})).ok,false);
 binding.ownership.generation=2;binding.certificate.generation=2;assert.equal((await call('inbox.commitConsumption',params)).ok,false);
 ctx.NativeNode.stop();console.log('native Inbox commit: failed CAS retains pending, atomic token, identical retry, conflict and binding generation PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
