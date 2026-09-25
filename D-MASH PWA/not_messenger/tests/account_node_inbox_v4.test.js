'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {createCore,nacl}=require('./fixtures/core_vm.cjs');
global.nacl=nacl;require('../js/route_discovery_v4.js');const codec=require('../js/recipient_payload_v4.js');
const {NodeInboxV4}=require('../js/node_inbox_v4.js');
const Bridge=require('../js/account_node_inbox_v4.js');
class Store{
 constructor(){this.rows=new Map();}
 async open(){}
 async read(key){return structuredClone(this.rows.get(key)||null);}
 async all(){return structuredClone([...this.rows.values()]);}
 async cas(key,revision,row){const old=this.rows.get(key);if((old?.revision??null)!==revision)return false;this.rows.set(key,structuredClone({...row,key,revision:(revision??0)+1}));return true;}
 close(){}
}
const hex=value=>Buffer.from(value).toString('hex');
(async()=>{
 const [a,b]=await Promise.all([createCore(),createCore()]);
 const shared=hex(nacl.randomBytes(32)),route='b'.repeat(64),recipient=nacl.box.keyPair();
 const messages=new Map(),receipts=[];let writes=0,failPersist=false,failAck=false,now=1000;
 for(const [local,peer] of [[a,b],[b,a]]){
  for(const file of ['account_ratchet.js','account_ratchet_runtime.js'])vm.runInContext(fs.readFileSync(require.resolve('../js/'+file),'utf8'),local.ctx);
  local.core.activeIdentity=local===a?'slot-A':'slot-B';local.core.blindSalt=nacl.randomBytes(32);
  await local.storage.putBox('blind_peers',{alias:peer.core.keys.pub_hex,data:{curvePub:hex(peer.core.keys.box.publicKey)}});
  await local.storage.putBox('blind_secrets',{alias:peer.core.keys.pub_hex,data:{staticShared:shared,ratchetRoot:shared,ratchetEpoch:1}});
 }
 await b.storage.putBox('pairing_material',{alias:'node-route-v4:'+route,data:{peerId:a.core.keys.pub_hex}});
 b.storage.hasMessageWireId=async(peer,id)=>messages.has(peer+id);
 b.storage.saveMessageGamma=async(peer,body,inbound,read,state,id)=>{if(failPersist)throw Error('Disk failure');writes++;messages.set(peer+id,body);return writes;};
 b.core.sendMessage=async message=>{receipts.push(message);return true;};b.core.renderPeers=async()=>{};
 const inbox=await NodeInboxV4.open(nacl.randomBytes(32),'a'.repeat(64),{store:new Store(),clock:()=>now++});
 const host={closed:false,inboxList:(...args)=>inbox.list(...args),acknowledgeInbox:(...args)=>{if(failAck){failAck=false;throw Error('Worker reply lost');}return inbox.acknowledge(...args);}};
 const bridge=new Bridge(host,b.core);
 const payload=async(id,body)=>{const ciphertext=await a.core.encrypt(JSON.stringify({type:'dmash_message',id,body}),b.core.keys.pub_hex);return JSON.stringify({version:1,ciphertext,sender_proof:hex(nacl.sign.detached(Buffer.from(ciphertext,'hex'),a.core.keys.sign.secretKey))});};
 const deliver=async value=>inbox.receive(route,'slot-B',codec.sealPayload(recipient.publicKey,value),[recipient.secretKey]);
 await deliver(await payload('one','real authenticated Account message'));
 const bKeys=b.core.keys;b.core.activeIdentity='slot-A';
 assert.equal((await bridge.drain()).processed,0);assert.equal(writes,0);b.core.activeIdentity='slot-B';
 failPersist=true;assert.equal((await bridge.drain()).failed,1);assert.equal((await inbox.list('slot-B')).records.length,1);
 failPersist=false;failAck=true;assert.equal((await bridge.drain()).failed,1);assert.equal(writes,1);
 assert.equal((await bridge.drain()).processed,1);assert.equal(writes,1,'Account persistence before lost Inbox receipt must not duplicate history');
 assert.equal(messages.get(a.core.keys.pub_hex+'one'),'real authenticated Account message');assert.equal(receipts[0].state,'DELIVERED');
 const invalid=JSON.stringify({version:1,ciphertext:'0400',sender_proof:'00'.repeat(64)});
 for(let i=0;i<129;i++)await deliver(invalid);
 await deliver(await payload('two','valid after 129 rejected records'));
 assert.equal((await bridge.drain()).failed,128);assert.equal(writes,1);
 const next=await bridge.drain();assert.equal(next.failed,1);assert.equal(next.processed,1);assert.equal(writes,2);
 assert.equal((await inbox.list('slot-B',128)).records.length,128,'rejected records are retained, not acknowledged as delivered');
 // Cancel between list and dispatch; stale Account work must not reach crypto.
 const originalList=host.inboxList;let release,entered;
 const listed=new Promise(resolve=>entered=resolve);
 host.inboxList=async(...args)=>{const page=await originalList(...args);entered();await new Promise(resolve=>release=resolve);return page;};
 const task=bridge.drain();await listed;b.core.keys={...bKeys};release();await task;assert.equal(writes,2);host.inboxList=originalList;b.core.keys=bKeys;
 bridge.close();assert.equal((await bridge.drain()).processed,0);inbox.close();recipient.secretKey.fill(0);
 console.log('PASS real Account ratchet + recipient crypto through v4 Inbox: slot/proof isolation, persist failure, lost local receipt dedupe, bounded poison-page progress and session cancellation (established Account fixture)');
})().catch(error=>{console.error(error);process.exitCode=1;});
