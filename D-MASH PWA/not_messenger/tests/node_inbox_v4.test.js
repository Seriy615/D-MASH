'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
require('../js/route_discovery_v4.js');const codec=require('../js/recipient_payload_v4.js');
const {NodeInboxV4}=require('../js/node_inbox_v4.js');
const LocalDelivery=require('../js/node_local_delivery_v4.js');
class MemoryStore{
 constructor(rows=new Map()){this.rows=rows;this.closed=false;}
 async open(){return this;}
 check(){if(this.closed)throw Error('closed');}
 async read(key){this.check();return structuredClone(this.rows.get(key)||null);}
 async all(){this.check();return structuredClone([...this.rows.values()]);}
 async allBindings(){return (await this.all()).filter(row=>row.key==='owner'||row.key.startsWith('binding:'));}
 async cas(key,revision,row){this.check();const current=this.rows.get(key);if((current?.revision??null)!==revision)return false;if(row===null)this.rows.delete(key);else this.rows.set(key,structuredClone({...row,key,revision:(revision??0)+1}));return true;}
 async promote(sourceKey,sourceRevision,targetKey,targetRevision,row){this.check();const source=this.rows.get(sourceKey),target=this.rows.get(targetKey);if(!source||source.revision!==sourceRevision||(target?.revision??null)!==targetRevision)return false;if(row)this.rows.set(targetKey,structuredClone({...row,key:targetKey,revision:(targetRevision??0)+1}));this.rows.delete(sourceKey);return true;}
 close(){this.closed=true;}
}
(async()=>{
 const material=crypto.getRandomValues(new Uint8Array(32)),localId='a'.repeat(64),route='b'.repeat(64),recipient=nacl.box.keyPair(),rows=new Map();
 let now=1000000000;
 const open=()=>NodeInboxV4.open(material,localId,{store:new MemoryStore(rows),clock:()=>now});
 let inbox=await open();
 const blob=codec.sealPayload(recipient.publicKey,'opaque-A');
 assert.equal((await inbox.receive(route,'slot-A',blob,[])).status,'deferred');
 assert.equal((await inbox.list('slot-A')).records.length,0);
 assert.equal(await inbox.retryDeferred(route,'slot-B',[recipient.secretKey]),0);
 assert.equal(await inbox.retryDeferred(route,'slot-A',[recipient.secretKey]),1);
 const [first]= (await inbox.list('slot-A')).records;
 assert.equal(first.payload,'opaque-A');
 assert.equal((await inbox.list('slot-B')).records.length,0);
 await assert.rejects(inbox.acknowledge(first.handle,'slot-B'),/mismatch/);
 inbox.close();inbox=await open();
 assert.equal((await inbox.list('slot-A')).records[0].payload,'opaque-A');
 assert.equal(await inbox.acknowledge(first.handle,'slot-A'),true);
 assert.equal((await inbox.receive(route,'slot-A',blob,[recipient.secretKey])).inserted,false);
 assert.equal((await inbox.list('slot-A')).records.length,0);
 assert.equal((await inbox.receive(route,'slot-A',codec.coverBox(),[recipient.secretKey])).status,'discard');
 const good=codec.sealPayload(recipient.publicKey,'after damaged record');
 const duplicate=await Promise.all([inbox.receive(route,'slot-B',good,[recipient.secretKey]),inbox.receive(route,'slot-B',good,[recipient.secretKey])]);
 assert.equal(duplicate.filter(result=>result.inserted).length,1);
 const damagedBlob=codec.sealPayload(recipient.publicKey,'damaged');
 await inbox.receive(route,'slot-A',damagedBlob,[recipient.secretKey]);
 const bad=(await inbox.list('slot-A')).records[0];
 new Uint8Array(rows.get(bad.handle).ciphertext)[0]^=1;
 assert.equal((await inbox.list('slot-B')).records[0].payload,'after damaged record');
 assert.equal((await inbox.list('slot-B')).unreadable,1);
 assert(!JSON.stringify([...rows.values()]).includes('opaque-A'));
 assert([...rows.keys()].every(key=>key==='owner'||/^[0-9a-f]{64}$/.test(key)));
 now+=30*86400000+1;assert.equal(await inbox.pruneSeen(),1);
 inbox.close();
 await assert.rejects(NodeInboxV4.open(new Uint8Array(32),localId,{store:new MemoryStore(rows)}));
 await assert.rejects(NodeInboxV4.open(material,'c'.repeat(64),{store:new MemoryStore(rows)}));
 await assert.rejects(inbox.list('slot-A'),/closed/);
 const ownRows=new Map(),ownInbox=await NodeInboxV4.open(material,localId,{store:new MemoryStore(ownRows)});
 const runtime={owned:[],bindLocal(certificate,sign,box,handler){this.owned.push({certificate,sign,box,handler});}};
 let broker=new LocalDelivery(runtime,ownInbox);
 const owner=nacl.sign.keyPair(),discovery=nacl.sign.keyPair(),box=nacl.box.keyPair();
 const seconds=Math.floor(Date.now()/1000);
 const certificate=DmashRouteDiscoveryV4.issueCertificate(owner,discovery.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:seconds,expiresAt:seconds+3600});
 await broker.bind({certificate,accountSlot:'slot-A',discoverySeed:discovery.secretKey.slice(0,32),discoveryBox:box.secretKey,recipientKeys:[]});
 await runtime.owned[0].handler(null,{payload:blob});
 assert.equal((await ownInbox.list('slot-A')).deferred,1);
 await assert.rejects(broker.installRecipientKeys(certificate.route_id,[nacl.box.keyPair().secretKey]),/mismatch/);
 assert.equal((await ownInbox.list('slot-A')).deferred,1);
 assert.equal((await broker.installRecipientKeys(certificate.route_id,[recipient.secretKey])).processed,1);
 broker.close();assert(runtime.owned[0].sign.secretKey.every(value=>value===0));
 await assert.rejects(runtime.owned[0].handler(null,{payload:blob}),/closed/);
 runtime.owned=[];broker=new LocalDelivery(runtime,ownInbox);
 assert.deepEqual(await broker.restore(),{restored:1,unavailable:0});
 assert.equal((await ownInbox.list('slot-A')).records.length,1);
 broker.close();ownInbox.close();owner.secretKey.fill(0);discovery.secretKey.fill(0);box.secretKey.fill(0);
 recipient.secretKey.fill(0);material.fill(0);
 console.log('PASS v4 Inbox: encrypted persistence, deferred keys, Account isolation, post-persist receipt, replay tombstones, concurrent duplicate and damaged-record isolation');
})().catch(error=>{console.error(error);process.exitCode=1;});
