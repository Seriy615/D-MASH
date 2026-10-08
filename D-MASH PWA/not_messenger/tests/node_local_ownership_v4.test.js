'use strict';
const assert=require('node:assert/strict');global.nacl=require('../js/vendor/nacl-fast.min.js');require('../js/secure_session.js');require('../js/route_discovery_v4.js');require('../js/recipient_payload_v4.js');const {NodeInboxV4}=require('../js/node_inbox_v4.js'),Local=require('../js/node_local_delivery_v4.js'),Ownership=require('../js/node_local_ownership_v4.js');
class Store{constructor(rows){this.rows=rows;}async open(){}async read(k){return structuredClone(this.rows.get(k)||null);}async all(){return structuredClone([...this.rows.values()].filter(r=>r.key!=='owner'&&!r.key.startsWith('binding:')));}async allBindings(){return structuredClone([...this.rows.values()].filter(r=>r.key==='owner'||r.key.startsWith('binding:')));}async cas(k,rev,row){const prior=this.rows.get(k);if((prior?.revision??null)!==rev)return false;this.rows.set(k,structuredClone({...row,key:k,revision:(rev??0)+1}));return true;}close(){}}
(async()=>{
 const rows=new Map(),root=crypto.getRandomValues(new Uint8Array(32)),account=nacl.sign.keyPair(),route=nacl.sign.keyPair(),sign=nacl.sign.keyPair(),box=nacl.box.keyPair(),recipient=nacl.box.keyPair(),hex=b=>Buffer.from(b).toString('hex'),now=Math.floor(Date.now()/1000);
 const cert=DmashRouteDiscoveryV4.issueCertificate(route,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600});
 let inbox,local,owner,runtime;
 async function open(){inbox=await NodeInboxV4.open(root,'a'.repeat(64),{store:new Store(rows)});runtime={owned:[],labels:new Map(),bindLocal(c,s,b,h){this.owned.push({certificate:c,sign:s,box:b,handler:h});}};local=new Local(runtime,inbox);owner=new Ownership(local,inbox);await local.restore();}
 async function register(){const c=await owner.challenge(hex(account.publicKey),cert),sig=nacl.sign.detached(new TextEncoder().encode(c.transcript),account.secretKey);return owner.register(c.challenge,sig);}
 await open();const cap=await register();
 const data=()=>({migrationId:'b'.repeat(64),bindingDigest:'c'.repeat(64),expectedGeneration:1,certificate:cert,discoverySeed:sign.secretKey.slice(0,32),discoveryBox:box.secretKey.slice(),recipientKeys:[recipient.secretKey.slice()]});
 await assert.rejects(owner.prepare(cap.token,{...data(),recipientKeys:[]}));
 await assert.rejects(owner.prepare(cap.token,{...data(),recipientKeys:[nacl.box.keyPair().secretKey]}));
 let material=data(),prepared=await owner.prepare(cap.token,material);assert.equal(prepared.state,'NODE_PREPARED');assert.equal(runtime.owned.length,0);assert(material.discoverySeed.every(v=>v===0));
 assert.deepEqual(await owner.prepare(cap.token,data()),prepared);
 await assert.rejects(owner.prepare(cap.token,{...data(),bindingDigest:'d'.repeat(64)}));
 owner.close();local.close();inbox.close();await open();assert.equal(runtime.owned.length,0);
 await assert.rejects(owner.query(cap.token,'b'.repeat(64)));
 const restored=await register();const q=await owner.query(restored.token,'b'.repeat(64));assert.deepEqual(q,prepared);
 const {state,...tuple}=q;const actualBind=local.bind.bind(local);local.bind=async()=>{throw Error('Injected dispatch installation failure');};await assert.rejects(owner.change(restored.token,tuple,'ACTIVE'));assert.equal((await owner.query(restored.token,'b'.repeat(64))).state,'ACTIVE');local.bind=actualBind;await owner.change(restored.token,tuple,'ACTIVE');assert.equal(runtime.owned.length,1);
 const blob=DmashRecipientPayloadV4.sealPayload(recipient.publicKey,'retained local delivery');await runtime.owned[0].handler(null,{payload:blob});assert.equal((await inbox.list(restored.ownerSlot)).records.length,1);
 owner.close();local.close();inbox.close();await open();assert.equal(runtime.owned.length,1);const after=await register();assert.equal((await inbox.list(after.ownerSlot)).records.length,1);
 const foreign=nacl.sign.keyPair(),challenge=await owner.challenge(hex(foreign.publicKey),cert);const f=await owner.register(challenge.challenge,nacl.sign.detached(new TextEncoder().encode(challenge.transcript),foreign.secretKey));await assert.rejects(owner.query(f.token,'b'.repeat(64)));
 await owner.change(after.token,tuple,'RETIRED');assert.equal(runtime.owned.length,0);assert.equal((await inbox.list(after.ownerSlot)).records.length,1);
 owner.close();local.close();inbox.close();await open();assert.equal(runtime.owned.length,0);
 console.log('node_local_ownership_v4 persistence/owner/isolation PASS');owner.close();local.close();inbox.close();
})().catch(e=>{console.error(e);process.exitCode=1;});
