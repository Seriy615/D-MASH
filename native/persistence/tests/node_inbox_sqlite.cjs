'use strict';
// Actual unchanged NodeInboxV4 consumer and real WebCrypto/NaCl over the C++
// SQLite port. This one-shot CLI transport is a test adapter, not product IPC.
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../../..');
const js = path.join(root, 'D-MASH PWA/not_messenger/js');
global.nacl = require(path.join(js, 'vendor/nacl-fast.min.js'));
require(path.join(js, 'route_discovery_v4.js'));
const codec = require(path.join(js, 'recipient_payload_v4.js'));
const {NodeInboxV4,InboxStore} = require(path.join(js, 'node_inbox_v4.js'));
const LocalDelivery = require(path.join(js, 'node_local_delivery_v4.js'));
const binary = process.argv[2];
assert(binary && fs.existsSync(binary), 'supply built dmash_inbox_bridge path');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dmash-inbox-sql-'));
const encode = row => row === null ? null : {iv: Buffer.from(row.iv).toString('base64'), ciphertext: Buffer.from(row.ciphertext).toString('base64')};
const decode = row => row === null ? null : {...row, iv: Uint8Array.from(Buffer.from(row.iv, 'base64')), ciphertext: Uint8Array.from(Buffer.from(row.ciphertext, 'base64')).buffer};
class NativeStore {
  constructor(file, {maxRecords=4096, maxBytes=32*1024*1024}={}) { Object.assign(this,{file,maxRecords,maxBytes,closed:false}); }
  check(){ if(this.closed) throw Error('Native Inbox closed'); }
  run(q){
    this.check();
    const raw=execFileSync(binary,[this.file,String(this.maxRecords),String(this.maxBytes)],{input:JSON.stringify(q)+'\n',encoding:'utf8',maxBuffer:96*1024*1024,timeout:10000});
    const result=JSON.parse(raw); if(!result.ok)throw Error(result.error);return result.value;
  }
  async open(){this.check();return this;}
  async reconcile(){this.run({op:'reconcile'});}
  async read(key){return decode(this.run({op:'read',key}));}
  async all(){return this.run({op:'all'}).map(decode);}
  async allBindings(){return this.run({op:'allBindings'}).map(decode);}
  async cas(key,revision,row,{guard=()=>true}={}){this.check();if(!guard())throw Error('Inbox owner session changed');return this.run({op:'cas',key,revision,row:encode(row)});}
  async promote(sourceKey,sourceRevision,targetKey,targetRevision,row){return this.run({op:'promote',sourceKey,sourceRevision,targetKey,targetRevision,row:encode(row)});}
  close(){this.closed=true;}
}
(async()=>{
  const file=path.join(dir,'node.sqlite'),local='a'.repeat(64),route='b'.repeat(64),slot='synthetic-local-slot';
  const material=nacl.randomBytes(32),recipient=nacl.box.keyPair();let now=1000000000;
  const open=()=>NodeInboxV4.open(material,local,{store:new NativeStore(file),clock:()=>now});
  let inbox=await open();
  const opaque='synthetic-opaque-account-frame-20261020',sealed=codec.sealPayload(recipient.publicKey,opaque);
  assert.equal((await inbox.receive(route,slot,sealed,[])).status,'deferred');
  assert.equal(await inbox.retryDeferred(route,'other-slot',[recipient.secretKey]),0);
  assert.equal(await inbox.retryDeferred(route,slot,[recipient.secretKey]),1);
  assert.equal((await inbox.list(slot)).records[0].payload,opaque);
  assert.equal((await inbox.store.all()).length,1,'atomic promotion removes source rather than double-counting');
  assert.equal((await inbox.store.allBindings()).length,1,'owner in separate bindings bucket');
  const [message]=(await inbox.list(slot)).records;
  await assert.rejects(inbox.acknowledge(message.handle,'other-slot'),/mismatch/);
  await assert.rejects(inbox.acknowledge(message.handle,slot,{guard:()=>false}),/session changed/);
  assert.equal((await inbox.list(slot)).records.length,1);
  inbox.close();inbox=await open();
  assert.equal((await inbox.list(slot)).records[0].payload,opaque,'reopened actual encrypted SQL row');
  assert.equal(await inbox.acknowledge(message.handle,slot),true);
  // Exact replay tombstone must survive deferred->seen promotion without
  // replacing the target or resurrecting an acknowledged message.
  await inbox.receive(route,slot,sealed,[]);
  assert.equal(await inbox.retryDeferred(route,slot,[recipient.secretKey]),1);
  assert.equal((await inbox.list(slot)).records.length,0);
  assert.equal((await inbox.store.all()).length,1);
  const second=codec.sealPayload(recipient.publicKey,'synthetic second frame');
  const duplicates=await Promise.all([inbox.receive(route,'other-slot',second,[recipient.secretKey]),inbox.receive(route,'other-slot',second,[recipient.secretKey])]);
  assert.equal(duplicates.filter(x=>x.inserted).length,1);
  const victim=(await inbox.list('other-slot')).records[0],row=await inbox.store.read(victim.handle);
  new Uint8Array(row.ciphertext)[0]^=1;assert(await inbox.store.cas(victim.handle,row.revision,row));
  const damage=await inbox.list(slot);assert.equal(damage.unreadable,1);assert.equal(damage.records.length,0);
  await inbox.saveBinding(route,{ownerSlot:slot});assert.equal((await inbox.bindings()).records.length,1);
  assert.equal((await inbox.store.allBindings()).length,2);
  now+=30*86400000+1;assert.equal(await inbox.pruneSeen(),1);
  inbox.close();await assert.rejects(inbox.list(slot),/closed/);
  await assert.rejects(NodeInboxV4.open(new Uint8Array(32),local,{store:new NativeStore(file)}));
  await assert.rejects(NodeInboxV4.open(material,'c'.repeat(64),{store:new NativeStore(file)}));
  for(const suffix of ['','-wal','-shm'])if(fs.existsSync(file+suffix))assert(!fs.readFileSync(file+suffix).includes(Buffer.from(opaque)),'no application frame at rest');
  // Existing route owner/local delivery consumer also restores encrypted
  // bindings and promotes pending ciphertext through the same SQL adapter.
  const localFile=path.join(dir,'local.sqlite'),owned=await NodeInboxV4.open(material,local,{store:new NativeStore(localFile)});
  const runtime={owned:[],bindLocal(certificate,sign,box,handler){this.owned.push({certificate,sign,box,handler});}};
  let delivery=new LocalDelivery(runtime,owned);const owner=nacl.sign.keyPair(),discovery=nacl.sign.keyPair(),box=nacl.box.keyPair(),seconds=Math.floor(Date.now()/1000);
  const certificate=DmashRouteDiscoveryV4.issueCertificate(owner,discovery.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:seconds,expiresAt:seconds+3600});
  await delivery.bind({certificate,accountSlot:slot,discoverySeed:discovery.secretKey.slice(0,32),discoveryBox:box.secretKey,recipientKeys:[]});
  await runtime.owned[0].handler(null,{payload:sealed});assert.equal((await owned.list(slot)).deferred,1);
  assert.equal((await delivery.installRecipientKeys(certificate.route_id,[recipient.secretKey])).processed,1);
  delivery.close();runtime.owned=[];delivery=new LocalDelivery(runtime,owned);assert.deepEqual(await delivery.restore(),{restored:1,unavailable:0});
  assert.equal((await owned.list(slot)).records[0].payload,opaque);delivery.close();owned.close();
  // Differentially execute bounded stateful traces against the actual original
  // IndexedDB store, not a copied model/helper. Covers competing revisions,
  // inserts/deletes/replacements, failed growth and promotions to absent or
  // present targets, including preserve-target semantics and resulting rows.
  global.indexedDB=new (require('fake-indexeddb').IDBFactory)();
  const idb=await new InboxStore({databaseName:'differential',maxRecords:3,maxBytes:1024}).open();
  const native=new NativeStore(path.join(dir,'differential.sqlite'),{maxRecords:3,maxBytes:1024});await native.open();
  await idb.reconcile();await native.reconcile();
  const encrypted=n=>({iv:new Uint8Array(12).fill(1),ciphertext:new Uint8Array(n).fill(7).buffer});
  const outcome=async f=>{try{return {ok:await f()};}catch(_){return {rejected:true};}};
  const normalize=rows=>rows.map(r=>({key:r.key,revision:r.revision,iv:Buffer.from(r.iv).toString('hex'),ciphertext:Buffer.from(r.ciphertext).toString('hex')})).sort((a,b)=>a.key.localeCompare(b.key));
  const keys=['d'.repeat(64),'e'.repeat(64),'f'.repeat(64)];
  const compare=async(op,args)=>{
    const before=await outcome(()=>idb[op](...args)),after=await outcome(()=>native[op](...args));assert.deepEqual(after,before,op+' outcome');
    assert.deepEqual(normalize(await native.all()),normalize(await idb.all()),op+' records');
    assert.deepEqual(normalize(await native.allBindings()),normalize(await idb.allBindings()),op+' bindings');
  };
  await compare('cas',['owner',null,encrypted(32)]);
  await compare('cas',[keys[0],null,encrypted(200)]);await compare('cas',[keys[1],null,encrypted(300)]);
  await compare('cas',[keys[2],null,encrypted(400)]); // over byte quota, no mutation
  await compare('promote',[keys[0],1,keys[2],null,encrypted(200)]);
  await compare('promote',[keys[2],1,keys[1],1,null]); // preserve exact target
  let rng=20261020;
  const random=n=>{rng=(Math.imul(rng,1664525)+1013904223)>>>0;return rng%n;};
  for(let i=0;i<64;i++){
    const key=keys[random(3)],rev=[null,1,2,3][random(4)],replacement=random(4)===0?null:encrypted([16,200,700][random(3)]);
    if(i%3)await compare('cas',[key,rev,replacement]);
    else {const target=keys[(keys.indexOf(key)+1+random(2))%3];await compare('promote',[key,rev??1,target,[null,1,2][random(3)],replacement]);}
  }
  idb.close();native.close();
  material.fill(0);recipient.secretKey.fill(0);owner.secretKey.fill(0);discovery.secretKey.fill(0);box.secretKey.fill(0);
  console.log('PASS unchanged NodeInboxV4/LocalDelivery consumers: actual encrypted SQLite, deferred promotion, quotas/buckets, reopen, guarded receipt, seen replay, Account isolation, damage isolation and binding restoration');
  console.log('PASS 70 stateful operations differential against actual original IndexedDB InboxStore, with both buckets compared after every operation');
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>fs.rmSync(dir,{recursive:true,force:true}));
