'use strict';
// Existing BootstrapRuntime + real signed owner/offer, compared on original IDB
// and injected actual C++ SQLite Inbox. No network/KEM-validity claim.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{execFileSync}=require('node:child_process');
const {indexedDB}=require('fake-indexeddb');global.indexedDB=indexedDB;
const js=path.resolve(__dirname,'../../D-MASH PWA/not_messenger/js');global.nacl=require(path.join(js,'vendor/nacl-fast.min.js'));
for(const name of ['secure_session','route_discovery_v4','account_pairing_v2','account_route_binding_v2','recipient_payload_v4','node_inbox_v4','node_local_delivery_v4','node_local_ownership_v4','node_bootstrap_control_v4','node_bootstrap_dispatcher_v4'])require(path.join(js,name+'.js'));
const Bootstrap=require(path.join(js,'node_bootstrap_runtime_v4.js')),binary=process.argv[2];assert(binary&&fs.existsSync(binary),'supply actual dmash_inbox_bridge');
const folder=fs.mkdtempSync(path.join(os.tmpdir(),'dmash-bootstrap-store-'));fs.chmodSync(folder,0o700);
const encode=r=>r===null?null:{iv:Buffer.from(r.iv).toString('base64'),ciphertext:Buffer.from(r.ciphertext).toString('base64')};
const decode=r=>r===null?null:{...r,iv:Uint8Array.from(Buffer.from(r.iv,'base64')),ciphertext:Uint8Array.from(Buffer.from(r.ciphertext,'base64')).buffer};
class NativeStore{
 constructor(file){this.file=file;this.closed=false;}
 check(){if(this.closed)throw Error('closed');}
 run(value){this.check();const r=JSON.parse(execFileSync(binary,[this.file,'96','1048576'],{input:JSON.stringify(value)+'\n',encoding:'utf8',timeout:10000}));assert(r.ok,r.error);return r.value;}
 async open(){this.check();return this;}async reconcile(){this.run({op:'reconcile'});}async read(key){return decode(this.run({op:'read',key}));}
 async all(){return this.run({op:'all'}).map(decode);}async allBindings(){return this.run({op:'allBindings'}).map(decode);}
 async cas(key,revision,row,{guard=()=>true}={}){assert(guard());return this.run({op:'cas',key,revision,row:encode(row)});}close(){this.closed=true;}
}
const hex=b=>Buffer.from(b).toString('hex'),material=nacl.randomBytes(32),nodeId='a'.repeat(64),account=nacl.sign.keyPair(),route=nacl.sign.keyPair(),discovery=nacl.sign.keyPair(),box=nacl.box.keyPair(),recipient=nacl.box.keyPair(),now=Math.floor(Date.now()/1000);
const certificate=DmashRouteDiscoveryV4.issueCertificate(route,discovery.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600});
const pairing=DmashAccountPairingV2.createCodec({nacl,discovery:DmashRouteDiscoveryV4});
const bundle=pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(nacl.randomBytes(32)),generation:1,issued_at:now,expires_at:now+3600,previous_binding:null,intended_peer:null,contribution:hex(nacl.randomBytes(32)),account_keys:{signing:hex(account.publicKey),box:hex(nacl.box.keyPair().publicKey),kem_profile:'ACCOUNT_STATIC_LEGACY_KYBER768_V1',kem_public:Buffer.from(nacl.randomBytes(1184)).toString('base64url')},inbound_certificate:certificate},account.secretKey).serialized;
(async()=>{
 for(const injected of [false,true]){
  const mainFile=path.join(folder,(injected?'sql':'idb')+'-main.sqlite'),bootstrapFile=path.join(folder,'bootstrap.sqlite');
  const context=async()=>{
   const inbox=await DmashNodeInboxV4.open(material,nodeId,injected?{store:new NativeStore(mainFile)}:{databaseName:'bootstrap-main-default'});
   const bound=new Map(),runtime={bindLocal(c,s,b,h){bound.set(c.route_id,{c,s,b,h});}},local=new DmashNodeLocalDeliveryV4(runtime,inbox),ownership=new DmashNodeLocalOwnershipV4(local,inbox);
   const options={runtime,local,ownership,isCurrent:()=>true};if(injected)options.store=new NativeStore(bootstrapFile);
   const before=global.indexedDB;if(injected)global.indexedDB={open(){throw Error('injected backend must not open IndexedDB');}};
   let bootstrap;try{bootstrap=await Bootstrap.open(material,nodeId,options);}finally{global.indexedDB=before;}
   if(injected)assert.equal(bootstrap.inbox.store,options.store);
   return {bootstrap,inbox,local,ownership,bound};
  };
  let c=await context();const challenge=await c.ownership.challenge(hex(account.publicKey),certificate),owner=await c.ownership.register(challenge.challenge,nacl.sign.detached(new TextEncoder().encode(challenge.transcript),account.secretKey));
  await c.bootstrap.provision(owner.token,{localBundle:bundle,discoverySeed:discovery.secretKey.slice(0,32),discoveryBox:box.secretKey.slice(),recipientKeys:[recipient.secretKey.slice()]});
  assert.equal(c.bound.size,1);assert.deepEqual(await c.bootstrap.dispatcher.list(owner.token),[]);
  const config=(await c.bootstrap.inbox.store.all())[0];assert(config&&config.ciphertext.byteLength>16);assert(!Buffer.from(config.ciphertext).includes(Buffer.from(bundle)));
  c.bootstrap.close();c.local.close();c.inbox.close();
  c=await context();assert.equal(c.bound.size,1,'exact existing bootstrap config restores on new runtime');
  const restored=[...c.bound.values()][0];assert.deepEqual(restored.c,certificate);assert.deepEqual(restored.s.publicKey,discovery.publicKey);assert.deepEqual(restored.b.publicKey,box.publicKey);
  c.bootstrap.close();c.local.close();c.inbox.close();
  if(injected){await assert.rejects(()=>DmashNodeInboxV4.open(material,nodeId,{store:new NativeStore(bootstrapFile)}),'bootstrap domain key differs from main Inbox');}
 }
 console.log('PASS original IDB and actual injected SQLite BootstrapRuntime: real signed owner/offer, encrypted config, exact route/key restore, injected backend uses no IndexedDB, separate domain key; no network/KEM-validity claim');
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>{for(const value of [material,account.secretKey,route.secretKey,discovery.secretKey,box.secretKey,recipient.secretKey])value.fill(0);fs.rmSync(folder,{recursive:true,force:true});});
