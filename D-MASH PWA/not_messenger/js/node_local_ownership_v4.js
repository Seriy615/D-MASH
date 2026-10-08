'use strict';
// Worker-local authority. No Account secret enters this module; owner signatures
// are local registration proofs, never sent on the mesh.
(function(g){
 const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),unhex=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Invalid commitment');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));},canonical=v=>g.DmashSecureSession.canonical(v),digest=async v=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(v)))));
 class Ownership{
  constructor(local,inbox){this.local=local;this.inbox=inbox;this.challenges=new Map();this.owners=new Map();this.busy=new Set();this.closed=false;}
  check(){if(this.closed)throw Error('Local ownership closed');this.local.check();}
  async challenge(accountPublic,certificate,{archive=false}={}){
   this.check();g.DmashRouteDiscoveryV4.validateEd25519PublicEncoding(accountPublic);
   if(archive){if(!Number.isSafeInteger(certificate?.expires_at)||certificate.expires_at>Math.floor(Date.now()/1000))throw Error('Archive requires expired certificate');g.DmashRouteDiscoveryV4.verifyCertificate(certificate,certificate.expires_at-1);}else g.DmashRouteDiscoveryV4.verifyCertificate(certificate);
   for(const [id,v]of this.challenges)if(v.expires<=Date.now())this.challenges.delete(id);
   if(this.challenges.size>=16)throw Error('Owner challenge quota');
   const id=hex(crypto.getRandomValues(new Uint8Array(32))),routeAuthorityDigest=await digest(certificate),ownerSlot=await this.inbox.alias('local-account-owner-v4|'+accountPublic);
   if(archive){const expected={accountPublic,ownerSlot,routeAuthorityDigest,routeId:certificate.route_id};let row=await this.read(certificate.route_id);if(!row?.ownership&&this.archiveRowProvider)row=await this.archiveRowProvider(expected);if(!row?.ownership||row.ownership.accountPublic!==accountPublic||row.ownership.ownerSlot!==ownerSlot||row.ownership.routeAuthorityDigest!==routeAuthorityDigest||await digest(row.certificate)!==routeAuthorityDigest)throw Error('Existing archived owner required');}
   const proof={...(archive?{archive:true}:{}),domain:'D-MASH|LOCAL-OWNER|V4',nodeId:this.inbox.localId,accountPublic,ownerSlot,routeAuthorityDigest,routeId:certificate.route_id,challenge:id,expires:Date.now()+60000};
   this.check();this.challenges.set(id,proof);return {challenge:id,transcript:canonical(proof)};
  }
  async register(challenge,signature){
   this.check();const proof=this.challenges.get(challenge);this.challenges.delete(challenge);
   if(!proof||proof.expires<=Date.now()||this.owners.size>=64)throw Error('Owner challenge unavailable');
   if(!(signature instanceof Uint8Array)||signature.length!==64)throw Error('Owner signature required');
   g.DmashRouteDiscoveryV4.validateEd25519SignatureEncoding(hex(signature));
   if(!nacl.sign.detached.verify(new TextEncoder().encode(canonical(proof)),signature,unhex(proof.accountPublic)))throw Error('Owner proof rejected');
   const token=hex(crypto.getRandomValues(new Uint8Array(32))),value={...(proof.archive?{archive:true}:{}),accountPublic:proof.accountPublic,ownerSlot:proof.ownerSlot,routeAuthorityDigest:proof.routeAuthorityDigest,routeId:proof.routeId};
   this.owners.set(token,value);return {token,...value,accountPublic:proof.accountPublic};
  }
  owner(token,{archiveAllowed=false}={}){this.check();const value=this.owners.get(token);if(!value)throw Error('Owner capability unavailable');if(value.archive&&!archiveAllowed)throw Error('Archive capability is read/drain only');return value;}
  async read(routeId){const key='binding:'+await this.inbox.alias('route|'+routeId),row=await this.inbox.store.read(key);return row?await this.inbox.decrypt(row):null;}
  matches(value,owner){if(!value?.ownership||value.ownership.ownerSlot!==owner.ownerSlot||value.ownership.routeAuthorityDigest!==owner.routeAuthorityDigest)throw Error('Owner tuple mismatch');}
  async prepare(token,data){try{return await this.prepareInner(token,data);}finally{for(const bytes of [data?.discoverySeed,data?.discoveryBox,...(Array.isArray(data?.recipientKeys)?data.recipientKeys:[])])bytes?.fill?.(0);}}
  async prepareInner(token,data){
   const owner=this.owner(token);for(const v of [data.migrationId,data.bindingDigest])unhex(v);
   if(!Number.isSafeInteger(data.expectedGeneration)||data.expectedGeneration<1||data.expectedGeneration!==data.certificate?.generation)throw Error('Invalid generation');
   if(this.busy.has(owner.routeId))throw Error('Binding mutation pending');this.busy.add(owner.routeId);
   let sign,box;
   try{
    g.DmashRouteDiscoveryV4.verifyCertificate(data.certificate);
    if(await digest(data.certificate)!==owner.routeAuthorityDigest)throw Error('Route authority changed');
    for(const bytes of [data.discoverySeed,data.discoveryBox,...data.recipientKeys])if(!(bytes instanceof Uint8Array)||bytes.length!==32)throw Error('Invalid private material');
    if(!Array.isArray(data.recipientKeys)||data.recipientKeys.length<1||data.recipientKeys.length>2)throw Error('Recipient quota');
    sign=nacl.sign.keyPair.fromSeed(data.discoverySeed);box=nacl.box.keyPair.fromSecretKey(data.discoveryBox);
    if(hex(sign.publicKey)!==data.certificate.discovery_sign||hex(box.publicKey)!==data.certificate.discovery_box)throw Error('Route private authority mismatch');
    this.local.validateRecipient({certificate:data.certificate},data.recipientKeys);
    const tuple={...owner,migrationId:data.migrationId,bindingDigest:data.bindingDigest,generation:data.expectedGeneration};
    tuple.preparationDigest=await digest(tuple);
    const previous=await this.read(owner.routeId);
    if(previous){this.matches(previous,owner);if(canonical(previous.ownership)!==canonical(tuple))throw Error('Binding transaction conflict');return {...tuple,state:previous.state};}
    const saved={certificate:{...data.certificate},accountSlot:owner.ownerSlot,discoverySeed:hex(data.discoverySeed),discoveryBox:hex(data.discoveryBox),recipientKeys:data.recipientKeys.map(hex),ownership:tuple,state:'NODE_PREPARED'};
    this.owner(token);if(!await this.inbox.saveBinding(owner.routeId,saved))throw Error('Binding CAS conflict');return {...tuple,state:saved.state};
   }finally{this.busy.delete(owner.routeId);sign?.secretKey.fill(0);box?.secretKey.fill(0);for(const bytes of [data.discoverySeed,data.discoveryBox,...(data.recipientKeys||[])])bytes?.fill?.(0);}
  }
  async query(token,migrationId){const owner=this.owner(token,{archiveAllowed:true}),row=await this.read(owner.routeId);if(!row)return null;this.matches(row,owner);if(row.ownership.migrationId!==migrationId)throw Error('Migration mismatch');return {...row.ownership,state:row.state};}
  async change(token,tuple,state){
   const owner=this.owner(token);if(this.busy.has(owner.routeId))throw Error('Binding mutation pending');this.busy.add(owner.routeId);
   try{
    const row=await this.read(owner.routeId);this.matches(row,owner);
    if(canonical(row.ownership)!==canonical(tuple))throw Error('Prepared tuple mismatch');
    if(row.state===state){if(state==='ACTIVE'&&!this.local.bindings.has(owner.routeId))await this.activateSaved(row);return {...tuple,state};}
    if(state==='ACTIVE'&&row.state!=='NODE_PREPARED'||state==='RETIRED'&&row.state!=='ACTIVE')throw Error('Invalid binding transition');
    this.owner(token);if(!await this.inbox.saveBinding(owner.routeId,{...row,state},{replace:true}))throw Error('Binding CAS conflict');
    if(state==='ACTIVE'){
     await this.activateSaved({...row,state});
    }else this.local.retireOwned(owner.routeId);
    return {...tuple,state};
   }finally{this.busy.delete(owner.routeId);}
  }
  async activateSaved(row){if(this.detachBootstrap)await this.detachBootstrap(row.routeId);const material=[unhex(row.discoverySeed),unhex(row.discoveryBox),...row.recipientKeys.map(unhex)];try{await this.local.bind({...row,discoverySeed:material[0],discoveryBox:material[1],recipientKeys:material.slice(2)},{persist:false});}finally{for(const value of material)value.fill(0);}}
  close(){this.closed=true;this.challenges.clear();this.owners.clear();}
 }
 g.DmashNodeLocalOwnershipV4=Ownership;if(typeof module!=='undefined')module.exports=Ownership;
})(globalThis);
