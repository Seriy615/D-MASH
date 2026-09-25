'use strict';
(function(global){
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const unhex=value=>{if(typeof value!=='string'||!/^[0-9a-f]{64}$/.test(value))throw Error('Invalid local key');return Uint8Array.from(value.match(/../g),b=>parseInt(b,16));};
 const key=value=>{if(!(value instanceof Uint8Array)||value.length!==32)throw Error('Invalid local key');return value.slice();};
 const wipe=entry=>{entry?.sign?.secretKey.fill(0);entry?.box?.secretKey.fill(0);for(const k of entry?.recipientKeys||[])k.fill(0);};
 class LocalDeliveryV4{
  constructor(runtime,inbox){this.runtime=runtime;this.inbox=inbox;this.bindings=new Map();this.busy=new Set();this.routes=new Map();this.pending=0;this.closed=false;}
  check(){if(this.closed)throw Error('Local Node closed');this.inbox.check();}
  async bind(data,{persist=true}={}){
   this.check();const certificate={...data.certificate},id=certificate.route_id;
   global.DmashRouteDiscoveryV4.verifyCertificate(certificate);
   if(typeof data.accountSlot!=='string'||!data.accountSlot||data.accountSlot.length>512)throw Error('Invalid local Account slot');
   if(this.busy.has(id)||this.bindings.has(id)||this.bindings.size+this.busy.size>=32)throw Error('Local route unavailable');
   this.busy.add(id);let entry,seed,boxSeed;
   try{
    seed=key(data.discoverySeed);boxSeed=key(data.discoveryBox);
    entry={certificate,accountSlot:data.accountSlot,sign:nacl.sign.keyPair.fromSeed(seed),box:nacl.box.keyPair.fromSecretKey(boxSeed),recipientKeys:[]};
    if(!Array.isArray(data.recipientKeys)||data.recipientKeys.length>2)throw Error('Invalid recipient keys');
    for(const value of data.recipientKeys)entry.recipientKeys.push(key(value));
    if(hex(entry.sign.publicKey)!==certificate.discovery_sign||hex(entry.box.publicKey)!==certificate.discovery_box)throw Error('Discovery key mismatch');
    this.validateRecipient(entry,entry.recipientKeys);
    const saved={certificate,accountSlot:data.accountSlot,discoverySeed:hex(seed),discoveryBox:hex(boxSeed),recipientKeys:entry.recipientKeys.map(hex)};
    if(persist&&!await this.inbox.saveBinding(id,saved))throw Error('Local route already persisted');
    this.check();
    const binding=entry;
    entry.handler=async(_,packet)=>{this.check();return this.inbox.receive(id,binding.accountSlot,packet.payload,binding.recipientKeys);};
    this.runtime.bindLocal(certificate,entry.sign,entry.box,entry.handler);
    this.bindings.set(id,entry);entry=null;
    return {bound:true};
   }finally{this.busy.delete(id);seed?.fill(0);boxSeed?.fill(0);wipe(entry);}
  }
  validateRecipient(entry,keys){
   if(keys.length){const pair=nacl.box.keyPair.fromSecretKey(keys[0]);try{if(hex(pair.publicKey)!==entry.certificate.recipient_box)throw Error('Recipient key mismatch');}finally{pair.secretKey.fill(0);}}
  }
  async restore(){
   const stored=await this.inbox.bindings();let unavailable=stored.unreadable;
   for(const value of stored.records){
    const material=[];const decode=value=>{const bytes=unhex(value);material.push(bytes);return bytes;};
    try{await this.bind({certificate:value.certificate,accountSlot:value.accountSlot,discoverySeed:decode(value.discoverySeed),discoveryBox:decode(value.discoveryBox),recipientKeys:value.recipientKeys.map(decode)},{persist:false});}
    catch(error){this.check();unavailable++;}
    finally{for(const bytes of material)bytes.fill(0);}
   }
   return {restored:this.bindings.size,unavailable};
  }
  async installRecipientKeys(id,values){
   this.check();const entry=this.bindings.get(id);
   if(!entry||this.busy.has(id)||!Array.isArray(values)||values.length<1||values.length>2)throw Error('Local route unavailable');
   this.busy.add(id);const keys=[];let installed=false;
   try{
    for(const value of values)keys.push(key(value));this.validateRecipient(entry,keys);
    const saved={certificate:entry.certificate,accountSlot:entry.accountSlot,discoverySeed:hex(entry.sign.secretKey.subarray(0,32)),discoveryBox:hex(entry.box.secretKey),recipientKeys:keys.map(hex)};
    if(!await this.inbox.saveBinding(id,saved,{replace:true}))throw Error('Local route changed');
    this.check();for(const previous of entry.recipientKeys)previous.fill(0);
    entry.recipientKeys=keys;installed=true;
    const processed=await this.inbox.retryDeferred(id,entry.accountSlot,keys);return {installed:true,processed};
   }finally{this.busy.delete(id);if(!installed)for(const bytes of keys)bytes.fill(0);}
  }
  prune(){for(const [id,row] of this.routes)if(row.route.expires_at<=this.runtime.clock()||this.runtime.peers.get(row.route.peer)!==row.route.channel)this.routes.delete(id);}
  async discover(certificate){
   this.check();this.prune();if(this.pending>=4||this.routes.size+this.pending>=128)throw Error('Local discovery quota');
   certificate={...certificate};this.pending++;
   try{
    const route=await this.runtime.discover(certificate);this.check();
    const handle=hex(crypto.getRandomValues(new Uint8Array(32)));this.routes.set(handle,{route,certificate});
    return {handle,expiresAt:route.expires_at};
   }finally{this.pending--;}
  }
  send(handle,payload,replyRouteId){
   this.check();this.prune();const destination=this.routes.get(handle),reply=this.bindings.get(replyRouteId);
   if(!destination||!reply)throw Error('Local route unavailable');
   global.DmashRouteDiscoveryV4.verifyCertificate(destination.certificate);
   this.runtime.send(destination.route,global.DmashRecipientPayloadV4.sealPayload(unhex(destination.certificate.recipient_box),payload),reply.handler);
   return {queued:true};
  }
  close(){this.closed=true;for(const entry of this.bindings.values())wipe(entry);this.bindings.clear();this.routes.clear();}
 }
 global.DmashNodeLocalDeliveryV4=LocalDeliveryV4;
 if(typeof module!=='undefined')module.exports=LocalDeliveryV4;
})(typeof window!=='undefined'?window:globalThis);
