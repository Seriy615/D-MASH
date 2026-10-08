'use strict';
(function(g){
 const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),decode=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Bootstrap key encoding');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 class BootstrapRuntime{
  #roots=new Map();#routes=new Map();
  static async open(storageKey,nodeId,{runtime,ownership,local,isCurrent}){
   const base=await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']),key=new Uint8Array(await crypto.subtle.sign('HMAC',base,new TextEncoder().encode('D-MASH|NODE-BOOTSTRAP|V4|STORAGE')));
   let inbox;try{inbox=await g.DmashNodeInboxV4.open(key,nodeId,{databaseName:'dmash_node_bootstrap_v4',maxRecords:96,maxBytes:1024*1024,isCurrent});}finally{key.fill(0);}
   const result=new BootstrapRuntime();Object.assign(result,{runtime,ownership,local,inbox,isCurrent,closed:false});
   const pairing=g.DmashAccountPairingV2.createCodec({nacl,discovery:g.DmashRouteDiscoveryV4}),binding=g.DmashAccountRouteBindingV2.createBindingCodec({nacl,discovery:g.DmashRouteDiscoveryV4,pairing});
   result.codec=g.DmashNodeBootstrapControlV4.createCodec({pairing,binding});
   result.dispatcher=new g.DmashNodeBootstrapDispatcherV4({ownership:{owner:(token,options)=>{result.check();return result.#roots.get(token)||ownership.owner(token,options);}},inbox,codec:result.codec});
   try{await result.restore();return result;}catch(error){result.close();throw error;}
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Bootstrap root closed');this.inbox.check();}
  async provision(token,data){
   let sign,box;const material=[data.discoverySeed,data.discoveryBox,...(Array.isArray(data.recipientKeys)?data.recipientKeys:[])];
   try{
    const owner=this.ownership.owner(token);const final=await this.ownership.read(owner.routeId);this.ownership.owner(token);if(final&&['ACTIVE','RETIRED'].includes(final.state))throw Error('Final route cannot become bootstrap');await this.codec.localOffer(data.localBundle,owner);const certificate=JSON.parse(data.localBundle).inbound_certificate;
    if(!Array.isArray(data.recipientKeys)||data.recipientKeys.length!==1||material.some(v=>!(v instanceof Uint8Array)||v.length!==32))throw Error('Bootstrap private material required');
    sign=nacl.sign.keyPair.fromSeed(data.discoverySeed);box=nacl.box.keyPair.fromSecretKey(data.discoveryBox);
    if(hex(sign.publicKey)!==certificate.discovery_sign||hex(box.publicKey)!==certificate.discovery_box)throw Error('Bootstrap discovery authority mismatch');
    this.local.validateRecipient({certificate},data.recipientKeys);
    await this.dispatcher.register(token,data.localBundle);
    const key=await this.dispatcher.key('config',owner),old=await this.dispatcher.load(key),saved={...old.value,owner:{...owner},certificate,discoverySeed:hex(data.discoverySeed),discoveryBox:hex(data.discoveryBox),recipientKeys:data.recipientKeys.map(hex),suspended:false};
    if(old.value.discoverySeed){if(old.value.discoverySeed!==saved.discoverySeed||old.value.discoveryBox!==saved.discoveryBox||old.value.recipientKeys[0]!==saved.recipientKeys[0])throw Error('Bootstrap material changed');if(old.value.suspended)throw Error('Bootstrap already retired');}
    else await this.dispatcher.save(token,key,old,saved);
    this.ownership.owner(token);await this.attach(saved);return {provisioned:true,state:'BOOTSTRAP_ONLY'};
   }finally{sign?.secretKey.fill(0);box?.secretKey.fill(0);for(const value of material)value?.fill?.(0);}
  }
  async attach(config){
   this.check();if(this.#routes.has(config.owner.routeId))return;
   if(config.suspended||JSON.parse(config.localBundle).expires_at<=Math.floor(Date.now()/1000))return;
   const final=await this.ownership.read(config.owner.routeId);if(final&&['ACTIVE','RETIRED'].includes(final.state))return;
   await this.codec.localOffer(config.localBundle,config.owner);
   if(await this.ownership.inbox.alias('local-account-owner-v4|'+config.owner.accountPublic)!==config.owner.ownerSlot)throw Error('Bootstrap blind owner mismatch');
   const rootToken=Object.freeze({}),seed=decode(config.discoverySeed),boxSeed=decode(config.discoveryBox),keys=config.recipientKeys.map(decode),sign=nacl.sign.keyPair.fromSeed(seed),box=nacl.box.keyPair.fromSecretKey(boxSeed);seed.fill(0);boxSeed.fill(0);
   let installed=false;
   try{
    const entry={owner:config.owner,rootToken,sign,box,keys,handler:null};
    entry.handler=async(_,packet)=>{this.check();const opened=g.DmashRecipientPayloadV4.openPayload(keys,packet.payload);if(opened.status!=='accepted')return {discarded:true};let value;try{value=JSON.parse(opened.payload);}catch(_){return {discarded:true};}
     try{if(value.type==='NODE_BOOTSTRAP_REQUEST_V4')return await this.dispatcher.request(rootToken,opened.payload);
     if(value.type==='NODE_BOOTSTRAP_RECEIPT_V4'&&Object.keys(value).sort().join(',')==='exchange_id,receipt,type')return await this.dispatcher.receipt(rootToken,value.exchange_id,value.receipt);
     return {discarded:true};}catch(_){this.check();return {discarded:true};}};
    this.#roots.set(rootToken,config.owner);this.runtime.bindLocal(config.certificate,sign,box,entry.handler);this.#routes.set(config.owner.routeId,entry);installed=true;
   }finally{if(!installed){this.#roots.delete(rootToken);sign.secretKey.fill(0);box.secretKey.fill(0);for(const k of keys)k.fill(0);}}
  }
  async archiveRow(owner){this.check();const key=await this.dispatcher.key('config',owner),row=await this.dispatcher.load(key);if(!row?.value.owner||!row.value.certificate)return null;return {ownership:row.value.owner,certificate:row.value.certificate};}
  async restore(){let unavailable=0;for(const row of await this.inbox.store.all()){try{const value=await this.inbox.decrypt(row);if(value.kind==='bootstrap-config'&&value.owner&&value.discoverySeed)await this.attach(value);}catch(_){this.check();unavailable++;}}return {restored:this.#routes.size,unavailable};}
  async detach(routeId){
   const entry=this.#routes.get(routeId);if(!entry)return;
   const key=await this.dispatcher.key('config',entry.owner),old=await this.dispatcher.load(key);if(old){const encrypted=await this.inbox.encrypt(key,{...old.value,suspended:true});this.check();if(!await this.inbox.store.cas(key,old.row.revision,encrypted))throw Error('Bootstrap retirement conflict');}
   this.runtime.owned=this.runtime.owned.filter(row=>row.handler!==entry.handler);for(const [key,row]of this.runtime.labels)if(row.target===entry.handler)this.runtime.labels.delete(key);
   this.#roots.delete(entry.rootToken);this.#routes.delete(routeId);entry.sign.secretKey.fill(0);entry.box.secretKey.fill(0);for(const key of entry.keys)key.fill(0);
  }
  async submit(token,handle,data){
   const owner=this.ownership.owner(token),entry=this.#routes.get(owner.routeId),destination=this.local.routes.get(handle);if(!entry||!destination)throw Error('Bootstrap route unavailable');let wire;
   if(data.kind==='REQUEST'){
    const checked=await this.codec.inspect(data.targetBundle,data.serialized);if(checked.remoteAccount!==owner.accountPublic)throw Error('Outbound bootstrap signer mismatch');
    const target=JSON.parse(data.targetBundle).inbound_certificate;if(g.DmashSecureSession.canonical(target)!==g.DmashSecureSession.canonical(destination.certificate))throw Error('Bootstrap destination mismatch');
    await this.dispatcher.request(token,data.serialized,{targetBundle:data.targetBundle,outbound:true});wire=data.serialized;
   }else if(data.kind==='RECEIPT'){
    const records=await this.dispatcher.list(token),record=records.find(v=>v.exchangeId===data.exchangeId);if(!record||record.state!=='SELECTED')throw Error('Bootstrap selection required');
    const peerBundle=record.direction==='OUTBOUND'?record.targetBundle:JSON.parse(record.serialized).bundle;
    if(g.DmashSecureSession.canonical(JSON.parse(peerBundle).inbound_certificate)!==g.DmashSecureSession.canonical(destination.certificate))throw Error('Bootstrap receipt destination mismatch');
    await this.dispatcher.receipt(token,data.exchangeId,data.serialized);wire=g.DmashSecureSession.canonical({type:'NODE_BOOTSTRAP_RECEIPT_V4',exchange_id:data.exchangeId,receipt:data.serialized});this.codec.fits(wire);
   }else throw Error('Bootstrap user payload forbidden');
   this.ownership.owner(token);this.check();this.runtime.send(destination.route,g.DmashRecipientPayloadV4.sealPayload(decode(destination.certificate.recipient_box),wire),entry.handler);return {queued:true};
  }
  close(){if(this.closed)return;this.closed=true;for(const entry of this.#routes.values()){entry.sign.secretKey.fill(0);entry.box.secretKey.fill(0);for(const key of entry.keys)key.fill(0);}this.#routes.clear();this.#roots.clear();this.dispatcher?.close();}
 }
 g.DmashNodeBootstrapRuntimeV4=BootstrapRuntime;if(typeof module!=='undefined')module.exports=BootstrapRuntime;
})(globalThis);
