'use strict';
// Root-owned public/reply registrations and neutral control journal. Account
// secrets never enter this actor. Final ownership activation is a separate API.
(function(g){
 const text=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),canonical=v=>g.DmashSecureSession.canonical(v);
 const decode=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Public material encoding');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 const hash=async s=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(s))));
 class PublicRuntime{
  #caps=new Map();#routes=new Map();#replays=new Set();#tail=Promise.resolve();
  static async open(storageKey,nodeId,{runtime,ownership,local,isCurrent}){
   const base=await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']),key=new Uint8Array(await crypto.subtle.sign('HMAC',base,text('D-MASH|NODE-PUBLIC-BOOTSTRAP|V4|STORAGE')));
   let inbox;try{inbox=await g.DmashNodeInboxV4.open(key,nodeId,{databaseName:'dmash_node_public_bootstrap_v4',maxRecords:128,maxBytes:1536*1024,isCurrent});}finally{key.fill(0);}
   const result=new PublicRuntime();Object.assign(result,{runtime,ownership,local,inbox,isCurrent,closed:false});
   const pairing=g.DmashAccountPairingV2.createCodec({nacl:g.nacl,discovery:g.DmashRouteDiscoveryV4}),binding=g.DmashAccountRouteBindingV2.createBindingCodec({nacl:g.nacl,discovery:g.DmashRouteDiscoveryV4,pairing});
   result.codec=g.DmashNodePublicBootstrapControlV4.createCodec({pairing,binding});result.privateCodec=g.DmashNodeBootstrapControlV4.createCodec({pairing,binding});
   try{await result.restore();return result;}catch(error){result.close();throw error;}
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Public root closed');this.inbox.check();}
  run(fn){const task=this.#tail.then(()=>{this.check();return fn();});this.#tail=task.catch(()=>{});return task;}
  async key(kind,id,request=''){return this.inbox.alias('public-v4|'+kind+'|'+id+'|'+request);}
  async load(key){const row=await this.inbox.store.read(key);this.check();return row?{row,value:await this.inbox.decrypt(row)}:null;}
  async save(key,old,value,guard=()=>true){if(value.kind==='public-request'){let bytes=text(canonical(value)).length;for(const row of await this.rows('public-request'))if(row.row.key!==key)bytes+=text(canonical(row.value)).length;if(bytes>1024*1024)throw Error('Public total control bytes quota');}const encrypted=await this.inbox.encrypt(key,value);this.check();guard();if(!await this.inbox.store.cas(key,old?.row.revision??null,encrypted,{guard:()=>{this.check();return guard();}}))throw Error('Public journal conflict');}
  async rows(kind){const values=[];for(const row of await this.inbox.store.all()){try{const value=await this.inbox.decrypt(row);if(value.kind===kind)values.push({row,value});}catch(_){this.check();}}return values;}
  capability(token){this.check();const value=this.#caps.get(token);if(!value)throw Error('Public root capability unavailable');return value;}
  descriptor(config){return {id:config.id,kind:config.routeKind,certificate:config.certificate,bootstrapBox:config.bootstrapBox,profile:'public-v1',installed:this.#routes.has(config.id)};}
  routes(){return this.run(async()=>{const rows=await this.rows('public-config');return rows.map(row=>this.descriptor(row.value));});}
  register(data){return this.run(async()=>{
   let config;if(data.id){decode(data.id);const saved=await this.load(await this.key('config',data.id));if(!saved||saved.value.kind!=='public-config')throw Error('Public registration absent');config=saved.value;}
   else{
    if(!['PUBLIC_INTAKE','PUBLIC_REPLY'].includes(data.kind))throw Error('Public route kind');const now=Math.floor(Date.now()/1000),max=data.kind==='PUBLIC_REPLY'?86400:30*86400;
    if(!Number.isSafeInteger(data.expiresAt)||data.expiresAt<=now||data.expiresAt>now+max)throw Error('Public registration expiry');
    if((await this.rows('public-config')).length>=16)throw Error('Public registration quota');
    const route=g.nacl.sign.keyPair(),sign=g.nacl.sign.keyPair(),box=g.nacl.box.keyPair(),recipient=g.nacl.box.keyPair(),bootstrap=g.nacl.box.keyPair();
    try{config={kind:'public-config',id:hex(crypto.getRandomValues(new Uint8Array(32))),routeKind:data.kind,certificate:g.DmashRouteDiscoveryV4.issueCertificate(route,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:data.expiresAt}),routeSeed:hex(route.secretKey.subarray(0,32)),discoverySeed:hex(sign.secretKey.subarray(0,32)),discoveryBox:hex(box.secretKey),recipientKey:hex(recipient.secretKey),bootstrapKey:hex(bootstrap.secretKey),bootstrapBox:hex(bootstrap.publicKey)};await this.save(await this.key('config',config.id),null,config);}finally{for(const k of [route.secretKey,sign.secretKey,box.secretKey,recipient.secretKey,bootstrap.secretKey])k.fill(0);}
   }
   if(this.#caps.size>=32)throw Error('Public handle quota');await this.attach(config);const token=hex(crypto.getRandomValues(new Uint8Array(32)));this.#caps.set(token,config);return {token,...this.descriptor(config)};
  });}
  release(token){this.#caps.delete(token);return {released:true};}
  async attach(config){
   this.check();if(this.#routes.has(config.id)||config.certificate.expires_at<=Math.floor(Date.now()/1000))return;
   g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);const seed=decode(config.discoverySeed),boxSeed=decode(config.discoveryBox),sign=g.nacl.sign.keyPair.fromSeed(seed),box=g.nacl.box.keyPair.fromSecretKey(boxSeed),recipient=decode(config.recipientKey),recipientPair=g.nacl.box.keyPair.fromSecretKey(recipient);seed.fill(0);boxSeed.fill(0);const recipientPublic=hex(recipientPair.publicKey);recipientPair.secretKey.fill(0);
   if(hex(sign.publicKey)!==config.certificate.discovery_sign||hex(box.publicKey)!==config.certificate.discovery_box||recipientPublic!==config.certificate.recipient_box){sign.secretKey.fill(0);box.secretKey.fill(0);recipient.fill(0);throw Error('Public stored material mismatch');}
   const handler=async(_,packet)=>{try{this.check();const opened=g.DmashRecipientPayloadV4.openPayload([recipient],packet.payload);if(opened.status!=='accepted')return {discarded:true};return await this.run(()=>this.receive(config,opened.payload));}catch(_){this.check();return {discarded:true};}};
   try{this.runtime.bindLocal(config.certificate,sign,box,handler);this.#routes.set(config.id,{config,sign,box,recipient,handler});}catch(error){sign.secretKey.fill(0);box.secretKey.fill(0);recipient.fill(0);throw error;}
  }
  async restore(){for(const row of await this.rows('public-config')){try{await this.attach(row.value);}catch(_){this.check();}}}
  async quota(config,wire){let bytes=0,count=0,local=0;for(const row of await this.rows('public-request')){if(row.value.expiresAt<=Math.floor(Date.now()/1000)&&['PENDING','DENIED','REQUESTED'].includes(row.value.state)){await this.inbox.store.cas(row.row.key,row.row.revision,null,{guard:()=>{this.check();return true;}});continue;}count++;if(row.value.registration===config.id)local++;bytes+=text(canonical(row.value)).length;}if(count>=64||local>=16||bytes+text(wire).length>1024*1024)throw Error('Public request quota');}
  async receive(config,wire){
   const value=JSON.parse(wire);if(value.type==='CONTACT_PRIVATE_V2')return this.receivePrivate(config,value);if(value.type!=='CONTACT_REQUEST_V2'||config.routeKind!=='PUBLIC_INTAKE')throw Error('Public control unavailable');
   const checked=await this.codec.inspectRequest(config.certificate,wire),key=await this.key('request',config.id,checked.requestId),old=await this.load(key);
   if(old){if(old.value.requestDigest!==checked.digest)throw Error('Conflicting public replay');return {stored:true,duplicate:true};}
   await this.quota(config,wire);await this.save(key,null,{kind:'public-request',registration:config.id,requestId:checked.requestId,requestDigest:checked.digest,expiresAt:checked.expiresAt,state:'PENDING',direction:'INBOUND',request:wire,claim:null});return {stored:true,duplicate:false};
  }
  list(token,{limit=16,after=null}={}){return this.run(async()=>{if(!Number.isInteger(limit)||limit<1||limit>16)throw Error('Public page limit');if(after!==null)decode(after);const config=this.capability(token),rows=await this.rows('public-request');this.capability(token);return rows.filter(row=>row.value.registration===config.id&&(after===null||row.value.requestId>after)).sort((a,b)=>a.value.requestId.localeCompare(b.value.requestId)).slice(0,limit).map(({value})=>{const {blob,acceptBlob,confirmBlob,receiptBlobs,claim,...projection}=value;const safeClaim=claim?(({bootstrapKey,...publicClaim})=>publicClaim)(claim):null;return {...projection,claim:safeClaim,state:value.expiresAt<=Math.floor(Date.now()/1000)?'EXPIRED_'+value.state:value.state};});});}
  request(token,targetCertificate,data){return this.run(async()=>{
   const config=this.capability(token);if(config.routeKind!=='PUBLIC_REPLY')throw Error('Reply registration required');g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);
   decode(data.requestId);const prior=await this.load(await this.key('request',config.id,data.requestId));let wire;
   if(prior){const original=JSON.parse(prior.value.request);if(original.display_name!==data.displayName||original.introduction!==data.introduction||original.nonce!==data.nonce||(data.expiresAt!==undefined&&original.expires_at!==data.expiresAt)||canonical(prior.value.targetCertificate)!==canonical(targetCertificate))throw Error('Public outbound retry context changed');wire=prior.value.request;}
   else{const seed=decode(config.routeSeed),sign=g.nacl.sign.keyPair.fromSeed(seed);seed.fill(0);try{wire=await this.codec.request(targetCertificate,{...data,replyCertificate:config.certificate,bootstrapBox:config.bootstrapBox},sign.secretKey);}finally{sign.secretKey.fill(0);}}
   const checked=await this.codec.inspectRequest(targetCertificate,wire),key=await this.key('request',config.id,checked.requestId),old=await this.load(key);let saved;
   if(old){if(old.value.requestDigest!==checked.digest)throw Error('Public outbound retry changed bytes');saved=old.value;}
   else{await this.quota(config,wire);saved={kind:'public-request',registration:config.id,requestId:checked.requestId,requestDigest:checked.digest,expiresAt:checked.expiresAt,state:'REQUESTED',direction:'OUTBOUND',request:wire,targetCertificate,blob:g.DmashRecipientPayloadV4.sealPayload(decode(targetCertificate.recipient_box),wire),claim:null};await this.save(key,null,saved,()=>{this.capability(token);return true;});}
   this.capability(token);const found=await this.local.discover(targetCertificate);this.capability(token);g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);g.DmashRouteDiscoveryV4.verifyCertificate(targetCertificate);if(saved.expiresAt<=Math.floor(Date.now()/1000))throw Error('Public request expired before send');const route=this.local.routes.get(found.handle),entry=this.#routes.get(config.id);if(!route||!entry)throw Error('Public reply route unavailable');this.runtime.send(route.route,saved.blob,entry.handler);return {queued:true,requestId:checked.requestId,requestDigest:checked.digest};
  });}
  decline(token,requestId,requestDigest){return this.run(async()=>{const config=this.capability(token),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.requestDigest!==requestDigest||old.value.direction!=='INBOUND'||!['PENDING','DENIED'].includes(old.value.state))throw Error('Public decline context');if(old.value.state==='DENIED')return {denied:true};await this.save(key,old,{...old.value,state:'DENIED',request:null},()=>{this.capability(token);return true;});return {denied:true};});}
  claim(token,ownerToken,requestId,requestDigest,localBundle){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken);if(config.routeKind!=='PUBLIC_INTAKE')throw Error('Public intake required');const final=await this.ownership.read(owner.routeId);this.ownership.owner(ownerToken);if(final&&['ACTIVE','RETIRED'].includes(final.state))throw Error('Public claim cannot reuse final route');await this.privateCodec.localOffer(localBundle,owner);if(JSON.parse(localBundle).intended_peer!==null)throw Error('Public claim requires neutral offer');
   const key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.requestDigest!==requestDigest||old.value.expiresAt<=Math.floor(Date.now()/1000)||!['PENDING','CLAIMED'].includes(old.value.state))throw Error('Public claim context');
   if(old.value.claim){if(old.value.claim.ownerSlot!==owner.ownerSlot||old.value.claim.routeAuthorityDigest!==owner.routeAuthorityDigest||old.value.claim.localBundle!==localBundle)throw Error('Public request already claimed');return {claimed:true,bootstrapBox:old.value.claim.bootstrapBox};}
   const box=g.nacl.box.keyPair();try{const claim={ownerSlot:owner.ownerSlot,routeAuthorityDigest:owner.routeAuthorityDigest,accountPublic:owner.accountPublic,localBundle,bootstrapBox:hex(box.publicKey),bootstrapKey:hex(box.secretKey)};await this.save(key,old,{...old.value,state:'CLAIMED',claim},()=>{this.capability(token);this.ownership.owner(ownerToken);return true;});return {claimed:true,bootstrapBox:claim.bootstrapBox};}finally{box.secretKey.fill(0);}
  });}
  async contexts(config,row){const target=row.direction==='INBOUND'?config.certificate:row.targetCertificate,request=await this.codec.inspectRequest(target,row.request),accepted=row.accept?await this.codec.inspectAccept(request,row.accept):null,confirmed=row.confirm?await this.codec.inspectConfirm(accepted,row.confirm):null;return {request,accepted,confirmed};}
  envelope(requestId,kind,wire,key){const box=g.DmashRouteDiscoveryV4.seal(decode(key),{wire});return this.codec.fits(canonical({type:'CONTACT_PRIVATE_V2',request_id:requestId,kind,box}));}
  sealed(certificate,wire){return g.DmashRecipientPayloadV4.sealPayload(decode(certificate.recipient_box),wire);}
  async sendStored(config,certificate,blob,guard,expiresAt){guard();const found=await this.local.discover(certificate);guard();g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);g.DmashRouteDiscoveryV4.verifyCertificate(certificate);if(!Number.isSafeInteger(expiresAt)||expiresAt<=Math.floor(Date.now()/1000))throw Error('Public control expired before send');const destination=this.local.routes.get(found.handle),entry=this.#routes.get(config.id);if(!destination||!entry)throw Error('Public sender registration unavailable');this.runtime.send(destination.route,blob,entry.handler);return {queued:true};}
  checkClaim(row,owner){if(!row.claim||row.claim.ownerSlot!==owner.ownerSlot||row.claim.routeAuthorityDigest!==owner.routeAuthorityDigest||row.claim.accountPublic!==owner.accountPublic)throw Error('Public claim owner mismatch');}
  accept(token,ownerToken,requestId,wire){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.direction!=='INBOUND')throw Error('Public inbound request required');this.checkClaim(old.value,owner);
   const context=await this.contexts(config,old.value),checked=await this.codec.inspectAccept(context.request,wire),value=JSON.parse(wire);if(checked.accountPublic!==owner.accountPublic||value.bundle!==old.value.claim.localBundle||value.bootstrap_box!==old.value.claim.bootstrapBox)throw Error('Public accept claim mismatch');
   const request=JSON.parse(old.value.request);let saved=old.value;if(saved.accept&&saved.accept!==wire)throw Error('Public accept replay changed');const guard=()=>{this.capability(token);this.ownership.owner(ownerToken);return true;};
   if(!saved.accept){const wrapped=this.envelope(requestId,'ACCEPT',wire,request.bootstrap_box);saved={...saved,state:'ACCEPTED',accept:wire,acceptBlob:this.sealed(request.reply_certificate,wrapped)};await this.save(key,old,saved,guard);}
   return this.sendStored(config,request.reply_certificate,saved.acceptBlob,guard,value.expires_at);
  });}
  confirm(token,ownerToken,requestId,wire){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.direction!=='OUTBOUND'||!old.value.accept)throw Error('Public accepted candidate required');
   const context=await this.contexts(config,old.value),checked=await this.codec.inspectConfirm(context.accepted,wire),value=JSON.parse(wire);if(checked.remoteAccount!==owner.accountPublic)throw Error('Public confirming Account mismatch');await this.privateCodec.localOffer(value.bundle,owner);const final=await this.ownership.read(owner.routeId);this.ownership.owner(ownerToken);if(final&&['ACTIVE','RETIRED'].includes(final.state)&&!old.value.confirm)throw Error('Public confirm cannot reuse final route');
   const guard=()=>{this.capability(token);this.ownership.owner(ownerToken);return true;};let saved=old.value;
   if(saved.confirm){this.checkClaim(saved,owner);if(saved.confirm!==wire)throw Error('Public confirm replay changed');}
   else{const wrapped=this.envelope(requestId,'CONFIRM',wire,JSON.parse(saved.accept).bootstrap_box);saved={...saved,state:'CONFIRMED',confirm:wire,confirmBlob:this.sealed(saved.targetCertificate,wrapped),receipts:value.accept_receipt?{ACCEPT:value.accept_receipt}:{},claim:{ownerSlot:owner.ownerSlot,routeAuthorityDigest:owner.routeAuthorityDigest,accountPublic:owner.accountPublic,localBundle:value.bundle}};await this.save(key,old,saved,guard);}
   return this.sendStored(config,saved.targetCertificate,saved.confirmBlob,guard,value.expires_at);
  });}
  replaySaved(key,config,certificate,blob,expiresAt){if(this.#replays.has(key)||this.#replays.size>=16)return;this.#replays.add(key);setTimeout(()=>{this.sendStored(config,certificate,blob,()=>{this.check();return true;},expiresAt).catch(()=>{}).finally(()=>this.#replays.delete(key));},0);}
  async receivePrivate(config,wrapper){
   if(Object.keys(wrapper).sort().join(',')!=='box,kind,request_id,type'||!['ACCEPT','CONFIRM','RECEIPT'].includes(wrapper.kind))throw Error('Public private wrapper schema');decode(wrapper.request_id);
   const key=await this.key('request',config.id,wrapper.request_id),old=await this.load(key);if(!old||old.value.expiresAt<=Math.floor(Date.now()/1000))throw Error('Public outstanding request required');
   const keyHex=old.value.direction==='OUTBOUND'?config.bootstrapKey:old.value.claim?.bootstrapKey;if(!keyHex)throw Error('Public bootstrap recipient absent');const secret=decode(keyHex);let content;try{content=g.DmashRouteDiscoveryV4.openBox(secret,wrapper.box);}finally{secret.fill(0);}if(!content||Object.keys(content).join(',')!=='wire'||typeof content.wire!=='string')throw Error('Public encrypted content schema');
   const context=await this.contexts(config,old.value);let changes;
   if(wrapper.kind==='ACCEPT'){
    if(old.value.direction!=='OUTBOUND')throw Error('Public accept direction');await this.codec.inspectAccept(context.request,content.wire);if(old.value.accept){if(old.value.accept!==content.wire)throw Error('Public accept conflict');return {stored:true,duplicate:true};}changes={state:'CANDIDATE',accept:content.wire};
   }else if(wrapper.kind==='CONFIRM'){
    if(old.value.direction!=='INBOUND'||!context.accepted)throw Error('Public confirm direction');await this.codec.inspectConfirm(context.accepted,content.wire);if(old.value.confirm){if(old.value.confirm!==content.wire)throw Error('Public confirm conflict');const reply=JSON.parse(old.value.request).reply_certificate;for(const [phase,blob] of Object.entries(old.value.receiptBlobs||{}))this.replaySaved(config.id+'|'+wrapper.request_id+'|'+phase,config,reply,blob,JSON.parse(old.value.confirm).expires_at);return {stored:true,duplicate:true};}const initial=JSON.parse(content.wire).accept_receipt;changes={state:'CONFIRMED',confirm:content.wire,receipts:initial?{ACCEPT:initial}:{}};
   }else{
    if(!context.confirmed)throw Error('Public final context absent');const receipt=this.codec.receipt(context.confirmed,content.wire),previous=old.value.receipts?.[receipt.phase];if(previous){if(previous!==content.wire)throw Error('Public receipt conflict');if(receipt.phase==='ACCEPT'&&old.value.direction==='OUTBOUND'&&old.value.receiptBlobs?.CONFIRM)this.replaySaved(config.id+'|'+wrapper.request_id+'|CONFIRM',config,old.value.targetCertificate,old.value.receiptBlobs.CONFIRM,JSON.parse(old.value.confirm).expires_at);return {stored:true,duplicate:true};}if(receipt.phase==='CONFIRM'&&!old.value.receipts?.ACCEPT)throw Error('Public ACCEPT receipt required');changes={receipts:{...old.value.receipts,[receipt.phase]:content.wire}};
   }
   await this.save(key,old,{...old.value,...changes});return {stored:true,duplicate:false};
  }
  receipt(token,ownerToken,requestId,wire){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old?.value.confirm)throw Error('Public confirmed exchange required');this.checkClaim(old.value,owner);const context=await this.contexts(config,old.value),receipt=this.codec.receipt(context.confirmed,wire);if(receipt.signer!==owner.accountPublic)throw Error('Public receipt signer not local owner');
   if(receipt.phase==='CONFIRM'&&!old.value.receipts?.ACCEPT)throw Error('Public ACCEPT receipt required');const previous=old.value.receipts?.[receipt.phase];if(previous&&previous!==wire)throw Error('Public receipt changed');
   const guard=()=>{this.capability(token);this.ownership.owner(ownerToken);return true;},request=JSON.parse(old.value.request),destination=old.value.direction==='INBOUND'?request.reply_certificate:old.value.targetCertificate,box=old.value.direction==='INBOUND'?request.bootstrap_box:JSON.parse(old.value.accept).bootstrap_box;
   let saved=old.value,blob=saved.receiptBlobs?.[receipt.phase];if(!blob){blob=this.sealed(destination,this.envelope(requestId,'RECEIPT',wire,box));saved={...saved,receipts:{...saved.receipts,[receipt.phase]:wire},receiptBlobs:{...saved.receiptBlobs,[receipt.phase]:blob}};await this.save(key,old,saved,guard);}return this.sendStored(config,destination,blob,guard,JSON.parse(saved.confirm).expires_at);
  });}
  close(){if(this.closed)return;this.closed=true;this.#caps.clear();for(const row of this.#routes.values()){row.sign.secretKey.fill(0);row.box.secretKey.fill(0);row.recipient.fill(0);}this.#routes.clear();this.inbox.close();}
 }
 g.DmashNodePublicBootstrapRuntimeV4=PublicRuntime;if(typeof module!=='undefined')module.exports=PublicRuntime;
})(globalThis);
