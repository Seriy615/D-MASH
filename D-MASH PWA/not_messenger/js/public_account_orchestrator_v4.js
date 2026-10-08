'use strict';
(function(g){
 const DOMAIN='D-MASH|PUBLIC-ACCOUNT-INTENT|V4\0',STORE='pairing_material';
 const utf=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),b64=b=>btoa(String.fromCharCode(...b));
 const fail=code=>{throw Object.assign(Error(code),{code});};
 const unhex=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))fail('PUBLIC_ACCOUNT_ENCODING');return Uint8Array.from(s.match(/../g),v=>parseInt(v,16));};
 class PublicAccountOrchestratorV4{
  #poll=null;#history;#core;#storage;#active=new Map();#opened=new Set();#sealed;#transport;#runtime;#progress;#inbox;#session;#coordinator;#capture;#host;#journal;#router;#kem;#aliasKey;#owners=new Map();#closed=false;#tail=Promise.resolve();#transactions=new Set();#ownerAbort=new AbortController();#onAbort;#account;#pairing;#binding;#control;
  static async open({core,storage,deviceRoot,coordinator}){
   if(typeof core?.captureAccountSessionV4!=='function')fail('ACCOUNT_SESSION_REQUIRED');
   const s=core.captureAccountSessionV4();s.assertCurrent();
   if(storage?.db!==s.db||storage.masterKey!==s.masterKey||deviceRoot?.state!==s.rootState||!s.db.objectStoreNames.contains(STORE))fail('ACCOUNT_VAULT_CONTEXT');
   const value=new PublicAccountOrchestratorV4();value.#core=core;value.#storage=storage;value.#session=s;value.#coordinator=coordinator;value.#account=hex(s.keys.sign.publicKey);
   value.#onAbort=()=>value.close();s.signal.addEventListener('abort',value.#onAbort,{once:true});
   try{
    await value.#wait(coordinator.start());value.#capture=coordinator.capture();value.#host=value.#capture.host;
    if(value.#host.localOwnership!=='managed'||value.#host.identity?.bootstrapProfile!=='public-v1')fail('PUBLIC_NODE_PROFILE_REQUIRED');
    value.#pairing=g.DmashAccountPairingV2.createCodec({nacl:g.nacl,discovery:g.DmashRouteDiscoveryV4});value.#binding=g.DmashAccountRouteBindingV2.createBindingCodec({nacl:g.nacl,discovery:g.DmashRouteDiscoveryV4,pairing:value.#pairing});value.#control=g.DmashNodePublicBootstrapControlV4.createCodec({pairing:value.#pairing,binding:value.#binding});
    value.#aliasKey=await value.#wait(crypto.subtle.importKey('raw',s.blindSalt,{name:'HMAC',hash:'SHA-256'},false,['sign']));
    value.#kem=await value.#wait(g.DmashAccountStaticKemV1.open({session:s}));
    value.#journal=await value.#wait(g.DmashAccountRouteJournalV2.open({core,storage,deviceRoot,accountSignal:s.signal,bindingCodec:value.#binding,verifyPreparation:value.#host.verifyPreparation.bind(value.#host)}));
    value.#router=coordinator.registerAccountJournal(value.#journal);value.#check();return value;
   }catch(error){value.close();throw error;}
  }
  #check(){if(this.#closed)fail('PUBLIC_ACCOUNT_CLOSED');this.#session.assertCurrent();if(this.#capture&&!this.#capture.current())fail('PUBLIC_ROOT_CHANGED');}
  async #wait(p){this.#check();const value=await p;this.#check();return value;}
  #run(fn){const task=this.#tail.then(()=>{this.#check();return fn();});this.#tail=task.catch(()=>{});return task;}
  get account(){return this.#account;}
  close(){if(this.#closed)return;this.#closed=true;this.#ownerAbort.abort();this.#owners.clear();this.#active.clear();this.#opened.clear();this.#history?.close();this.#inbox?.close();this.#progress?.close();this.#runtime?.close();this.#transport?.close();this.#sealed?.close();for(const tx of this.#transactions)try{tx.abort();}catch(_){}this.#transactions.clear();this.#journal?.close();this.#kem?.close();if(this.#router)this.#coordinator.unregisterAccountJournal(this.#router);this.#session?.signal.removeEventListener('abort',this.#onAbort);}
  async #alias(registrationId,requestId){unhex(registrationId);unhex(requestId);return hex(new Uint8Array(await this.#wait(crypto.subtle.sign('HMAC',this.#aliasKey,utf(DOMAIN+this.#account+'|'+registrationId+'|'+requestId)))));}
  #tx(alias,write,expected){this.#check();return new Promise((resolve,reject)=>{let row,error;const tx=this.#session.db.transaction(STORE,write?'readwrite':'readonly');this.#transactions.add(tx);tx.oncomplete=()=>{this.#transactions.delete(tx);try{this.#check();resolve(row??null);}catch(e){reject(e);}};tx.onabort=()=>{this.#transactions.delete(tx);reject(error||tx.error||Error('PUBLIC_INTENT_ABORTED'));};tx.onerror=()=>{};const store=tx.objectStore(STORE),request=store.get(alias);request.onsuccess=()=>{try{this.#check();row=request.result;if(write){if((row?.blob??null)!==expected)fail('PUBLIC_INTENT_CONFLICT');store.put(write);row=write;}}catch(e){error=e;tx.abort();}};});}
  async #read(alias){const row=await this.#wait(this.#tx(alias));if(!row)return null;let plain;try{if(row.alias!==alias||typeof row.blob!=='string'||row.blob.length>65536)fail('PUBLIC_INTENT_CORRUPT');const bytes=Uint8Array.from(atob(row.blob),x=>x.charCodeAt(0));if(bytes.length<28||b64(bytes)!==row.blob)fail('PUBLIC_INTENT_CORRUPT');plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(0,12),additionalData:utf(DOMAIN+alias)},this.#session.masterKey,bytes.subarray(12)));this.#check();return {row,value:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain))};}finally{plain?.fill(0);}}
  async #save(alias,prior,value){this.#check();const plain=utf(JSON.stringify(value));if(plain.length>45000)fail('PUBLIC_INTENT_QUOTA');try{const iv=crypto.getRandomValues(new Uint8Array(12)),cipher=new Uint8Array(await this.#wait(crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf(DOMAIN+alias)},this.#session.masterKey,plain))),packed=new Uint8Array(12+cipher.length);packed.set(iv);packed.set(cipher,12);const row=await this.#wait(this.#tx(alias,{alias,blob:b64(packed)},prior?.row.blob??null));return {row,value};}finally{plain.fill(0);}}
  async #selected(registration,requestId,requestDigest){
   unhex(requestId);unhex(requestDigest);unhex(registration?.id);let after=null;
   for(let page=0;page<4;page++){const rows=await this.#wait(this.#host.publicRequests(registration.capability,{limit:16,after}));const row=rows.find(r=>r.requestId===requestId);if(row){if(row.registration!==registration.id||row.requestDigest!==requestDigest||row.expiresAt<=Math.floor(Date.now()/1000)||!row.request)fail('PUBLIC_REQUEST_CONTEXT');return row;}if(rows.length<16)break;after=rows.at(-1).requestId;}
   fail('PUBLIC_REQUEST_MISSING');
  }
  async #verifyIntent(intent,row,registration,target){
   const v=intent.value;if(v.type!=='PUBLIC_ACCOUNT_INTENT_V4'||v.account!==this.#account||v.registration!==registration.id||v.requestId!==row.requestId||v.requestDigest!==row.requestDigest||v.direction!==row.direction||v.target!==target)fail('PUBLIC_INTENT_CONTEXT');unhex(v.migrationId);
   const bundle=this.#pairing.parse(v.bundle,{expectedPeer:this.#account,localAccount:target??undefined}).bundle;
   if(bundle.account_keys.kem_profile!==g.DmashAccountStaticKemV1.PROFILE||bundle.intended_peer!==target||bundle.generation!==1)fail('PUBLIC_INTENT_PROFILE');
   const kem=await this.#wait(this.#kem.load());if(!kem)fail('PUBLIC_INTENT_KEM_MISSING');try{if(kem.profile!==bundle.account_keys.kem_profile||b64(kem.publicKey).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==bundle.account_keys.kem_public)fail('PUBLIC_INTENT_KEM_CHANGED');}finally{this.#kem.release(kem);}
   const material=[];let route,sign,box,recipient;try{for(const value of [v.routeSeed,v.discoverySeed,v.discoveryBox,v.recipientKey])material.push(unhex(value));route=g.nacl.sign.keyPair.fromSeed(material[0]);sign=g.nacl.sign.keyPair.fromSeed(material[1]);box=g.nacl.box.keyPair.fromSecretKey(material[2]);recipient=g.nacl.box.keyPair.fromSecretKey(material[3]);if(hex(route.publicKey)!==bundle.inbound_certificate.route_id||hex(sign.publicKey)!==bundle.inbound_certificate.discovery_sign||hex(box.publicKey)!==bundle.inbound_certificate.discovery_box||hex(recipient.publicKey)!==bundle.inbound_certificate.recipient_box)fail('PUBLIC_INTENT_MATERIAL');}finally{for(const bytes of [...material,route?.secretKey,sign?.secretKey,box?.secretKey,recipient?.secretKey])bytes?.fill(0);}
   return bundle;
  }
  async #intent(row,registration,target){
   const alias=await this.#alias(registration.id,row.requestId);let saved=await this.#read(alias);if(saved){await this.#verifyIntent(saved,row,registration,target);return {alias,...saved};}
   const kem=await this.#wait(this.#kem.createExplicit()),route=g.nacl.sign.keyPair(),sign=g.nacl.sign.keyPair(),box=g.nacl.box.keyPair(),recipient=g.nacl.box.keyPair(),now=Math.floor(Date.now()/1000);
   try{
    const certificate=g.DmashRouteDiscoveryV4.issueCertificate(route,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:row.expiresAt});
    const bundle=this.#pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(crypto.getRandomValues(new Uint8Array(32))),generation:1,issued_at:now,expires_at:row.expiresAt,previous_binding:null,intended_peer:target,contribution:hex(crypto.getRandomValues(new Uint8Array(32))),account_keys:{signing:this.#account,box:hex(this.#session.keys.box.publicKey),kem_profile:kem.profile,kem_public:b64(kem.publicKey).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')},inbound_certificate:certificate},this.#session.keys.sign.secretKey,{localAccount:target??undefined}).serialized;
    const value={type:'PUBLIC_ACCOUNT_INTENT_V4',account:this.#account,registration:registration.id,requestId:row.requestId,requestDigest:row.requestDigest,direction:row.direction,target,bundle,routeSeed:hex(route.secretKey.subarray(0,32)),discoverySeed:hex(sign.secretKey.subarray(0,32)),discoveryBox:hex(box.secretKey),recipientKey:hex(recipient.secretKey),migrationId:hex(crypto.getRandomValues(new Uint8Array(32))),controls:{}};
    try{saved=await this.#save(alias,null,value);}catch(error){if(error.code!=='PUBLIC_INTENT_CONFLICT')throw error;saved=await this.#read(alias);if(!saved)throw error;await this.#verifyIntent(saved,row,registration,target);}return {alias,...saved};
   }finally{this.#kem.release(kem);for(const key of [route.secretKey,sign.secretKey,box.secretKey,recipient.secretKey])key.fill(0);}
  }
  async #owner(intent){const id=JSON.parse(intent.value.bundle).inbound_certificate.route_id;if(this.#owners.has(id))return this.#owners.get(id);if(this.#owners.size>=32)fail('PUBLIC_OWNER_QUOTA');const certificate=JSON.parse(intent.value.bundle).inbound_certificate,challenge=await this.#wait(this.#host.challengeLocalOwner(this.#account,certificate)),signature=g.nacl.sign.detached(utf(challenge.transcript),this.#session.keys.sign.secretKey);const cap=await this.#wait(this.#host.registerLocalOwner(challenge.challenge,signature,{accountPublic:this.#account,isAccountCurrent:()=>{try{this.#check();return true;}catch(_){return false;}},signal:this.#ownerAbort.signal}));this.#owners.set(id,cap);return cap;}
  async #saveControl(intent,kind,wire){if(intent.value.controls[kind])return intent;return {alias:intent.alias,...await this.#save(intent.alias,intent,{...intent.value,controls:{...intent.value.controls,[kind]:wire}})};}
  async #indexAlias(){return this.#alias('0'.repeat(64),'0'.repeat(64));}
  async #rememberPeer(peer,intent){
   const alias=await this.#indexAlias(),prior=await this.#read(alias),value=prior?.value||{type:'PUBLIC_ACTIVE_INDEX_V4',account:this.#account,peers:[]};
   if(value.type!=='PUBLIC_ACTIVE_INDEX_V4'||value.account!==this.#account||!Array.isArray(value.peers)||value.peers.length>32)fail('PUBLIC_PEER_INDEX_CORRUPT');
   const entries=value.peers.filter(row=>row.peer!==peer);if(entries.length>=32)fail('PUBLIC_OWNER_QUOTA');
   entries.push({peer,intentAlias:intent.alias});await this.#save(alias,prior,{...value,peers:entries});
  }
  rehydrate(){return this.#run(async()=>{
   const index=await this.#read(await this.#indexAlias());if(!index)return {restored:0,pending:[]};
   const value=index.value;if(value.type!=='PUBLIC_ACTIVE_INDEX_V4'||value.account!==this.#account||!Array.isArray(value.peers)||value.peers.length>32)fail('PUBLIC_PEER_INDEX_CORRUPT');
   const result={restored:0,pending:[]};
   for(const row of value.peers){
    unhex(row.peer);unhex(row.intentAlias);const saved=await this.#read(row.intentAlias);if(!saved)fail('PUBLIC_INTENT_MISSING');const intent={alias:row.intentAlias,...saved},v=intent.value;
    if(await this.#alias(v.registration,v.requestId)!==row.intentAlias)fail('PUBLIC_INTENT_CONTEXT');
    try{
     await this.#verifyIntent(intent,{requestId:v.requestId,requestDigest:v.requestDigest,direction:v.direction},{id:v.registration},v.target);
     const snapshot=await this.#wait(this.#journal.readRouteSnapshot(row.peer));if(!snapshot?.preparation||snapshot.readiness!=='NODE_PROOF_REQUIRED')fail('PUBLIC_PEER_REQUIRES_MIGRATION');
     const owner=await this.#owner(intent),cached=this.#active.get(row.peer);let preparation=cached?.bindingDigest===snapshot.digest&&cached.generation===snapshot.generation?cached.preparation:null;if(!preparation){const query=await this.#wait(this.#host.queryLocalBinding(owner,v.migrationId));if(!query?.handle)fail('PUBLIC_PREPARATION_MISSING');preparation=query.handle;}
     const proof=await this.#wait(this.#host.verifyPreparation(preparation,snapshot.preparation));if(proof.state!=='ACTIVE')fail('PUBLIC_ACCOUNT_NOT_ACTIVE');
     this.#active.set(row.peer,Object.freeze({peer:row.peer,capability:owner,preparation,bindingDigest:snapshot.digest,generation:snapshot.generation}));
     const runtime=await this.#openRuntime();await this.#wait(runtime.openPeer(row.peer,{requiredSuite:g.DmashAccountHandshakeV4.SUITE}));this.#opened.add(row.peer);result.restored++;
    }catch(error){this.#check();result.pending.push({peer:row.peer,code:error.code||error.message});}
   }
   if(this.#runtime)this.#runtime.startRetries();return result;
  });}
  async #openRuntime(){
   if(this.#runtime)return this.#runtime;
   // All resolver entries originate in successful Host + Account journal activation.
   // Caller-supplied peer identifiers can select an entry, never create authority.
   this.#sealed=await this.#wait(g.DmashAccountSealedOperationV4.open({session:this.#session,journal:this.#journal}));
   this.#transport=new g.DmashAccountNodeTransportV4(this.#host,this.#core,this.#storage,{journal:this.#journal,sealedStore:this.#sealed,resolveOwner:(peer,snapshot)=>{
    this.#check();const value=this.#active.get(peer);if(!value||value.bindingDigest!==snapshot.digest||value.generation!==snapshot.generation)fail('PUBLIC_ACTIVE_OWNER_REQUIRED');return value;
   }});
   this.#history=new g.DmashAccountAuthenticatedHistoryV4({core:this.#core,verifySuccessor:(proof,expected)=>{this.#check();if(!this.#runtime)fail('PUBLIC_SESSION_REQUIRED');return this.#wait(this.#runtime.verifyPendingSuccessor(proof,expected));},verifyMigration:async peer=>{const status=await this.#sessionStatus(peer);if(!status.sessionEstablished)fail('PUBLIC_KEYS_PENDING');const active=this.#active.get(peer);if(typeof this.#runtime.contactMigrationProof!=='function')fail('PUBLIC_MIGRATION_PROOF_UPGRADE_REQUIRED');const proof=await this.#wait(this.#runtime.contactMigrationProof(peer));if(proof.peer!==peer||proof.bindingDigest!==active.bindingDigest||proof.generation!==active.generation||proof.sessionId!==status.sessionId)fail('PUBLIC_MIGRATION_CONTEXT');await this.#wait(this.#transport.getRoute(peer));return proof;}});
   this.#runtime=new g.DmashAccountSessionRuntimeV4({core:this.#core,transport:this.#transport,persistAuthenticated:this.#history.persistAuthenticated.bind(this.#history),persistOutgoing:this.#history.persistOutgoing.bind(this.#history),persistOutgoingAck:this.#history.ackOutgoing.bind(this.#history),migrateOutgoing:this.#history.migrateOutgoingContext.bind(this.#history),outgoingDeliveryStatus:this.#history.outgoingDeliveryStatus.bind(this.#history),verifyOutgoingDeliveryStatus:this.#history.verifyOutgoingDeliveryStatus.bind(this.#history)});
   try{
    this.#progress=await this.#wait(g.DmashAccountInboxProgressV4.open({session:this.#session,kind:'managed'}));
    this.#inbox=new g.DmashAccountManagedInboxV4(this.#host,{session:this.#session,journal:this.#journal,progress:this.#progress,resolveOwners:async()=>{this.#check();return [...this.#active.values()];},consume:payload=>this.#runtime.receive(payload)});
    return this.#runtime;
   }catch(error){this.#runtime.close();this.#transport.close();this.#sealed.close();this.#runtime=null;throw error;}
  }
  migrateContact(peer){return this.#run(async()=>{unhex(peer);if(!this.#opened.has(peer))fail('PUBLIC_SESSION_REQUIRED');return this.#wait(this.#history.migrateContact(peer));});}
  publishContact(peer,name){return this.#run(async()=>{
   unhex(peer);if(!this.#active.has(peer))fail('PUBLIC_ACTIVE_OWNER_REQUIRED');await this.#openRuntime();
   await this.#wait(this.#transport.getRoute(peer));return this.#wait(this.#history.registerContact(peer,name));
  });}
  async sendApplication(peer,message){this.#check();
   unhex(peer);if(!this.#opened.has(peer))fail('PUBLIC_SESSION_REQUIRED');const status=await this.#sessionStatus(peer);if(!status.sessionEstablished)fail('PUBLIC_KEYS_PENDING');
   if(this.#runtime.durableApplicationEnqueue!==true||typeof this.#runtime.resumeApplications!=='function')fail('PUBLIC_OUTBOX_UPGRADE_REQUIRED');return this.#wait(this.#runtime.sendApplication(peer,message));
  }
  establish(peer){return this.#run(async()=>{
   unhex(peer);if(!this.#active.has(peer))fail('PUBLIC_ACTIVE_OWNER_REQUIRED');const runtime=await this.#openRuntime();
   await this.#wait(runtime.openPeer(peer,{requiredSuite:g.DmashAccountHandshakeV4.SUITE}));this.#opened.add(peer);
   const prior=await this.#wait(runtime.status(peer));if(prior.phase==='NO_SESSION')await this.#wait(runtime.initiate(peer));
   return this.#sessionStatus(peer);
  });}
  async #sessionStatus(peer){
   const status=await this.#wait(this.#runtime.status(peer));
   const route=await this.#wait(this.#transport.getRoute(peer));
   return Object.freeze({...status,sessionEstablished:status.phase==='ESTABLISHED'&&!!route});
  }
  sessionStatus(peer){return this.#run(async()=>{unhex(peer);if(!this.#opened.has(peer))fail('PUBLIC_SESSION_REQUIRED');return this.#sessionStatus(peer);});}
  pollSessions(){
   this.#check();if(this.#poll)return this.#poll;
   const task=(async()=>{if(!this.#runtime)return {processed:0,statuses:[]};this.#runtime.startRetries();const result=await this.#wait(this.#inbox.drain());const statuses=[];for(const peer of [...this.#opened])statuses.push({peer,...await this.#sessionStatus(peer)});return {...result,statuses};})();
   this.#poll=task;return task.finally(()=>{if(this.#poll===task)this.#poll=null;});
  }
  accept(registration,requestId,requestDigest){return this.#run(async()=>{const row=await this.#selected(registration,requestId,requestDigest);if(row.direction!=='INBOUND')fail('PUBLIC_ACCEPT_DIRECTION');let intent=await this.#intent(row,registration,null);const owner=await this.#owner(intent);if(row.claim&&(row.claim.accountPublic!==this.#account||row.claim.localBundle!==intent.value.bundle))fail('PUBLIC_CLAIM_CHANGED');const claim=row.claim||await this.#wait(this.#host.claimPublicRequest(registration.capability,owner,requestId,requestDigest,intent.value.bundle)),request=await this.#wait(this.#control.inspectRequest(registration.certificate,row.request));if(!intent.value.controls.ACCEPT)intent=await this.#saveControl(intent,'ACCEPT',await this.#wait(this.#control.accept(request,{bundle:intent.value.bundle,bootstrapBox:claim.bootstrapBox},this.#session.keys.sign.secretKey)));await this.#wait(this.#host.submitPublicControl(registration.capability,owner,requestId,'ACCEPT',intent.value.controls.ACCEPT));return {state:'ACCEPT_SENT',ready:false};});}
  confirm(registration,requestId,requestDigest,expectedPeer){return this.#run(async()=>{unhex(expectedPeer);const row=await this.#selected(registration,requestId,requestDigest);if(row.direction!=='OUTBOUND'||!row.accept)fail('PUBLIC_CONFIRM_DIRECTION');const request=await this.#wait(this.#control.inspectRequest(row.targetCertificate,row.request)),accepted=await this.#wait(this.#control.inspectAccept(request,row.accept));if(accepted.accountPublic!==expectedPeer)fail('PUBLIC_PEER_SELECTION');let intent=await this.#intent(row,registration,expectedPeer);const owner=await this.#owner(intent),stage=await this.#wait(this.#journal.stage([JSON.parse(row.accept).bundle,intent.value.bundle],expectedPeer)),receipt=stage.phase==='ACCEPT'?await this.#wait(this.#journal.reserveAndSign(stage)):null;if(!intent.value.controls.CONFIRM)intent=await this.#saveControl(intent,'CONFIRM',await this.#wait(this.#control.confirm(accepted,{bundle:intent.value.bundle,acceptReceipt:receipt},this.#session.keys.sign.secretKey)));await this.#wait(this.#host.submitPublicControl(registration.capability,owner,requestId,'CONFIRM',intent.value.controls.CONFIRM));return {state:'CONFIRM_SENT',ready:false};});}
  advance(registration,requestId,requestDigest){return this.#run(async()=>{
   const row=await this.#selected(registration,requestId,requestDigest);if(!row.accept||!row.confirm)return {state:'WAITING_PUBLIC_CONTROL',ready:false};
   const request=await this.#wait(this.#control.inspectRequest(row.direction==='INBOUND'?registration.certificate:row.targetCertificate,row.request)),accepted=await this.#wait(this.#control.inspectAccept(request,row.accept));await this.#wait(this.#control.inspectConfirm(accepted,row.confirm));
   const bundles=[JSON.parse(row.accept).bundle,JSON.parse(row.confirm).bundle],remote=bundles.map(b=>JSON.parse(b).account_keys.signing).find(a=>a!==this.#account);if(!remote)fail('PUBLIC_LOCAL_PARTICIPANT');const target=row.direction==='INBOUND'?null:remote,alias=await this.#alias(registration.id,requestId),saved=await this.#read(alias);if(!saved)fail('PUBLIC_INTENT_MISSING');const intent={alias,...saved};await this.#verifyIntent(intent,row,registration,target);if(!bundles.includes(intent.value.bundle))fail('PUBLIC_LOCAL_BUNDLE_CHANGED');
   const stage=await this.#wait(this.#journal.stage(bundles,remote)),owner=await this.#owner(intent);if(stage.phase==='CONFIRM'&&!row.receipts?.ACCEPT)return {state:'WAITING_ACCEPT_RECEIPT',ready:false};
   const localReceipt=await this.#wait(this.#journal.reserveAndSign(stage,row.receipts?.ACCEPT));await this.#wait(this.#host.submitPublicControl(registration.capability,owner,requestId,'RECEIPT',localReceipt));const latest=await this.#selected(registration,requestId,requestDigest);if(!latest.receipts?.ACCEPT||!latest.receipts?.CONFIRM)return {state:'WAITING_BILATERAL_RECEIPTS',ready:false};
   const certificate=JSON.parse(intent.value.bundle).inbound_certificate,preparation=await this.#wait(this.#host.prepareLocalBinding(owner,{certificate,migrationId:intent.value.migrationId,bindingDigest:stage.digest,expectedGeneration:stage.generation,discoverySeed:unhex(intent.value.discoverySeed),discoveryBox:unhex(intent.value.discoveryBox),recipientKeys:[unhex(intent.value.recipientKey)]})),committed=await this.#wait(this.#journal.commit(stage,[latest.receipts.ACCEPT,latest.receipts.CONFIRM],{preparation}));
   if(!committed.commitReceipt)fail('PUBLIC_ACCOUNT_COMMIT_RECEIPT');await this.#wait(this.#host.activateLocalBinding(owner,preparation,committed.commitReceipt));const tuple=await this.#wait(this.#host.verifyPreparation(preparation,{accountPublic:this.#account,routeId:certificate.route_id,bindingDigest:stage.digest,generation:stage.generation}));if(tuple.state!=='ACTIVE')fail('PUBLIC_ACCOUNT_NOT_ACTIVE');await this.#rememberPeer(remote,intent);this.#active.set(remote,Object.freeze({peer:remote,capability:owner,preparation,bindingDigest:stage.digest,generation:stage.generation}));return {state:'ACCOUNT_ROUTE_ACTIVE',ready:true,peer:remote,bindingDigest:stage.digest,generation:stage.generation,sessionEstablished:false};
  });}
 }
 g.DmashPublicAccountOrchestratorV4=PublicAccountOrchestratorV4;if(typeof module!=='undefined')module.exports=PublicAccountOrchestratorV4;
})(globalThis);
