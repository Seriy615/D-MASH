'use strict';
(function(g){
 const DOMAIN='D-MASH|AUTHENTICATED-HISTORY|V4\0',stores=['blind_secrets','blind_messages','blind_peers','pairing_material'];
 const utf=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
 const fail=code=>{throw Object.assign(Error(code),{code});};
 const valid=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
 class AccountAuthenticatedHistoryV4{
  #deliveryProofs=new WeakMap();#verifySuccessor;#verifyMigration;#session;#hash;#salt;#closed=false;#txs=new Set();#abort;
  constructor({core,verifyMigration=null,verifySuccessor=null}){
   if(typeof core?.captureAccountSessionV4!=='function'||typeof core.fastHash!=='function')fail('HISTORY_ACCOUNT_REQUIRED');
   this.#verifySuccessor=verifySuccessor;this.#verifyMigration=verifyMigration;this.#session=core.captureAccountSessionV4();this.#session.assertCurrent();this.#hash=core.fastHash.bind(core);this.#salt=this.#session.blindSalt.slice();
   if(stores.some(s=>!this.#session.db.objectStoreNames.contains(s)))fail('HISTORY_STORE_REQUIRED');
   this.#abort=()=>this.close();this.#session.signal.addEventListener('abort',this.#abort,{once:true});
  }
  #check(){if(this.#closed)fail('HISTORY_CLOSED');this.#session.assertCurrent();}
  async #wait(p){this.#check();const v=await p;this.#check();return v;}
  async #alias(base,level){const a=utf(base+level),b=new Uint8Array(a.length+this.#salt.length);b.set(a);b.set(this.#salt,a.length);try{return await this.#wait(this.#hash(b));}finally{b.fill(0);}}
  async #crypt(value,aad){const plain=utf(JSON.stringify(value));try{const iv=crypto.getRandomValues(new Uint8Array(12)),box=new Uint8Array(await this.#wait(crypto.subtle.encrypt({name:'AES-GCM',iv,...(aad?{additionalData:utf(aad)}:{})},this.#session.masterKey,plain))),bytes=new Uint8Array(iv.length+box.length);bytes.set(iv);bytes.set(box,iv.length);return btoa(String.fromCharCode(...bytes));}finally{plain.fill(0);}}
  async #plain(row,aad){if(!row)return null;let plain;try{if(typeof row.blob!=='string'||row.blob.length>131072)fail('HISTORY_CORRUPT');const bytes=Uint8Array.from(atob(row.blob),c=>c.charCodeAt(0));if(bytes.length<28)fail('HISTORY_CORRUPT');plain=new Uint8Array(await this.#wait(crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(0,12),...(aad?{additionalData:utf(aad)}:{})},this.#session.masterKey,bytes.subarray(12))));return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}finally{plain?.fill(0);}}
  #read(keys){this.#check();return new Promise((resolve,reject)=>{const tx=this.#session.db.transaction(stores,'readonly'),rows={};this.#txs.add(tx);for(const [name,key] of Object.entries(keys)){const r=tx.objectStore(name).get(key);r.onsuccess=()=>rows[name]=r.result??null;}tx.oncomplete=()=>{this.#txs.delete(tx);try{this.#check();resolve(rows);}catch(e){reject(e);}};tx.onerror=()=>{};tx.onabort=()=>{this.#txs.delete(tx);reject(tx.error||Error('HISTORY_READ_ABORTED'));};});}
  #commit(prior,rows,dependencies=[]){this.#check();return new Promise((resolve,reject)=>{
   const tx=this.#session.db.transaction(stores,'readwrite');this.#txs.add(tx);let error,remaining=Object.keys(rows).length+dependencies.length;
   const checked=()=>{if(--remaining===0){this.#check();for(const [store,value] of Object.entries(rows))tx.objectStore(store).put(value);}};
   const guard=(request,expected)=>{request.onsuccess=()=>{try{this.#check();if((request.result?.blob??null)!==(expected?.blob??null))fail('HISTORY_CONFLICT');checked();}catch(e){error=e;tx.abort();}};};
   for(const [name,row]of Object.entries(rows))guard(tx.objectStore(name).get(row.alias),prior[name]);
   for(const dependency of dependencies)guard(tx.objectStore('pairing_material').get(dependency.alias),dependency);
   tx.oncomplete=()=>{this.#txs.delete(tx);try{this.#check();resolve();}catch(e){reject(e);}};tx.onerror=()=>{};tx.onabort=()=>{this.#txs.delete(tx);reject(error||tx.error||Error('HISTORY_WRITE_ABORTED'));};
  });}
  async migrateContact(peer){
   this.#check();if(!valid(peer)||typeof this.#verifyMigration!=='function')fail('HISTORY_MIGRATION_PROOF_REQUIRED');
   const proof=await this.#wait(this.#verifyMigration(peer));if(!proof||proof.peer!==peer||!valid(proof.bindingDigest)||!valid(proof.sessionId)||!Number.isSafeInteger(proof.generation)||proof.generation<1)fail('HISTORY_MIGRATION_PROOF_REQUIRED');
   const alias=await this.#alias(peer,'L1'),marker=await this.#alias(DOMAIN+'MIGRATION|'+peer,'APP_V4');
   for(let retry=0;retry<8;retry++){
    const prior=await this.#read({blind_peers:alias,pairing_material:marker}),contact=await this.#plain(prior.blind_peers),receipt=await this.#plain(prior.pairing_material,DOMAIN+marker);
    if(!contact||contact.id!==peer)fail('HISTORY_EXISTING_CONTACT_REQUIRED');
    if(receipt){if(receipt.type!=='ACCOUNT_CONTACT_MIGRATION_V4'||receipt.peer!==peer||receipt.bindingDigest!==proof.bindingDigest||receipt.generation!==proof.generation||contact.transportProfile!=='NODE_ACCOUNT_V4')fail('HISTORY_MIGRATION_CHANGED');return {migrated:true,duplicate:true};}
    if(contact.transportProfile==='NODE_ACCOUNT_V4')fail('HISTORY_MIGRATION_RECORD_MISSING');
    const fresh=await this.#wait(this.#verifyMigration(peer));if(JSON.stringify(fresh)!==JSON.stringify(proof))fail('HISTORY_MIGRATION_CHANGED');
    const rows={blind_peers:{alias,blob:await this.#crypt({...contact,transportProfile:'NODE_ACCOUNT_V4',nodeBindingDigest:proof.bindingDigest,nodeBindingGeneration:proof.generation})},pairing_material:{alias:marker,blob:await this.#crypt({type:'ACCOUNT_CONTACT_MIGRATION_V4',...proof,previousContact:prior.blind_peers,at:Date.now()},DOMAIN+marker)}};
    try{await this.#commit(prior,rows);return {migrated:true,duplicate:false};}catch(e){this.#check();if(e.code!=='HISTORY_CONFLICT')throw e;}
   }
   fail('HISTORY_CONTENTION');
  }
  async registerContact(peer,name){
   this.#check();if(!valid(peer)||typeof name!=='string'||!name.trim()||utf(name).length>256)fail('HISTORY_CONTACT_SCHEMA');
   const alias=await this.#alias(peer,'L1');
   for(let retry=0;retry<8;retry++){
    const prior=await this.#read({blind_peers:alias}),existing=await this.#plain(prior.blind_peers);
    if(existing){if(existing.id!==peer||existing.transportProfile!=='NODE_ACCOUNT_V4')fail('HISTORY_CONTACT_MIGRATION_REQUIRED');return {existing:true};}
    const row={alias,blob:await this.#crypt({id:peer,name:name.trim(),transportProfile:'NODE_ACCOUNT_V4',securityAlert:false,unread:false,last_ts:Date.now()})};
    try{await this.#commit(prior,{blind_peers:row});return {existing:false};}catch(e){this.#check();if(e.code!=='HISTORY_CONFLICT')throw e;}
   }
   fail('HISTORY_CONTENTION');
  }
  persistAuthenticated(data){return this.#persist(data,true);}
  persistOutgoing(data){return this.#persist(data,false);}
  async #persist({peer,operationId,plaintext,contentType,bindingDigest,generation,sessionId},inbound){
   this.#check();if(!valid(peer)||!valid(operationId)||contentType!=='text/plain;charset=utf-8'||typeof plaintext!=='string'||utf(plaintext).length>8192)fail('HISTORY_MESSAGE_SCHEMA');
   const context=inbound?{}:{bindingDigest,generation,sessionId};if(!inbound&&(!valid(bindingDigest)||!valid(sessionId)||!Number.isSafeInteger(generation)||generation<1))fail('HISTORY_MESSAGE_CONTEXT');
   const alias=await this.#alias(peer,'L1'),marker=await this.#alias(DOMAIN+(inbound?'':'OUTGOING|')+peer+'|'+operationId,'APP_V4'),digest=hex(new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',utf(JSON.stringify({peer,operationId,plaintext,contentType,...context}))))));
   for(let retry=0;retry<8;retry++){
    const prior=await this.#read({blind_secrets:alias,blind_peers:alias,pairing_material:marker}),receipt=await this.#plain(prior.pairing_material,DOMAIN+marker);
    if(receipt){
     if(receipt.type!=='ACCOUNT_HISTORY_RECEIPT_V4'||receipt.peer!==peer||receipt.operationId!==operationId||receipt.digest!==digest||!Number.isSafeInteger(receipt.seq)||receipt.seq<1)fail('HISTORY_OPERATION_CONFLICT');
     if(!inbound){
      const contact=await this.#plain(prior.blind_peers),messageAlias=await this.#alias(alias+receipt.seq,'L3'),read=await this.#read({blind_messages:messageAlias}),message=await this.#plain(read.blind_messages);
      if(!contact||contact.id!==peer||contact.transportProfile!=='NODE_ACCOUNT_V4'||contact.chatLock||!message||message.inbound!==false||message.wireId!==operationId||message.accountTransport!=='NODE_ACCOUNT_V4'||message.text!==plaintext||message.contentType!==contentType||!['PENDING','DELIVERED'].includes(message.transportState))fail('HISTORY_OUTGOING_REMOVED');
      prior.blind_messages=read.blind_messages;
      try{await this.#commit(prior,{blind_peers:prior.blind_peers,pairing_material:prior.pairing_material,blind_messages:read.blind_messages});}catch(error){this.#check();if(error.code==='HISTORY_CONFLICT')continue;throw error;}
     }
     return {persisted:true,duplicate:true,seq:receipt.seq};
    }
    const secrets=await this.#plain(prior.blind_secrets)||{msgCount:0},contact=await this.#plain(prior.blind_peers);
    // Existing legacy contacts require explicit authenticated migration first.
    if(!contact||contact.id!==peer||contact.transportProfile!=='NODE_ACCOUNT_V4')fail('HISTORY_CONTACT_MIGRATION_REQUIRED');
    if(contact.chatLock)fail('HISTORY_CHAT_LOCK_ADAPTER_REQUIRED');
    if(!Number.isSafeInteger(secrets.msgCount)||secrets.msgCount<0||secrets.msgCount>=Number.MAX_SAFE_INTEGER)fail('HISTORY_COUNTER_CORRUPT');
    const seq=secrets.msgCount+1,messageAlias=await this.#alias(alias+seq,'L3'),existing=await this.#read({blind_messages:messageAlias});if(existing.blind_messages)fail('HISTORY_SEQUENCE_COLLISION');prior.blind_messages=null;
    const ts=Date.now(),rows={blind_secrets:{alias,blob:await this.#crypt({...secrets,msgCount:seq})},blind_messages:{alias:messageAlias,blob:await this.#crypt({text:plaintext,ts,inbound,transportState:inbound?null:'PENDING',wireId:operationId,accountTransport:'NODE_ACCOUNT_V4',contentType})},blind_peers:{alias,blob:await this.#crypt({...contact,last_ts:ts,unread:inbound?true:contact.unread})},pairing_material:{alias:marker,blob:await this.#crypt({type:'ACCOUNT_HISTORY_RECEIPT_V4',peer,operationId,digest,seq,...context},DOMAIN+marker)}};
    try{await this.#commit(prior,rows);return {persisted:true,duplicate:false,seq};}catch(e){this.#check();if(e.code!=='HISTORY_CONFLICT')throw e;}
   }
   fail('HISTORY_CONTENTION');
  }
  async migrateOutgoingContext({peer,operationId,from,to,proof}){
   this.#check();const context=x=>x&&Object.keys(x).sort().join(',')==='bindingDigest,generation,sessionId'&&valid(x.bindingDigest)&&valid(x.sessionId)&&Number.isSafeInteger(x.generation)&&x.generation>0;
   if(!valid(peer)||!valid(operationId)||!context(from)||!context(to)||from.bindingDigest!==to.bindingDigest||from.generation!==to.generation||from.sessionId===to.sessionId||typeof this.#verifySuccessor!=='function')fail('HISTORY_SUCCESSOR_REQUIRED');
   from=Object.freeze({...from});to=Object.freeze({...to});const expected=Object.freeze({peer,operationId,from,to});
   const verify=async()=>{const result=await this.#wait(this.#verifySuccessor(proof,expected));if(result?.valid!==true||!Array.isArray(result.dependencies)||result.dependencies.length!==3||new Set(result.dependencies.map(x=>x.alias)).size!==3||result.dependencies.some(x=>!valid(x.alias)||typeof x.blob!=='string'||!x.blob.length||x.blob.length>1000000))fail('HISTORY_SUCCESSOR_REQUIRED');return result.dependencies.map(x=>Object.freeze({alias:x.alias,blob:x.blob}));};await verify();
   const alias=await this.#alias(peer,'L1'),marker=await this.#alias(DOMAIN+'OUTGOING|'+peer+'|'+operationId,'APP_V4');
   for(let retry=0;retry<8;retry++){
    const prior=await this.#read({blind_peers:alias,pairing_material:marker}),contact=await this.#plain(prior.blind_peers),receipt=await this.#plain(prior.pairing_material,DOMAIN+marker);
    if(!contact||contact.id!==peer||contact.transportProfile!=='NODE_ACCOUNT_V4'||contact.chatLock)fail('HISTORY_CONTACT_MIGRATION_REQUIRED');
    if(!receipt||receipt.type!=='ACCOUNT_HISTORY_RECEIPT_V4'||receipt.peer!==peer||receipt.operationId!==operationId||!Number.isSafeInteger(receipt.seq)||receipt.seq<1)fail('HISTORY_SUCCESSOR_CONTEXT');
    const matches=x=>receipt.bindingDigest===x.bindingDigest&&receipt.generation===x.generation&&receipt.sessionId===x.sessionId,duplicate=matches(to),lineage=receipt.contextLineage||[];
    if(!Array.isArray(lineage)||lineage.length>8||(!duplicate&&!matches(from))||(duplicate&&!lineage.some(x=>x.sessionId===from.sessionId&&x.bindingDigest===from.bindingDigest&&x.generation===from.generation)))fail('HISTORY_SUCCESSOR_CONTEXT');
    if(!duplicate&&lineage.length>=8)fail('HISTORY_SUCCESSOR_CAPACITY');
    const messageAlias=await this.#alias(alias+receipt.seq,'L3'),read=await this.#read({blind_messages:messageAlias}),message=await this.#plain(read.blind_messages);prior.blind_messages=read.blind_messages;
    if(!message||message.wireId!==operationId||message.inbound!==false||message.accountTransport!=='NODE_ACCOUNT_V4'||message.transportState!=='PENDING')fail('HISTORY_SUCCESSOR_MESSAGE');
    const digest=async ctx=>hex(new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',utf(JSON.stringify({peer,operationId,plaintext:message.text,contentType:message.contentType,...ctx}))))));
    if(receipt.digest!==await digest(duplicate?to:from))fail('HISTORY_SUCCESSOR_CONTEXT');await verify();
    const updated=duplicate?prior.pairing_material:{alias:marker,blob:await this.#crypt({...receipt,...to,digest:await digest(to),contextLineage:[...lineage,{...from,digest:receipt.digest}]},DOMAIN+marker)};
    const dependencies=await verify();if(dependencies.some(x=>x.alias===marker||x.alias===alias||x.alias===messageAlias))fail('HISTORY_SUCCESSOR_REQUIRED');try{await this.#commit(prior,{blind_peers:prior.blind_peers,pairing_material:updated,blind_messages:read.blind_messages},dependencies);return {persisted:true,duplicate,seq:receipt.seq};}catch(e){this.#check();if(e.code!=='HISTORY_CONFLICT')throw e;}
   }fail('HISTORY_CONTENTION');
  }
  async #deliveryStatus({peer,operationId,bindingDigest,generation,sessionId}){
   this.#check();if(!valid(peer)||!valid(operationId)||!valid(bindingDigest)||!valid(sessionId)||!Number.isSafeInteger(generation)||generation<1)fail('HISTORY_ACK_SCHEMA');
   const alias=await this.#alias(peer,'L1'),marker=await this.#alias(DOMAIN+'OUTGOING|'+peer+'|'+operationId,'APP_V4');
   for(let retry=0;retry<8;retry++){
    const prior=await this.#read({blind_peers:alias,pairing_material:marker}),contact=await this.#plain(prior.blind_peers),receipt=await this.#plain(prior.pairing_material,DOMAIN+marker);
    if(!contact||contact.id!==peer||contact.transportProfile!=='NODE_ACCOUNT_V4'||contact.chatLock)fail('HISTORY_CONTACT_MIGRATION_REQUIRED');
    if(!receipt||receipt.type!=='ACCOUNT_HISTORY_RECEIPT_V4'||receipt.peer!==peer||receipt.operationId!==operationId||receipt.bindingDigest!==bindingDigest||receipt.generation!==generation||receipt.sessionId!==sessionId||!valid(receipt.digest)||!Number.isSafeInteger(receipt.seq)||receipt.seq<1)fail('HISTORY_ACK_CONTEXT');
    const messageAlias=await this.#alias(alias+receipt.seq,'L3'),read=await this.#read({blind_messages:messageAlias}),message=await this.#plain(read.blind_messages);prior.blind_messages=read.blind_messages;
    if(!message||message.wireId!==operationId||message.inbound!==false||message.accountTransport!=='NODE_ACCOUNT_V4'||!['PENDING','DELIVERED'].includes(message.transportState))fail('HISTORY_ACK_MESSAGE');
    const digest=hex(new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',utf(JSON.stringify({peer,operationId,plaintext:message.text,contentType:message.contentType,bindingDigest,generation,sessionId}))))));if(receipt.digest!==digest)fail('HISTORY_ACK_CONTEXT');
    try{await this.#commit(prior,{blind_peers:prior.blind_peers,pairing_material:prior.pairing_material,blind_messages:read.blind_messages});return message.transportState==='DELIVERED';}catch(e){this.#check();if(e.code!=='HISTORY_CONFLICT')throw e;}
   }fail('HISTORY_CONTENTION');
  }
  async outgoingDeliveryStatus(value){const expected=Object.freeze({peer:value.peer,operationId:value.operationId,bindingDigest:value.bindingDigest,generation:value.generation,sessionId:value.sessionId});if(!await this.#deliveryStatus(expected))return null;const handle=Object.freeze({});this.#deliveryProofs.set(handle,expected);return handle;}
  async verifyOutgoingDeliveryStatus(handle,expected){try{this.#check();const recorded=this.#deliveryProofs.get(handle);if(!recorded||Object.keys(recorded).some(k=>recorded[k]!==expected?.[k]))return false;return await this.#deliveryStatus(recorded);}catch(_){return false;}}
  // Trusted AppCipher callback only, after authenticated recipient ACK verification.
  // A caller-provided delivery boolean is deliberately not part of this API.
  async ackOutgoing({peer,operationId,bindingDigest,generation,sessionId}){
   this.#check();if(!valid(peer)||!valid(operationId)||!valid(bindingDigest)||!valid(sessionId)||!Number.isSafeInteger(generation)||generation<1)fail('HISTORY_ACK_SCHEMA');
   const alias=await this.#alias(peer,'L1'),marker=await this.#alias(DOMAIN+'OUTGOING|'+peer+'|'+operationId,'APP_V4');
   for(let retry=0;retry<8;retry++){
    const prior=await this.#read({blind_peers:alias,pairing_material:marker}),contact=await this.#plain(prior.blind_peers),receipt=await this.#plain(prior.pairing_material,DOMAIN+marker);
    if(!contact||contact.id!==peer||contact.transportProfile!=='NODE_ACCOUNT_V4')fail('HISTORY_CONTACT_MIGRATION_REQUIRED');
    if(contact.chatLock)fail('HISTORY_CHAT_LOCK_ADAPTER_REQUIRED');
    if(!receipt||receipt.type!=='ACCOUNT_HISTORY_RECEIPT_V4'||receipt.peer!==peer||receipt.operationId!==operationId||receipt.bindingDigest!==bindingDigest||receipt.generation!==generation||receipt.sessionId!==sessionId||!valid(receipt.digest)||!Number.isSafeInteger(receipt.seq)||receipt.seq<1)fail('HISTORY_ACK_CONTEXT');
    const messageAlias=await this.#alias(alias+receipt.seq,'L3'),read=await this.#read({blind_messages:messageAlias}),message=await this.#plain(read.blind_messages);prior.blind_messages=read.blind_messages;
    if(!message||message.wireId!==operationId||message.inbound!==false||message.accountTransport!=='NODE_ACCOUNT_V4'||!['PENDING','DELIVERED'].includes(message.transportState))fail('HISTORY_ACK_MESSAGE');
    const digest=hex(new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',utf(JSON.stringify({peer,operationId,plaintext:message.text,contentType:message.contentType,bindingDigest,generation,sessionId}))))));if(digest!==receipt.digest)fail('HISTORY_ACK_CONTEXT');
    // CAS all dependencies even for a repeated ACK: deletion or replacement wins.
    const rows={blind_peers:prior.blind_peers,pairing_material:prior.pairing_material,blind_messages:message.transportState==='DELIVERED'?read.blind_messages:{alias:messageAlias,blob:await this.#crypt({...message,transportState:'DELIVERED'})}};
    try{await this.#commit(prior,rows);return {persisted:true,duplicate:message.transportState==='DELIVERED'};}catch(e){this.#check();if(e.code!=='HISTORY_CONFLICT')throw e;}
   }
   fail('HISTORY_CONTENTION');
  }
  close(){if(this.#closed)return;this.#closed=true;this.#deliveryProofs=new WeakMap();this.#salt.fill(0);for(const tx of this.#txs)try{tx.abort();}catch(_){}this.#txs.clear();this.#session.signal.removeEventListener('abort',this.#abort);}
 }
 g.DmashAccountAuthenticatedHistoryV4=AccountAuthenticatedHistoryV4;if(typeof module!=='undefined')module.exports=AccountAuthenticatedHistoryV4;
})(globalThis);
