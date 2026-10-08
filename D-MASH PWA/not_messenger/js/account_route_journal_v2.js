'use strict';
(function(global){
 const STORE='pairing_material',STATE='ACCOUNT_COMMITTED_BLOCKED',MAX_PLAIN=65536;
 const text=value=>new TextEncoder().encode(value);
 const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const key=value=>{if(typeof value!=='string'||!/^[0-9a-f]{64}$/.test(value))fail('ENCODING');return value;};
 const b64=bytes=>btoa(String.fromCharCode(...bytes));
 const TUPLE=['ownerSlot','routeAuthorityDigest','routeId','migrationId','bindingDigest','generation','preparationDigest','accountPublic'];
 function tuple(value){
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!TUPLE.includes(k)&&k!=='state')||TUPLE.some(k=>!Object.hasOwn(value,k)))fail('PREPARATION_TUPLE');
  if(Object.hasOwn(value,'state')&&!['NODE_PREPARED','ACTIVE'].includes(value.state))fail('PREPARATION_STATE');
  const result={};for(const name of TUPLE){const descriptor=Object.getOwnPropertyDescriptor(value,name);if(!descriptor||!Object.hasOwn(descriptor,'value'))fail('PREPARATION_TUPLE');result[name]=value[name];if(name==='generation'){if(!Number.isSafeInteger(result[name])||result[name]<1)fail('PREPARATION_TUPLE');}else key(result[name]);}
  return Object.freeze(result);
 }
 const sameTuple=(a,b)=>JSON.stringify(a??null)===JSON.stringify(b??null);
 class AccountRouteJournalV2{
  #verifyPreparation;
  #opened=false;
  #accountSignal;
  #closeObservers=new Set();
  #commitReceipts=new WeakMap();
  static async open(options){
   const journal=new AccountRouteJournalV2(options);
   try{journal.aliasKey=await journal.wait(journal.crypto.subtle.importKey('raw',journal.s.saltCopy,{name:'HMAC',hash:'SHA-256'},false,['sign']));journal.#opened=true;return journal;}
   catch(error){journal.close();throw error;}
  }
  static createReceiptRouter(deviceRoot){
   if(!deviceRoot?.state||typeof deviceRoot.onLock!=='function')fail('ROOT_REQUIRED');
   const rootState=deviceRoot.state,entries=new Map(),caps=new WeakMap();let closed=false,offRoot;
   const current=()=>!closed&&deviceRoot.state===rootState&&!!rootState;
   const remove=entry=>{if(entries.get(entry.journal)!==entry)return false;entries.delete(entry.journal);caps.delete(entry.cap);entry.journal.#closeObservers.delete(entry.cleanup);entry.signal.removeEventListener('abort',entry.cleanup);return true;};
   const close=()=>{if(closed)return;closed=true;for(const entry of [...entries.values()])remove(entry);offRoot?.();};
   offRoot=deviceRoot.onLock(close);
   return Object.freeze({
    register(journal){
     if(!current())fail('ROOT_CHANGED');
     if(!journal||typeof journal!=='object'||!(#opened in journal)||!journal.#opened)fail('JOURNAL_BRAND');
     trustedCheck.call(journal);if(journal.root!==deviceRoot||journal.s.root!==rootState)fail('ROOT_MISMATCH');
     if(entries.has(journal))return entries.get(journal).cap;if(entries.size>=32)fail('JOURNAL_QUOTA');
     const cap=Object.freeze({}),entry={journal,cap,signal:journal.#accountSignal,cleanup:null};entry.cleanup=()=>remove(entry);
     entries.set(journal,entry);caps.set(cap,entry);journal.#closeObservers.add(entry.cleanup);entry.signal.addEventListener('abort',entry.cleanup,{once:true});return cap;
    },
    unregister(cap){const entry=caps.get(cap);return entry?remove(entry):false;},
    async verify(receipt,expected){
     if(!current())return false;
     for(const entry of [...entries.values()]){
      if(entries.get(entry.journal)!==entry||entry.signal.aborted)continue;
      try{const accepted=await trustedVerify.call(entry.journal,receipt,expected);if(accepted&&current()&&entries.get(entry.journal)===entry&&!entry.signal.aborted)return true;}catch(_){/* One unavailable journal cannot block another Account. */}
     }
     return false;
    },close
   });
  }
  constructor({storage,core,deviceRoot,accountSignal,bindingCodec,verifyPreparation=null,crypto=global.crypto}){
   if(!storage?.db||!storage.masterKey||!core?.keys?.sign||!core.blindSalt||!core._accountBootAttempt||typeof core.activeIdentity!=='string'||!core.activeIdentity||!deviceRoot?.state||typeof deviceRoot.onLock!=='function'||!accountSignal||typeof accountSignal.addEventListener!=='function'||accountSignal.aborted||!bindingCodec?.prepare)fail('SESSION_REQUIRED');
   if(storage.masterKey.algorithm?.name!=='AES-GCM'||!storage.db.objectStoreNames.contains(STORE)||!(core.blindSalt instanceof Uint8Array)||core.blindSalt.length<32)fail('VAULT_CONTEXT');
   if(verifyPreparation!==null&&typeof verifyPreparation!=='function')fail('PREPARATION_VERIFIER');this.#verifyPreparation=verifyPreparation;
   this.storage=storage;this.core=core;this.root=deviceRoot;this.#accountSignal=accountSignal;this.codec=bindingCodec;this.crypto=crypto;
   this.closed=false;this.transactions=new Set();this.handles=new WeakMap();
   this.s=Object.freeze({db:storage.db,key:storage.masterKey,keys:core.keys,sign:core.keys.sign,identity:core.activeIdentity,generation:core._accountBootAttempt,root:deviceRoot.state,salt:core.blindSalt,saltCopy:core.blindSalt.slice(),account:key(hex(core.keys.sign.publicKey))});
   this.check();this.abort=()=>this.close();accountSignal.addEventListener('abort',this.abort,{once:true});this.offRoot=deviceRoot.onLock(this.abort);
  }
  check(){
   const s=this.s,c=this.core;
   if(this.closed||this.#accountSignal.aborted||c._accountTransitioning||this.storage.db!==s.db||this.storage.masterKey!==s.key||c.keys!==s.keys||c.keys.sign!==s.sign||c.activeIdentity!==s.identity||c._accountBootAttempt!==s.generation||this.root.state!==s.root||!this.root.state||c.blindSalt!==s.salt||s.salt.length!==s.saltCopy.length||s.salt.some((v,i)=>v!==s.saltCopy[i])||hex(s.sign.publicKey)!==s.account)fail('SESSION_CHANGED');
  }
  async wait(promise){this.check();const result=await promise;this.check();return result;}
  close(){if(this.closed)return;this.closed=true;for(const tx of this.transactions){try{tx.abort();}catch(_){}}this.transactions.clear();this.#accountSignal.removeEventListener('abort',this.abort);this.offRoot?.();this.s.saltCopy.fill(0);this.aliasKey=null;this.#commitReceipts=new WeakMap();for(const observer of [...this.#closeObservers])observer();this.#closeObservers.clear();}
  async location(kind,id){
   this.check();const alias=hex(new Uint8Array(await this.wait(this.crypto.subtle.sign('HMAC',this.aliasKey,text('D-MASH|ACCOUNT-ROUTE-JOURNAL|V2\0'+this.s.account+'\0'+kind+'\0'+id)))));
   return Object.freeze({kind,alias});
  }
  async encrypt(location,payload){
   this.check();const plain=text(JSON.stringify({schema:2,kind:location.kind,account:this.s.account,alias:location.alias,payload}));if(plain.length>MAX_PLAIN)fail('RECORD_SIZE');
   const iv=this.crypto.getRandomValues(new Uint8Array(12));
   try{const cipher=new Uint8Array(await this.wait(this.crypto.subtle.encrypt({name:'AES-GCM',iv},this.s.key,plain))),packed=new Uint8Array(12+cipher.length);packed.set(iv);packed.set(cipher,12);return {alias:location.alias,blob:b64(packed)};}finally{plain.fill(0);}
  }
  async decrypt(location,row){
   this.check();if(row===null)return null;
   if(row.alias!==location.alias||typeof row.blob!=='string'||row.blob.length>Math.ceil((MAX_PLAIN+28)/3)*4)fail('CORRUPT_RECORD');
   let raw,plain;
   try{raw=Uint8Array.from(atob(row.blob),c=>c.charCodeAt(0));if(raw.length<28||b64(raw)!==row.blob)fail('CORRUPT_RECORD');
    plain=new Uint8Array(await this.wait(this.crypto.subtle.decrypt({name:'AES-GCM',iv:raw.subarray(0,12)},this.s.key,raw.subarray(12))));
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));
    if(Object.keys(value).sort().join(',')!=='account,alias,kind,payload,schema'||value.schema!==2||value.account!==this.s.account||value.alias!==location.alias||value.kind!==location.kind)fail('CORRUPT_RECORD');
    return value.payload;
   }catch(error){this.check();fail('CORRUPT_RECORD');}finally{plain?.fill(0);}
  }
  transaction(locations,expected=null,writes=[]){
   this.check();return new Promise((resolve,reject)=>{
    let tx,problem=null;const rows=new Map();
    try{tx=this.s.db.transaction(STORE,expected?'readwrite':'readonly');this.transactions.add(tx);}catch(error){reject(error);return;}
    const stop=error=>{problem=error;try{tx.abort();}catch(_){reject(error);}};
    tx.onabort=()=>{this.transactions.delete(tx);reject(problem||tx.error||Object.assign(new Error('TX_ABORTED'),{code:'TX_ABORTED'}));};
    tx.onerror=()=>{};
    tx.oncomplete=()=>{this.transactions.delete(tx);try{this.check();resolve(rows);}catch(error){reject(error);}};
    const store=tx.objectStore(STORE);let remaining=locations.length;
    if(!remaining){stop(Object.assign(new Error('EMPTY_TRANSACTION'),{code:'EMPTY_TRANSACTION'}));return;}
    for(const location of locations){
     const request=store.get(location.alias);
     request.onsuccess=()=>{try{
      this.check();const row=request.result??null;rows.set(location.alias,row);
      if(expected){const prior=expected.get(location.alias)??null;if((prior?.blob??null)!==(row?.blob??null))fail('CAS_CONFLICT');}
      if(--remaining===0&&expected){this.check();for(const rowToWrite of writes){this.check();store.put(rowToWrite);}}
     }catch(error){stop(error);}};
    }
   });
  }
  async read(locations){
   const rows=await this.wait(this.transaction(locations)),values=new Map();
   for(const location of locations)values.set(location.alias,await this.wait(this.decrypt(location,rows.get(location.alias))));
   return {rows,values,get:location=>values.get(location.alias)};
  }
  pointerSnapshot(pointer,peer){
   if(pointer===null)return null;
   if(pointer.state!==STATE||pointer.peer!==peer||!Number.isSafeInteger(pointer.generation)||pointer.generation<1)fail('CORRUPT_POINTER');
   key(pointer.digest);for(const field of ['inbound','outbound','journal'])key(pointer[field]);
   return {generation:pointer.generation,binding_digest:pointer.digest,participants:[this.s.account,peer]};
  }
  async stage(bundles,peer){
   this.check();key(peer);if(peer===this.s.account)fail('SELF_PAIRING');
   if(!Array.isArray(bundles)||bundles.length!==2||bundles.some(v=>typeof v!=='string'||v.length>12288))fail('BUNDLES');
   const copied=bundles.slice(),active=await this.wait(this.location('active',peer)),saved=await this.wait(this.read([active]));
   const candidate=await this.wait(this.codec.prepare(copied,{expectedParticipants:[this.s.account,peer],committed:this.pointerSnapshot(saved.get(active),peer)}));
   const parsed=copied.map(v=>JSON.parse(v)),local=parsed.find(v=>v.account_keys.signing===this.s.account),remote=parsed.find(v=>v.account_keys.signing===peer);
   const phase=candidate.binding.participants[0].account===this.s.account?'ACCEPT':'CONFIRM';
   const handle=Object.freeze({digest:candidate.digest,generation:candidate.binding.generation,peer,phase,state:'STAGED'});
   this.handles.set(handle,{bundles:copied,local,remote,peer,phase,digest:candidate.digest,generation:candidate.binding.generation,active});return handle;
  }
  handle(value){this.check();const data=this.handles.get(value);if(!data)fail('UNKNOWN_STAGE');return data;}
  async locations(data,full=false){
   const rows={active:data.active,signature:await this.wait(this.location('signature',data.peer+':'+data.generation)),offers:[]};
   for(const bundle of [data.local,data.remote])rows.offers.push(await this.wait(this.location('offer',bundle.account_keys.signing+':'+bundle.pairing_id)));
   if(full){rows.inbound=await this.wait(this.location('inbound',data.local.inbound_certificate.route_id));rows.outbound=await this.wait(this.location('outbound',data.peer));rows.journal=await this.wait(this.location('journal',data.digest));}
   rows.all=Object.entries(rows).filter(([k])=>k!=='offers').map(([,v])=>v).concat(rows.offers);return rows;
  }
  checkOfferPins(data,locations,saved,required=false){
   for(const location of locations.offers){const pin=saved.get(location);if(pin&&(pin.digest!==data.digest||pin.peer!==data.peer))fail('OFFER_CONSUMED');if(required&&!pin)fail('OFFER_NOT_RESERVED');}
  }
  async refreshed(data,locations,saved){
   const candidate=await this.wait(this.codec.prepare(data.bundles,{expectedParticipants:[this.s.account,data.peer],committed:this.pointerSnapshot(saved.get(locations.active),data.peer)}));
   if(candidate.digest!==data.digest)fail('BINDING_CHANGED');return candidate;
  }
  async reserveAndSign(handle,acceptReceipt){
   const data=this.handle(handle),locations=await this.wait(this.locations(data)),saved=await this.wait(this.read(locations.all)),candidate=await this.wait(this.refreshed(data,locations,saved));
   this.checkOfferPins(data,locations,saved);const prior=saved.get(locations.signature);
   if(prior&&(prior.digest!==data.digest||prior.phase!==data.phase))fail('SIGNING_CONFLICT');
   if(prior){this.codec.verifyReceipt(candidate,prior.receipt,data.phase);this.checkOfferPins(data,locations,saved,true);return prior.receipt;}
   this.check();const receipt=this.codec.signReceipt(candidate,data.phase,this.s.sign.secretKey,acceptReceipt),writes=[];
   writes.push(await this.wait(this.encrypt(locations.signature,{digest:data.digest,phase:data.phase,receipt})));
   for(let i=0;i<locations.offers.length;i++)writes.push(await this.wait(this.encrypt(locations.offers[i],{digest:data.digest,peer:data.peer,owner:[data.local,data.remote][i].account_keys.signing,pairing_id:[data.local,data.remote][i].pairing_id})));
   await this.wait(this.transaction(locations.all,saved.rows,writes));return receipt;
  }
  async checkedPreparation(data,preparation){
   if(!this.#verifyPreparation)fail('NODE_PREPARATION_UNIMPLEMENTED');
   const expected={accountPublic:this.s.account,routeId:data.local.inbound_certificate.route_id,bindingDigest:data.digest,generation:data.generation};
   const verified=tuple(await this.wait(this.#verifyPreparation(preparation,Object.freeze(expected))));
   if(Object.entries(expected).some(([name,value])=>verified[name]!==value))fail('PREPARATION_CONTEXT');
   return verified;
  }
  async #mintReceipt(data,preparation,verified){
   const current=await this.wait(this.checkedPreparation(data,preparation));if(!sameTuple(current,verified))fail('PREPARATION_CHANGED');
   const receipt=Object.freeze({});this.#commitReceipts.set(receipt,Object.freeze({data,preparation,tuple:verified}));return receipt;
  }
  async verifyCommitReceipt(receipt,expected){
   try{
    this.check();const proof=this.#commitReceipts.get(receipt);if(!proof||!sameTuple(proof.tuple,tuple(expected)))return false;
    const preparation=await this.wait(this.checkedPreparation(proof.data,proof.preparation));if(!sameTuple(preparation,proof.tuple))return false;
    const committed=await this.wait(this.readCommitted(proof.data.peer));
    if(!committed||committed.digest!==proof.data.digest||committed.generation!==proof.data.generation||!sameTuple(committed.preparation,proof.tuple))return false;
    const latest=await this.wait(this.checkedPreparation(proof.data,proof.preparation));return sameTuple(latest,proof.tuple);
   }catch(_){return false;}
  }
  async commit(handle,receipts,options={}){
   const data=this.handle(handle),locations=await this.wait(this.locations(data,true)),saved=await this.wait(this.read(locations.all)),candidate=await this.wait(this.refreshed(data,locations,saved));
   const verified=this.codec.verifyReceipts(candidate,receipts,{committed:this.pointerSnapshot(saved.get(locations.active),data.peer)});this.check();
   this.checkOfferPins(data,locations,saved,true);const reserved=saved.get(locations.signature);
   if(!reserved||reserved.digest!==data.digest||reserved.phase!==data.phase||reserved.receipt!==verified.receipts[data.phase==='ACCEPT'?0:1])fail('SIGNATURE_NOT_RESERVED');
   const hasPreparation=Object.hasOwn(options,'preparation'),prepared=hasPreparation?await this.wait(this.checkedPreparation(data,options.preparation)):null;
   const oldInbound=saved.get(locations.inbound);if(oldInbound&&oldInbound.peer!==data.peer)fail('INBOUND_OWNERSHIP');
   const oldJournal=saved.get(locations.journal);
   if(verified.status==='IDEMPOTENT_REPLAY'){
    const current=await this.wait(this.readCommitted(data.peer));if(current?.digest!==data.digest)fail('CORRUPT_COMMIT');
    if(oldJournal&&JSON.stringify(oldJournal.receipts)!==JSON.stringify(verified.receipts))fail('RECEIPT_REPLAY_MISMATCH');
    if(!hasPreparation)return {...current,replayed:true};
    if(current.preparation){
     if(!sameTuple(current.preparation,prepared))fail('PREPARATION_CONFLICT');
     // Re-establish a CAS barrier over the durable four-row commit before reminting.
     await this.wait(this.transaction(locations.all,saved.rows,[]));
     return Object.freeze({...current,replayed:true,commitReceipt:await this.wait(this.#mintReceipt(data,options.preparation,prepared))});
    }
    // A historical BLOCKED snapshot needs a new proof-bound four-row transaction.
   }else if(oldJournal)fail('JOURNAL_CONFLICT');
   const common={peer:data.peer,generation:data.generation,digest:data.digest,state:STATE,preparation:prepared};
   const inbound={...common,certificate:data.local.inbound_certificate},outbound={...common,certificate:data.remote.inbound_certificate,localRouteId:data.local.inbound_certificate.route_id};
   const pointer={...common,inbound:locations.inbound.alias,outbound:locations.outbound.alias,journal:locations.journal.alias};
   const journal={...common,bundles:data.bundles,receipts:verified.receipts,inbound,outbound,previous:oldJournal?oldJournal.previous:saved.get(locations.active)};
   const writes=[];for(const [location,value]of [[locations.inbound,inbound],[locations.outbound,outbound],[locations.journal,journal],[locations.active,pointer]])writes.push(await this.wait(this.encrypt(location,value)));
   if(hasPreparation&&!sameTuple(await this.wait(this.checkedPreparation(data,options.preparation)),prepared))fail('PREPARATION_CHANGED');
   await this.wait(this.transaction(locations.all,saved.rows,writes));
   const commitReceipt=hasPreparation?await this.wait(this.#mintReceipt(data,options.preparation,prepared)):null;
   return Object.freeze({...common,ready:false,replayed:false,...(commitReceipt?{commitReceipt}:{})});
  }
  async readCommitted(peer){
   this.check();key(peer);const active=await this.wait(this.location('active',peer)),first=await this.wait(this.read([active])),pointer=first.get(active);
   if(pointer===null)return null;this.pointerSnapshot(pointer,peer);
   const locations=[active,{kind:'inbound',alias:pointer.inbound},{kind:'outbound',alias:pointer.outbound},{kind:'journal',alias:pointer.journal}],saved=await this.wait(this.read(locations));
   if(saved.rows.get(active.alias)?.blob!==first.rows.get(active.alias)?.blob)fail('CAS_CONFLICT');
   for(const location of locations){const value=saved.get(location);if(!value||value.digest!==pointer.digest||value.generation!==pointer.generation||value.peer!==peer||value.state!==STATE)fail('CORRUPT_COMMIT');}
   const preparation=pointer.preparation?tuple(pointer.preparation):null;
   for(const location of locations)if(!sameTuple(saved.get(location).preparation?tuple(saved.get(location).preparation):null,preparation))fail('CORRUPT_COMMIT');
   const journal=saved.get(locations[3]);
   if(preparation&&(preparation.bindingDigest!==pointer.digest||preparation.generation!==pointer.generation||preparation.accountPublic!==this.s.account||preparation.routeId!==journal.inbound?.certificate?.route_id))fail('CORRUPT_COMMIT');
   if(JSON.stringify(saved.get(locations[1]))!==JSON.stringify(journal.inbound)||JSON.stringify(saved.get(locations[2]))!==JSON.stringify(journal.outbound))fail('CORRUPT_COMMIT');
   return Object.freeze({peer,generation:pointer.generation,digest:pointer.digest,state:STATE,ready:false,replayed:false,preparation});
  }
  activate(){fail('NODE_ACTIVATION_UNIMPLEMENTED');}
 }
 const trustedVerify=AccountRouteJournalV2.prototype.verifyCommitReceipt,trustedCheck=AccountRouteJournalV2.prototype.check;
 global.DmashAccountRouteJournalV2=AccountRouteJournalV2;if(typeof module!=='undefined')module.exports=AccountRouteJournalV2;
})(typeof window!=='undefined'?window:globalThis);
