'use strict';
(function(global){
 const text=value=>new TextEncoder().encode(value);
 const token=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 const slot=value=>typeof value==='string'&&value.length>0&&value.length<=512;
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const bucket=key=>key==='owner'||key.startsWith('binding:')?'bindings':'records';
 const size=row=>{
  const bytes=row?.ciphertext?.byteLength;
  if(!Number.isSafeInteger(bytes)||bytes<16)return 65536+128;
  return bytes+128;
 };
 class InboxStore{
  constructor({databaseName='dmash_node_inbox_v4',maxRecords=4096,maxBytes=32*1024*1024,isCurrent=()=>true}={}){
   if(!Number.isInteger(maxRecords)||maxRecords<1||maxRecords>16384||!Number.isInteger(maxBytes)||maxBytes<1024||maxBytes>64*1024*1024)throw Error('Invalid Inbox quota');
   Object.assign(this,{databaseName,maxRecords,maxBytes,isCurrent,closed:false,transactions:new Set()});
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Node Inbox closed');}
  async open(){
   this.check();
   this.db=await new Promise((resolve,reject)=>{
    const request=global.indexedDB.open(this.databaseName,1);
    request.onupgradeneeded=()=>{request.result.createObjectStore('records',{keyPath:'key'});request.result.createObjectStore('usage',{keyPath:'key'});request.result.createObjectStore('bindings',{keyPath:'key'});};
    request.onerror=request.onblocked=()=>reject(Error('Node Inbox unavailable'));
    request.onsuccess=()=>{try{this.check();resolve(request.result);}catch(error){request.result.close();reject(error);}};
   });
   this.db.onversionchange=()=>this.close();
   return this;
  }
  async reconcile(){
   for(const kind of ['records','bindings'])await this.transaction('readwrite',(store,done,fail,usage)=>{store.getAll().onsuccess=e=>{
    try{const rows=e.target.result;usage.put({key:kind,count:rows.length,bytes:rows.reduce((n,row)=>n+size(row),0)});done(true);}catch(error){fail(error);}
   };},kind);
  }
  transaction(mode,body,kind='records'){
   this.check();return new Promise((resolve,reject)=>{
    const tx=this.db.transaction(['records','bindings','usage'],mode);this.transactions.add(tx);let result,error;
    tx.oncomplete=()=>{this.transactions.delete(tx);try{this.check();resolve(result);}catch(e){reject(e);}};
    tx.onabort=tx.onerror=()=>{this.transactions.delete(tx);reject(error||Error('Node Inbox transaction failed'));};
    try{body(tx.objectStore(kind),value=>{result=value;},failure=>{error=failure;tx.abort();},tx.objectStore('usage'));}catch(e){error=e;tx.abort();}
   });
  }
  read(key){return this.transaction('readonly',(store,done)=>{store.get(key).onsuccess=e=>done(e.target.result||null);},bucket(key));}
  all(){return this.transaction('readonly',(store,done)=>{store.getAll().onsuccess=e=>done(e.target.result);});}
  allBindings(){return this.transaction('readonly',(store,done)=>{store.getAll().onsuccess=e=>done(e.target.result);},'bindings');}
  cas(key,revision,row){
   const kind=bucket(key);
   return this.transaction('readwrite',(store,done,fail,usage)=>{
    store.get(key).onsuccess=e=>{
     const current=e.target.result;
     if((current?.revision??null)!==revision){done(false);return;}
     usage.get(kind).onsuccess=event=>{
      try{
       this.check();const totals=event.target.result;
       if(!Number.isSafeInteger(totals?.count)||!Number.isSafeInteger(totals?.bytes))throw Error('Inbox quota metadata missing');
       if(key==='owner'&&!current&&totals.count!==0)throw Error('Inbox owner missing');
       const count=totals.count+(row===null?-1:current?0:1);
       const bytes=totals.bytes-(current?size(current):0)+(row===null?0:size(row));
       if(row===null&&!current){done(false);return;}
       if(row!==null&&((bytes>(kind==='bindings'?256*1024:this.maxBytes)&&bytes>totals.bytes)||(count>(kind==='bindings'?33:this.maxRecords)&&count>totals.count)))throw Error('Node Inbox quota reached');
       if(row===null)store.delete(key);else store.put({...row,key,revision:(revision??0)+1});
       usage.put({key:kind,count,bytes});done(true);
      }catch(error){fail(error);}
     };
    };
   },kind);
  }
  promote(sourceKey,sourceRevision,targetKey,targetRevision,row){
   if(!token(sourceKey)||!token(targetKey)||sourceKey===targetKey)throw Error('Invalid Inbox promotion');
   return this.transaction('readwrite',(store,done,fail,usage)=>{
    store.get(sourceKey).onsuccess=sourceEvent=>{
     const source=sourceEvent.target.result;
     if(!source||source.revision!==sourceRevision){done(false);return;}
     store.get(targetKey).onsuccess=targetEvent=>{
      const target=targetEvent.target.result;
      if((target?.revision??null)!==targetRevision){done(false);return;}
      usage.get('records').onsuccess=event=>{
       try{
        this.check();const totals=event.target.result;
        const next=row||target;if(!next)throw Error('Missing promotion target');
        const count=totals.count-(target?1:0),bytes=totals.bytes-size(source)-(target?size(target):0)+size(next);
        if((bytes>this.maxBytes&&bytes>totals.bytes)||(count>this.maxRecords&&count>totals.count))throw Error('Inbox quota reached');
        if(row)store.put({...row,key:targetKey,revision:(targetRevision??0)+1});
        store.delete(sourceKey);usage.put({key:'records',count,bytes});done(true);
       }catch(error){fail(error);}
      };
     };
    };
   });
  }
  close(){this.closed=true;for(const tx of this.transactions)try{tx.abort();}catch(_){}this.transactions.clear();this.db?.close();this.db=null;}
 }
 class NodeInboxV4{
  static async open(storageKey,localId,{store,isCurrent=()=>true,clock=()=>Date.now(),...options}={}){
   if(!(storageKey instanceof Uint8Array)||storageKey.length!==32||!token(localId))throw Error('Invalid Inbox material');
   const inbox=new NodeInboxV4();Object.assign(inbox,{localId,isCurrent,clock,closed:false});
   inbox.store=store||new InboxStore({...options,isCurrent:()=>!inbox.closed&&isCurrent()});
   try{
    const base=await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']);
    for(const [name,algorithm,usages] of [['aliasKey',{name:'HMAC',hash:'SHA-256'},['sign']],['encryptionKey','AES-GCM',['encrypt','decrypt']]]){
     const material=new Uint8Array(await crypto.subtle.sign('HMAC',base,text('D-MASH|NODE-INBOX|V4|'+name)));
     try{inbox[name]=await crypto.subtle.importKey('raw',material,algorithm,false,usages);}finally{material.fill(0);}
    }
    inbox.check();await inbox.store.open();
    for(let attempt=0;attempt<8;attempt++){
     const row=await inbox.store.read('owner');
     if(row){const value=await inbox.decrypt(row);if(value.kind!=='owner'||value.version!==1||value.localId!==localId)throw Error('Node Inbox owner changed');await inbox.store.reconcile?.();return inbox;}
     if((await inbox.store.all()).length)throw Error('Node Inbox owner missing');
     await inbox.store.reconcile?.();
     if(await inbox.store.cas('owner',null,await inbox.encrypt('owner',{kind:'owner',version:1,localId})))return inbox;
    }
    throw Error('Node Inbox contention');
   }catch(error){inbox.close();throw error;}
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Node Inbox closed');}
  async alias(label){this.check();const result=hex(new Uint8Array(await crypto.subtle.sign('HMAC',this.aliasKey,text(label))));this.check();return result;}
  async encrypt(key,value){
   this.check();const iv=crypto.getRandomValues(new Uint8Array(12)),bytes=text(JSON.stringify(value));
   try{const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text('D-MASH|NODE-INBOX|V4|'+this.localId+'|'+key)},this.encryptionKey,bytes);this.check();return {iv,ciphertext};}
   finally{bytes.fill(0);}
  }
  async decrypt(row){
   this.check();let bytes;
   if(!row||!(row.key==='owner'||token(row.key)||(typeof row.key==='string'&&row.key.startsWith('binding:')&&token(row.key.slice(8))))||row.iv?.byteLength!==12||!Number.isSafeInteger(row.ciphertext?.byteLength)||row.ciphertext.byteLength<16||row.ciphertext.byteLength>65536||!Number.isSafeInteger(row.revision)||row.revision<1)throw Error('Invalid Inbox row');
   try{bytes=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:row.iv,additionalData:text('D-MASH|NODE-INBOX|V4|'+this.localId+'|'+row.key)},this.encryptionKey,row.ciphertext));this.check();return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
   finally{bytes?.fill(0);}
  }
  async receive(routeId,accountSlot,blob,privateKeys){
   this.check();if(!token(routeId)||!slot(accountSlot)||typeof blob!=='string'||blob.length<96||blob.length>21848)throw Error('Invalid local delivery');
   let raw;try{raw=atob(blob);}catch(_){throw Error('Invalid local delivery encoding');}
   if(raw.length<72||raw.length>16384||btoa(raw)!==blob)throw Error('Invalid local delivery encoding');
   const opened=global.DmashRecipientPayloadV4.openPayload(privateKeys,blob);
   if(opened.status==='discard')return {status:'discard'};
   const deferred=opened.status==='deferred';
   const id=deferred?hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(blob)))):opened.packet_id;
   const key=await this.alias((deferred?'deferred|':'packet|')+routeId+'|'+id);
   const value={kind:deferred?'deferred':'pending',routeId,accountSlot,receivedAt:this.clock(),
    ...(deferred?{blob}:{packetId:id,payload:opened.payload})};
   const inserted=await this.store.cas(key,null,await this.encrypt(key,value));this.check();
   return {status:deferred?'deferred':'stored',inserted};
  }
  async list(accountSlot,limit=32){
   this.check();if(!slot(accountSlot)||!Number.isInteger(limit)||limit<1||limit>128)throw Error('Invalid Inbox selector');
   const records=[];let unreadable=0,deferred=0;
   for(const row of await this.store.all()){
    if(row.key==='owner')continue;
    try{
     const value=await this.decrypt(row);
     if(value.accountSlot===accountSlot){if(value.kind==='pending')records.push({handle:row.key,...value});else if(value.kind==='deferred')deferred++;}
    }catch(error){this.check();unreadable++;}
   }
   records.sort((a,b)=>a.receivedAt-b.receivedAt);return {records:records.slice(0,limit),unreadable,deferred};
  }
  async acknowledge(handle,accountSlot){
   this.check();if(!token(handle)||!slot(accountSlot))throw Error('Invalid Inbox receipt');
   const row=await this.store.read(handle);if(!row)return false;
   const value=await this.decrypt(row);
   if(value.accountSlot!==accountSlot)throw Error('Inbox Account mismatch');
   if(value.kind==='seen')return true;
   if(value.kind!=='pending')throw Error('Invalid Inbox state');
   // Caller sends this only after Account state/message persistence succeeds.
   return this.store.cas(handle,row.revision,await this.encrypt(handle,{kind:'seen',accountSlot,seenAt:this.clock()}));
  }
  async saveBinding(routeId,value,{replace=false}={}){
   this.check();if(!token(routeId))throw Error('Invalid local route');
   const key='binding:'+await this.alias('route|'+routeId),row=await this.store.read(key);
   if(row&&!replace)return false;
   return this.store.cas(key,row?.revision??null,await this.encrypt(key,{...value,kind:'binding',routeId}));
  }
  async bindings(){
   this.check();const records=[];let unreadable=0;
   for(const row of await this.store.allBindings()){
    if(row.key==='owner')continue;
    try{const value=await this.decrypt(row);if(value.kind!=='binding'||!token(value.routeId))throw Error();records.push(value);}
    catch(error){this.check();unreadable++;}
   }
   return {records,unreadable};
  }
  async pruneSeen(){
   this.check();let removed=0;const before=this.clock()-30*86400000;
   for(const row of await this.store.all()){
    if(row.key==='owner')continue;
    let value;try{value=await this.decrypt(row);}catch(error){this.check();continue;}
    if(value.kind==='seen'&&value.seenAt<=before&&await this.store.cas(row.key,row.revision,null))removed++;
   }
   return removed;
  }
  async retryDeferred(routeId,accountSlot,privateKeys){
   this.check();if(!token(routeId)||!slot(accountSlot)||!Array.isArray(privateKeys)||!privateKeys.length)throw Error('Recipient keys required');
   let processed=0;
   for(const row of await this.store.all()){
    if(row.key==='owner')continue;
    let value;try{value=await this.decrypt(row);}catch(error){this.check();continue;}
    if(value.kind!=='deferred'||value.routeId!==routeId||value.accountSlot!==accountSlot)continue;
    const opened=global.DmashRecipientPayloadV4.openPayload(privateKeys,value.blob);
    if(opened.status==='discard'){if(await this.store.cas(row.key,row.revision,null))processed++;continue;}
    if(opened.status!=='accepted')continue;
    const targetKey=await this.alias('packet|'+routeId+'|'+opened.packet_id),target=await this.store.read(targetKey);
    let preserve=false;
    if(target){
     let prior;try{prior=await this.decrypt(target);}catch(error){this.check();}
     if(prior){if(prior.accountSlot!==accountSlot)throw Error('Inbox Account mismatch');preserve=prior.kind==='pending'||prior.kind==='seen';}
    }
    const replacement=preserve?null:await this.encrypt(targetKey,{kind:'pending',routeId,accountSlot,receivedAt:value.receivedAt,packetId:opened.packet_id,payload:opened.payload});
    if(await this.store.promote(row.key,row.revision,targetKey,target?.revision??null,replacement))processed++;
   }
   return processed;
  }
  close(){this.closed=true;this.store?.close();this.aliasKey=null;this.encryptionKey=null;}
 }
 global.DmashNodeInboxV4=NodeInboxV4;global.DmashNodeInboxStoreV4=InboxStore;
 if(typeof module!=='undefined')module.exports={NodeInboxV4,InboxStore};
})(typeof window!=='undefined'?window:globalThis);
