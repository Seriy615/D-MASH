'use strict';
(function(global){
 const TABLE='pairing_material',DOMAIN='D-MASH|ACCOUNT-APP-LEDGER|V4\0',TYPE='ACCOUNT_APP_V4',MAX_FRAME=16000;
 const fail=code=>{throw Object.assign(Error(code),{code});};
 const utf=s=>new TextEncoder().encode(s),hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
 const unhex=s=>Uint8Array.from(s.match(/../g),v=>parseInt(v,16));
 const h64=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s);
 const b64=a=>{let s='';for(const b of a)s+=String.fromCharCode(b);return btoa(s);};
 const from64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 const keys=(o,names)=>!!o&&Object.keys(o).sort().join(',')===names.slice().sort().join(',');
 const contentType=s=>s==='text/plain;charset=utf-8';
 class AccountAppCipherV4 {
  #store;#session;#crypto;#submit;#persist;#blindKey;#closed=false;#transactions=new Set();#abort;#pending=new Map();
  static async open(options){const c=new AccountAppCipherV4(options),salt=options.blindSalt.slice();try{c.#blindKey=await c.#wait(c.#crypto.subtle.importKey('raw',salt,{name:'HMAC',hash:'SHA-256'},false,['sign']));return c;}catch(e){c.close();throw e;}finally{salt.fill(0);}}
  constructor({store,session,blindSalt,submit,persistAuthenticated,crypto=global.crypto}){
   if(!store?.load||!store?.check||!store?.db?.objectStoreNames.contains(TABLE)||store.dataKey?.algorithm?.name!=='AES-GCM'||!store.context||!store.signal||!session?.status||!(blindSalt instanceof Uint8Array)||blindSalt.length!==32||typeof submit!=='function'||typeof persistAuthenticated!=='function'||!crypto?.subtle)fail('APP_DEPENDENCY');
   this.#store=store;this.#session=session;this.#crypto=crypto;this.#submit=submit;this.#persist=persistAuthenticated;
   this.#abort=()=>this.close();store.signal.addEventListener('abort',this.#abort,{once:true});this.#check();
  }
  #check(){if(this.#closed)fail('APP_CLOSED');this.#store.check();}
  async #wait(p){this.#check();const x=await p;this.#check();return x;}
  close(){if(this.#closed)return;this.#closed=true;for(const tx of this.#transactions)try{tx.abort();}catch(_){}this.#transactions.clear();this.#store.signal.removeEventListener('abort',this.#abort);this.#blindKey=null;}
  async #sha(s){return hex(new Uint8Array(await this.#wait(this.#crypto.subtle.digest('SHA-256',utf(s)))));}
  async #alias(direction,id){const c=this.#store.context;return hex(new Uint8Array(await this.#wait(this.#crypto.subtle.sign('HMAC',this.#blindKey,utf(DOMAIN+c.local+'\0'+c.peer+'\0'+direction+'\0'+id)))));}
  async #active(){this.#check();const status=await this.#wait(this.#session.status());if(status.phase!=='ESTABLISHED')fail('APP_SESSION_NOT_ESTABLISHED');const row=(await this.#wait(this.#store.load())).value,c=this.#store.context,x=row?.confirmed;
   if(!x||!h64(x.root)||!h64(x.session_id)||x.generation!==status.generation||x.session_id!==status.sessionId||row.ledger?.session_id!==x.session_id||row.ledger?.generation!==x.generation||c.bindingGeneration<1)fail('APP_SESSION_NOT_ESTABLISHED');return {root:x.root,sessionId:x.session_id,generation:x.generation};
  }
  async #still(a){const b=await this.#active();if(a.root!==b.root||a.sessionId!==b.sessionId||a.generation!==b.generation)fail('APP_SESSION_CHANGED');}
  #meta(a,sender,recipient,operationId,type){const c=this.#store.context;return {type:TYPE,version:4,suite:c.requiredSuite,binding_digest:c.bindingDigest,binding_generation:c.bindingGeneration,session_id:a.sessionId,session_generation:a.generation,sender,recipient,operation_id:operationId,content_type:type};}
  async #key(a,sender,recipient){const c=this.#store.context,root=unhex(a.root);try{const key=await this.#wait(this.#crypto.subtle.importKey('raw',root,'HKDF',false,['deriveKey']));return this.#wait(this.#crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unhex(a.sessionId),info:utf('D-MASH|ACCOUNT-APP-KEY|V4\0'+c.bindingDigest+'\0'+c.bindingGeneration+'\0'+sender+'\0'+recipient)},key,{name:'AES-GCM',length:256},false,['encrypt','decrypt']));}finally{root.fill(0);}}
  #tx(alias,expected,write){this.#check();return new Promise((resolve,reject)=>{let tx,problem,row=null;try{tx=this.#store.db.transaction(TABLE,write?'readwrite':'readonly');this.#transactions.add(tx);}catch(e){reject(e);return;}
   const abort=e=>{problem=e;try{tx.abort();}catch(_){reject(e);}};tx.onabort=()=>{this.#transactions.delete(tx);reject(problem||tx.error||Error('APP_TX_ABORTED'));};tx.onerror=()=>{};tx.oncomplete=()=>{this.#transactions.delete(tx);try{this.#check();resolve(row);}catch(e){reject(e);}};
   const table=tx.objectStore(TABLE),get=table.get(alias);get.onsuccess=()=>{try{this.#check();row=get.result??null;if(write){if((row?.blob??null)!==(expected?.blob??null))fail('APP_CAS');table.put(write);}}catch(e){abort(e);}};
  });}
  async #decode(alias,row){if(!row)return null;try{if(row.alias!==alias||typeof row.blob!=='string'||row.blob.length>50000)fail('APP_LEDGER_CORRUPT');const raw=from64(row.blob);if(raw.length<28||b64(raw)!==row.blob)fail('APP_LEDGER_CORRUPT');const plain=new Uint8Array(await this.#wait(this.#crypto.subtle.decrypt({name:'AES-GCM',iv:raw.subarray(0,12),additionalData:utf(DOMAIN+alias)},this.#store.dataKey,raw.subarray(12))));try{const r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));if(r.type!=='ACCOUNT_APP_LEDGER_V4'||r.alias!==alias||r.schema!==1)fail('APP_LEDGER_CORRUPT');return r;}finally{plain.fill(0);}}catch(e){this.#check();fail('APP_LEDGER_CORRUPT');}}
  async #encode(alias,r){const iv=this.#crypto.getRandomValues(new Uint8Array(12)),plain=utf(JSON.stringify(r));if(plain.length>30000)fail('APP_LEDGER_SIZE');try{const enc=new Uint8Array(await this.#wait(this.#crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf(DOMAIN+alias)},this.#store.dataKey,plain))),packed=new Uint8Array(12+enc.length);packed.set(iv);packed.set(enc,12);return {alias,blob:b64(packed)};}finally{plain.fill(0);}}
  async #save(alias,record){const prior=await this.#wait(this.#tx(alias));if(prior)return this.#decode(alias,prior);const encoded=await this.#encode(alias,record);try{await this.#wait(this.#tx(alias,null,encoded));return record;}catch(e){if(e.code!=='APP_CAS')throw e;const winner=await this.#decode(alias,await this.#wait(this.#tx(alias)));if(!winner)fail('APP_LEDGER_CORRUPT');return winner;}}
  async #single(id,task){const old=this.#pending.get(id);const run=(old?old.catch(()=>{}):Promise.resolve()).then(task);this.#pending.set(id,run);try{return await run;}finally{if(this.#pending.get(id)===run)this.#pending.delete(id);}}
  async sendApplication({operationId,plaintext,contentType:kind='text/plain;charset=utf-8'}){
   if(!h64(operationId)||typeof plaintext!=='string'||utf(plaintext).length>8192||!contentType(kind))fail('APP_INPUT');return this.#single('out:'+operationId,async()=>{
    const a=await this.#active(),c=this.#store.context,alias=await this.#alias('out',operationId),digest=await this.#sha(plaintext),prior=await this.#decode(alias,await this.#wait(this.#tx(alias)));let record=prior;
    if(!record){const meta=this.#meta(a,c.local,c.peer,operationId,kind),iv=this.#crypto.getRandomValues(new Uint8Array(12)),key=await this.#key(a,c.local,c.peer),ct=new Uint8Array(await this.#wait(this.#crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf(JSON.stringify(meta))},key,utf(plaintext))));const frame=JSON.stringify({...meta,nonce:hex(iv),ciphertext:b64(ct)});if(utf(frame).length>MAX_FRAME)fail('APP_FRAME_SIZE');record=await this.#save(alias,{schema:1,type:'ACCOUNT_APP_LEDGER_V4',alias,direction:'out',operationId,peer:c.peer,bindingDigest:c.bindingDigest,bindingGeneration:c.bindingGeneration,sessionId:a.sessionId,sessionGeneration:a.generation,contentType:kind,plaintextDigest:digest,frame});}
    if(record.direction!=='out'||record.operationId!==operationId||record.peer!==c.peer||record.bindingDigest!==c.bindingDigest||record.bindingGeneration!==c.bindingGeneration||record.sessionId!==a.sessionId||record.sessionGeneration!==a.generation||record.contentType!==kind||record.plaintextDigest!==digest||typeof record.frame!=='string')fail('APP_OPERATION_CONFLICT');
    await this.#still(a);const result=await this.#wait(this.#submit(Object.freeze({operationId,frame:record.frame,peer:c.peer,bindingDigest:c.bindingDigest,generation:c.bindingGeneration})));await this.#still(a);if(result?.queued!==true)fail('APP_LOCAL_QUEUE_REFUSED');return Object.freeze({operationId,durable:true,queued:true,recipientAck:false,frame:record.frame});
   });
  }
  async receiveApplication(frame){if(typeof frame!=='string'||utf(frame).length>MAX_FRAME)fail('APP_FRAME_SIZE');let f;try{f=JSON.parse(frame);}catch(_){fail('APP_FRAME_FORMAT');}const c=this.#store.context;
   if(!keys(f,['type','version','suite','binding_digest','binding_generation','session_id','session_generation','sender','recipient','operation_id','content_type','nonce','ciphertext'])||f.type!==TYPE||f.version!==4||f.suite!==c.requiredSuite||!h64(f.sender)||!h64(f.recipient)||!h64(f.operation_id)||!h64(f.session_id)||!h64(f.binding_digest)||!contentType(f.content_type)||!(/^[0-9a-f]{24}$/.test(f.nonce))||typeof f.ciphertext!=='string'||f.ciphertext.length>14000)fail('APP_FRAME_FORMAT');
   return this.#single('in:'+f.operation_id,async()=>{const a=await this.#active();if(f.sender!==c.peer||f.recipient!==c.local||f.binding_digest!==c.bindingDigest||f.binding_generation!==c.bindingGeneration||f.session_id!==a.sessionId||f.session_generation!==a.generation)fail('APP_CONTEXT');
    const meta=this.#meta(a,c.peer,c.local,f.operation_id,f.content_type);let ct;try{ct=from64(f.ciphertext);if(b64(ct)!==f.ciphertext||ct.length<16)fail('APP_FRAME_FORMAT');}catch(_){fail('APP_FRAME_FORMAT');}
    const key=await this.#key(a,c.peer,c.local);let plain;try{plain=new Uint8Array(await this.#wait(this.#crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(f.nonce),additionalData:utf(JSON.stringify(meta))},key,ct)));}catch(_){this.#check();fail('APP_AUTH_FAILED');}
    let plaintext;try{if(plain.length>8192)fail('APP_FRAME_SIZE');plaintext=new TextDecoder('utf-8',{fatal:true}).decode(plain);}catch(_){fail('APP_PLAINTEXT');}finally{plain.fill(0);}
    const alias=await this.#alias('in',f.operation_id),frameDigest=await this.#sha(frame),record=await this.#save(alias,{schema:1,type:'ACCOUNT_APP_LEDGER_V4',alias,direction:'in',operationId:f.operation_id,peer:c.peer,bindingDigest:c.bindingDigest,bindingGeneration:c.bindingGeneration,sessionId:a.sessionId,sessionGeneration:a.generation,contentType:f.content_type,frameDigest,historyCommitted:false});
    if(record.direction!=='in'||record.operationId!==f.operation_id||record.peer!==c.peer||record.bindingDigest!==c.bindingDigest||record.bindingGeneration!==c.bindingGeneration||record.sessionId!==a.sessionId||record.sessionGeneration!==a.generation||record.contentType!==f.content_type||record.frameDigest!==frameDigest)fail('APP_REPLAY_CONFLICT');
    // The history writer is authoritative for durable UI state. Recheck it on
    // every Node replay, including when our local marker says committed: a
    // user may have explicitly deleted the chat after that marker was written.
    await this.#still(a);const committed=await this.#wait(this.#persist(Object.freeze({peer:c.peer,operationId:f.operation_id,plaintext,contentType:f.content_type,bindingDigest:c.bindingDigest,generation:c.bindingGeneration,sessionId:a.sessionId})));if(committed?.persisted!==true)fail('APP_HISTORY_NOT_DURABLE');await this.#still(a);
    if(record.historyCommitted)return Object.freeze({persisted:true,duplicate:true,operationId:f.operation_id,kind:'application'});
    const raw=await this.#wait(this.#tx(alias)),latest=await this.#decode(alias,raw);if(latest.frameDigest!==frameDigest)fail('APP_REPLAY_CONFLICT');if(!latest.historyCommitted){const encoded=await this.#encode(alias,{...latest,historyCommitted:true});try{await this.#wait(this.#tx(alias,raw,encoded));}catch(e){if(e.code!=='APP_CAS')throw e;const winner=await this.#decode(alias,await this.#wait(this.#tx(alias)));if(!winner?.historyCommitted||winner.frameDigest!==frameDigest)fail('APP_REPLAY_CONFLICT');}}
    return Object.freeze({persisted:true,duplicate:false,operationId:f.operation_id,kind:'application'});
   });
  }
 }
 global.DmashAccountAppCipherV4=AccountAppCipherV4;if(typeof module!=='undefined')module.exports=AccountAppCipherV4;
})(typeof window!=='undefined'?window:globalThis);
