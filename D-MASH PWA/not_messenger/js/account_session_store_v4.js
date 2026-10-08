'use strict';
(function(global){
 const TABLE='pairing_material',MAX=131072;
 const fail=c=>{throw Object.assign(Error(c),{code:c});};
 const bytes=s=>new TextEncoder().encode(s),hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
 const b64=a=>{let s='';for(const b of a)s+=String.fromCharCode(b);return btoa(s);};
 const same=(a,b)=>a===null?b===null:b!==null&&a.alias===b.alias&&a.blob===b.blob;
 class AccountSessionStoreV4 {
  #tokens=new WeakMap();#closed=false;#transactions=new Set();
  static async open(options){const store=new AccountSessionStoreV4(options);try{await store._open();return store;}catch(e){store.close();throw e;}}
  constructor({db,dataKey,blindKey,owner,signal,crypto=global.crypto}){
   if(!db?.objectStoreNames.contains(TABLE)||dataKey?.algorithm?.name!=='AES-GCM'||(blindKey?.algorithm?.name!=='HMAC'||blindKey.algorithm.hash?.name!=='SHA-256')||!owner?.assertCurrent||!signal?.addEventListener||signal.aborted)fail('SESSION_REQUIRED');
   this.db=db;this.dataKey=dataKey;this.blindKey=blindKey;this.owner=owner;this.signal=signal;this.crypto=crypto;
   const c=owner.context();for(const value of [c.local,c.peer,c.bindingDigest])if(!/^[a-f0-9]{64}$/.test(value))fail('CONTEXT');this.context=Object.freeze({...c});
   this.abort=()=>this.close();signal.addEventListener('abort',this.abort,{once:true});this.check();
  }
  check(){if(this.#closed||this.signal.aborted)fail('SESSION_CHANGED');this.owner.assertCurrent();const c=this.owner.context();for(const key of ['local','peer','bindingDigest','bindingGeneration','requiredSuite'])if(c[key]!==this.context[key])fail('SESSION_CHANGED');}
  async wait(p){this.check();const result=await p;this.check();return result;}
  async _open(){this.aliases={};for(const kind of ['ledger','state'])this.aliases[kind]=hex(new Uint8Array(await this.wait(this.crypto.subtle.sign('HMAC',this.blindKey,bytes('D-MASH|ACCOUNT-SESSION-STORE|V4\0'+this.context.local+'\0'+this.context.peer+'\0'+kind)))));}
  close(){if(this.#closed)return;this.#closed=true;for(const tx of this.#transactions){try{tx.abort();}catch(_){}}this.#transactions.clear();this.signal.removeEventListener('abort',this.abort);this.#tokens=new WeakMap();this.dataKey=null;this.blindKey=null;}
  async _encrypt(kind,payload){const alias=this.aliases[kind],plain=bytes(JSON.stringify({schema:4,kind,alias,local:this.context.local,peer:this.context.peer,payload}));if(plain.length>MAX)fail('RECORD_SIZE');const iv=this.crypto.getRandomValues(new Uint8Array(12));try{const enc=new Uint8Array(await this.wait(this.crypto.subtle.encrypt({name:'AES-GCM',iv},this.dataKey,plain))),packed=new Uint8Array(iv.length+enc.length);packed.set(iv);packed.set(enc,12);return {alias,blob:b64(packed)};}finally{plain.fill(0);}}
  async _decrypt(kind,row){if(row===null)return null;let plain;try{if(row.alias!==this.aliases[kind]||typeof row.blob!=='string'||row.blob.length>Math.ceil((MAX+28)/3)*4)fail('CORRUPT_SESSION');const raw=Uint8Array.from(atob(row.blob),x=>x.charCodeAt(0));if(raw.length<28||b64(raw)!==row.blob)fail('CORRUPT_SESSION');plain=new Uint8Array(await this.wait(this.crypto.subtle.decrypt({name:'AES-GCM',iv:raw.subarray(0,12)},this.dataKey,raw.subarray(12))));const record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));if(Object.keys(record).sort().join(',')!=='alias,kind,local,payload,peer,schema'||record.schema!==4||record.kind!==kind||record.alias!==row.alias||record.local!==this.context.local||record.peer!==this.context.peer)fail('CORRUPT_SESSION');return record.payload;}catch(e){this.check();fail('CORRUPT_SESSION');}finally{plain?.fill(0);}}
  _transaction(expected=null,writes=null,guard=()=>{}){this.check();return new Promise((resolve,reject)=>{let tx,problem;try{tx=this.db.transaction(TABLE,writes?'readwrite':'readonly');this.#transactions.add(tx);}catch(e){reject(e);return;}const result={};const abort=e=>{problem=e;try{tx.abort();}catch(_){reject(e);}};tx.onabort=()=>{this.#transactions.delete(tx);reject(problem||tx.error||Error('TX_ABORTED'));};tx.onerror=()=>{};tx.oncomplete=()=>{this.#transactions.delete(tx);try{this.check();guard();resolve(result);}catch(e){reject(e);}};let remaining=2;const table=tx.objectStore(TABLE);for(const kind of ['ledger','state']){const request=table.get(this.aliases[kind]);request.onsuccess=()=>{try{this.check();guard();result[kind]=request.result??null;if(--remaining)return;if(expected&&(!same(expected.ledger,result.ledger)||!same(expected.state,result.state)))fail('SESSION_CONFLICT');if(writes)for(const k of ['ledger','state']){this.check();guard();table.put(writes[k]);}}catch(e){abort(e);}};}});}
  async load(){const raw=await this._transaction(),ledger=await this._decrypt('ledger',raw.ledger),state=await this._decrypt('state',raw.state);this.check();if(state&&!ledger)fail('LEDGER_MISSING');if(state&&state.revision!==ledger.revision)fail('SESSION_RECORD_CONFLICT');if(ledger&&(typeof ledger.revision!=='string'||!Array.isArray(ledger.retired)||!Array.isArray(ledger.superseded)))fail('CORRUPT_SESSION');const revision=Object.freeze({});this.#tokens.set(revision,raw);
   if(!ledger)return {revision,value:null};
   const value=state?state.value:{version:4,confirmed:null,pending:null,recovery:null,intents:[],superseded:[]};
   if(value.version!==4||!Array.isArray(value.intents))fail('CORRUPT_SESSION');value.ledger=ledger.confirmed;value.retired=ledger.retired;value.recovery=ledger.recovery;value.superseded=ledger.superseded;
   if(value.confirmed&&(value.confirmed.session_id!==value.ledger?.session_id||value.confirmed.generation!==value.ledger?.generation))fail('SESSION_RECORD_CONFLICT');return {revision,value};
  }
  async commit(revision,value,guard){this.check();const expected=this.#tokens.get(revision);if(!expected||typeof guard!=='function')fail('REVISION_REQUIRED');guard();const token=hex(this.crypto.getRandomValues(new Uint8Array(32))),state=structuredClone(value);delete state.ledger;delete state.retired;delete state.recovery;delete state.superseded;const writes={ledger:await this._encrypt('ledger',{revision:token,confirmed:value.ledger,retired:value.retired,recovery:value.recovery,superseded:value.superseded}),state:await this._encrypt('state',{revision:token,value:state})};this.check();guard();await this._transaction(expected,writes,guard);this.#tokens.delete(revision);this.check();}
 }
 global.DmashAccountSessionStoreV4=AccountSessionStoreV4;if(typeof module!=='undefined')module.exports=AccountSessionStoreV4;
})(typeof window!=='undefined'?window:globalThis);
