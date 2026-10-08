'use strict';
(function(global){
 const STORE='pairing_material',DOMAIN='D-MASH|ACCOUNT-INBOX-PROGRESS|V4';
 const fail=code=>{throw Object.assign(Error(code),{code});};
 const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 const bytes=value=>new TextEncoder().encode(value);
 const b64=value=>{let out='';for(const byte of value)out+=String.fromCharCode(byte);return btoa(out);};
 const validHex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
 const validAfter=value=>value===null||(value&&Number.isSafeInteger(value.receivedAt)&&value.receivedAt>=0&&validHex(value.handle)&&Object.keys(value).sort().join(',')==='handle,receivedAt');
 const validManaged=value=>{
  if(value===null)return true;
  if(!value||Object.keys(value).sort().join(',')!=='next,peers'||!Number.isSafeInteger(value.next)||value.next<0||!Array.isArray(value.peers)||value.peers.length>32)return false;
  const seen=new Set();for(const row of value.peers){
   if(!row||Object.keys(row).sort().join(',')!=='after,digest,generation,peer'||!validHex(row.peer)||!validHex(row.digest)||!Number.isSafeInteger(row.generation)||row.generation<1||!validAfter(row.after)||seen.has(row.peer))return false;
   seen.add(row.peer);
  }return true;
 };
 class AccountInboxProgressV4{
  static async open({session,kind='legacy',crypto=global.crypto}){
   const result=new AccountInboxProgressV4(session,kind,crypto);
   try{await result.initialize();return result;}catch(error){result.close();throw error;}
  }
  constructor(session,kind,crypto){
   if(!session?.assertCurrent||!session?.signal?.addEventListener||session.signal.aborted||!session.db?.objectStoreNames.contains(STORE)||session.masterKey?.algorithm?.name!=='AES-GCM'||!(session.blindSalt instanceof Uint8Array)||session.blindSalt.length<32||!session.keys?.sign?.publicKey||typeof session.accountId!=='string'||!session.accountId||!crypto?.subtle)fail('SESSION_REQUIRED');
   if(!['legacy','managed'].includes(kind))fail('PROGRESS_KIND');
   this.session=session;this.kind=kind;this.crypto=crypto;this.db=session.db;this.dataKey=session.masterKey;
   this.account=hex(session.keys.sign.publicKey);this.slot=session.accountId;
   if(!/^[a-f0-9]{64}$/.test(this.account))fail('ACCOUNT_REQUIRED');
   this.salt=session.blindSalt.slice();this.closed=false;this.transactions=new Set();
   this.abort=()=>this.close();session.signal.addEventListener('abort',this.abort,{once:true});this.check();
  }
  check(){if(this.closed||this.session.signal.aborted||this.session.db!==this.db||this.session.masterKey!==this.dataKey)fail('SESSION_CHANGED');this.session.assertCurrent();}
  async initialize(){
   const key=await this.crypto.subtle.importKey('raw',this.salt,{name:'HMAC',hash:'SHA-256'},false,['sign']);this.check();
   this.alias=hex(new Uint8Array(await this.crypto.subtle.sign('HMAC',key,bytes(DOMAIN+'\0'+this.kind+'\0'+this.account+'\0'+this.slot))));this.check();
   this.aad=bytes(DOMAIN+'\0'+this.kind+'\0'+this.account+'\0'+this.slot+'\0'+this.alias);
   this.salt.fill(0);
  }
  close(){if(this.closed)return;this.closed=true;for(const tx of this.transactions)try{tx.abort();}catch(_){}this.transactions.clear();this.session.signal.removeEventListener('abort',this.abort);this.salt.fill(0);this.aad?.fill(0);this.dataKey=null;}
  async encrypt(cursor){
   this.check();if(!(this.kind==='managed'?validManaged(cursor):validAfter(cursor)))fail('CURSOR');const plain=bytes(JSON.stringify({schema:4,kind:this.kind,account:this.account,slot:this.slot,alias:this.alias,cursor})),iv=this.crypto.getRandomValues(new Uint8Array(12));
   try{const ciphertext=new Uint8Array(await this.crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:this.aad},this.dataKey,plain));this.check();const packed=new Uint8Array(12+ciphertext.length);packed.set(iv);packed.set(ciphertext,12);return b64(packed);}finally{plain.fill(0);}
  }
  async decrypt(row){
   this.check();if(!row)return null;
   if(row.alias!==this.alias||typeof row.blob!=='string'||row.blob.length>16000||!/^[a-f0-9]{64}$/.test(row.revision||''))fail('CORRUPT_PROGRESS');
   let plain;
   try{
    const raw=Uint8Array.from(atob(row.blob),c=>c.charCodeAt(0));if(raw.length<28||b64(raw)!==row.blob)fail('CORRUPT_PROGRESS');
    plain=new Uint8Array(await this.crypto.subtle.decrypt({name:'AES-GCM',iv:raw.subarray(0,12),additionalData:this.aad},this.dataKey,raw.subarray(12)));this.check();
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));
    if(Object.keys(value).sort().join(',')!=='account,alias,cursor,kind,schema,slot'||value.schema!==4||value.kind!==this.kind||value.account!==this.account||value.slot!==this.slot||value.alias!==this.alias||!(this.kind==='managed'?validManaged(value.cursor):validAfter(value.cursor)))fail('CORRUPT_PROGRESS');
    return value.cursor;
   }catch(error){this.check();fail('CORRUPT_PROGRESS');}finally{plain?.fill(0);}
  }
  readRow(){this.check();return new Promise((resolve,reject)=>{let tx;try{tx=this.db.transaction(STORE,'readonly');this.transactions.add(tx);}catch(error){reject(error);return;}let row=null;tx.objectStore(STORE).get(this.alias).onsuccess=event=>{row=event.target.result??null;};tx.oncomplete=()=>{this.transactions.delete(tx);try{this.check();resolve(row);}catch(error){reject(error);}};tx.onabort=tx.onerror=()=>{this.transactions.delete(tx);reject(tx.error||Error('Progress read aborted'));};});}
  async load(){const row=await this.readRow(),cursor=await this.decrypt(row);this.check();return {revision:row?.revision??null,cursor};}
  async save(expected,cursor){
   this.check();if(expected!==null&&!/^[a-f0-9]{64}$/.test(expected||''))fail('REVISION');const blob=await this.encrypt(cursor),revision=hex(this.crypto.getRandomValues(new Uint8Array(32)));this.check();
   return new Promise((resolve,reject)=>{let tx,problem=null;try{tx=this.db.transaction(STORE,'readwrite');this.transactions.add(tx);}catch(error){reject(error);return;}
    const abort=error=>{problem=error;try{tx.abort();}catch(_){reject(error);}};
    tx.objectStore(STORE).get(this.alias).onsuccess=event=>{try{this.check();if((event.target.result?.revision??null)!==expected)fail('PROGRESS_CONFLICT');tx.objectStore(STORE).put({alias:this.alias,blob,revision});}catch(error){abort(error);}};
    tx.oncomplete=()=>{this.transactions.delete(tx);try{this.check();resolve(revision);}catch(error){reject(error);}};
    tx.onabort=tx.onerror=()=>{this.transactions.delete(tx);reject(problem||tx.error||Error('Progress write aborted'));};
   });
  }
 }
 global.DmashAccountInboxProgressV4=AccountInboxProgressV4;
 if(typeof module!=='undefined')module.exports=AccountInboxProgressV4;
})(typeof window!=='undefined'?window:globalThis);
