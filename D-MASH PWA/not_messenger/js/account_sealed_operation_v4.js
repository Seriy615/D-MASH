'use strict';
(function(global){
 const STORE='pairing_material',DOMAIN='D-MASH|ACCOUNT-SEALED-OPERATION|V4\0';
 const utf=value=>new TextEncoder().encode(value),hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const validHex=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 const b64=bytes=>btoa(String.fromCharCode(...bytes));
 class AccountSealedOperationV4{
  #session;#journal;#crypto;#recipient;#secure;#discovery;#aliasKey;#closed=false;#transactions=new Set();#abort;
  // Dependencies are fixed by trusted local integration, never provided by a wire frame.
  static async open(options){const store=new AccountSealedOperationV4(options);try{
   store.#aliasKey=await store.#wait(store.#crypto.subtle.importKey('raw',store.#session.blindSalt,{name:'HMAC',hash:'SHA-256'},false,['sign']));return store;
  }catch(error){store.close();throw error;}}
  constructor({session,journal,crypto=global.crypto,recipient=global.DmashRecipientPayloadV4,secureSession=global.DmashSecureSession,discovery=global.DmashRouteDiscoveryV4}){
   if(!session?.assertCurrent||!session.signal||!session.db?.objectStoreNames.contains(STORE)||!session.masterKey||!journal?.readRouteSnapshot||!recipient?.sealPayload||!secureSession?.canonical||!discovery?.verifyCertificate)fail('SEALED_OPERATION_DEPENDENCY');
   session.assertCurrent();this.#session=session;this.#journal=journal;this.#crypto=crypto;this.#recipient=recipient;this.#secure=secureSession;this.#discovery=discovery;
   this.#abort=()=>this.close();session.signal.addEventListener('abort',this.#abort,{once:true});this.#check();
  }
  #check(){if(this.#closed||this.#session.signal.aborted)fail('ACCOUNT_SESSION_CHANGED');this.#session.assertCurrent();}
  async #wait(p){this.#check();const value=await p;this.#check();return value;}
  close(){if(this.#closed)return;this.#closed=true;for(const tx of this.#transactions){try{tx.abort();}catch(_){}}this.#transactions.clear();this.#session.signal.removeEventListener('abort',this.#abort);this.#aliasKey=null;}
  async #digest(value){return hex(new Uint8Array(await this.#wait(this.#crypto.subtle.digest('SHA-256',utf(value)))));}
  async #alias(id){return hex(new Uint8Array(await this.#wait(this.#crypto.subtle.sign('HMAC',this.#aliasKey,utf(DOMAIN+id)))));}
  #transaction(alias,expected,write){
   this.#check();return new Promise((resolve,reject)=>{let error=null,row=null,tx;
    try{tx=this.#session.db.transaction(STORE,write?'readwrite':'readonly');this.#transactions.add(tx);}catch(e){reject(e);return;}
    const abort=e=>{error=e;try{tx.abort();}catch(_){reject(e);}};
    tx.onabort=()=>{this.#transactions.delete(tx);reject(error||tx.error||Error('SEALED_OPERATION_ABORTED'));};tx.onerror=()=>{};
    tx.oncomplete=()=>{this.#transactions.delete(tx);try{this.#check();resolve(row);}catch(e){reject(e);}};
    const store=tx.objectStore(STORE),request=store.get(alias);
    request.onsuccess=()=>{try{this.#check();row=request.result??null;if(write){if((row?.blob??null)!==(expected?.blob??null))fail('SEALED_OPERATION_CAS');store.put(write);}}catch(e){abort(e);}};
   });
  }
  async #decode(alias,row){
   if(!row)return null;try{
    if(row.alias!==alias||typeof row.blob!=='string'||row.blob.length>90000)fail('SEALED_OPERATION_CORRUPT');
    const bytes=Uint8Array.from(atob(row.blob),c=>c.charCodeAt(0));if(bytes.length<28||b64(bytes)!==row.blob)fail('SEALED_OPERATION_CORRUPT');
    const plain=await this.#wait(this.#crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(0,12)},this.#session.masterKey,bytes.subarray(12)));
    const record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));
    if(record.schema!==1||record.type!=='ACCOUNT_SEALED_OPERATION_V4'||record.alias!==alias)fail('SEALED_OPERATION_CORRUPT');return record;
   }catch(error){this.#check();fail('SEALED_OPERATION_CORRUPT');}
  }
  async #encode(alias,record){
   const iv=this.#crypto.getRandomValues(new Uint8Array(12)),plain=utf(JSON.stringify(record));
   try{const encrypted=new Uint8Array(await this.#wait(this.#crypto.subtle.encrypt({name:'AES-GCM',iv},this.#session.masterKey,plain))),packed=new Uint8Array(12+encrypted.length);packed.set(iv);packed.set(encrypted,12);return {alias,blob:b64(packed)};}finally{plain.fill(0);}
  }
  async materialize({operationId,peer,bindingDigest,generation,frame}){
   this.#check();if(!validHex(operationId)||!validHex(peer)||!validHex(bindingDigest)||!Number.isSafeInteger(generation)||generation<1||typeof frame!=='string'||utf(frame).length>15000)fail('SEALED_OPERATION_INPUT');
   const snapshot=await this.#wait(this.#journal.readRouteSnapshot(peer));
   if(!snapshot||snapshot.digest!==bindingDigest||snapshot.generation!==generation||snapshot.readiness!=='NODE_PROOF_REQUIRED')fail('SEALED_OPERATION_BINDING');
   const cert=snapshot.remoteCertificate;this.#discovery.verifyCertificate(cert);
   const certificateDigest=await this.#digest(this.#secure.canonical(cert)),frameDigest=await this.#digest(frame),alias=await this.#alias(operationId);
   const expected={schema:1,type:'ACCOUNT_SEALED_OPERATION_V4',alias,operationId,peer,bindingDigest,generation,certificateDigest,frameDigest};
   const compare=record=>{for(const [name,value]of Object.entries(expected))if(record[name]!==value)fail('SEALED_OPERATION_CONFLICT');
    if(Object.keys(record).sort().join(',')!==[...Object.keys(expected),'blob'].sort().join(',')||typeof record.blob!=='string')fail('SEALED_OPERATION_CORRUPT');
    const raw=Uint8Array.from(atob(record.blob),c=>c.charCodeAt(0));if(raw.length<72||raw.length>16384||b64(raw)!==record.blob)fail('SEALED_OPERATION_CORRUPT');
    return Object.freeze({operationId,peer,bindingDigest,generation,certificateDigest,blob:record.blob,state:'DURABLE_SEALED_OPERATION'});};
   const finish=async record=>{
    const latest=await this.#wait(this.#journal.readRouteSnapshot(peer));
    if(!latest||latest.digest!==bindingDigest||latest.generation!==generation||latest.readiness!=='NODE_PROOF_REQUIRED'||await this.#digest(this.#secure.canonical(latest.remoteCertificate))!==certificateDigest)fail('SEALED_OPERATION_BINDING');
    this.#discovery.verifyCertificate(latest.remoteCertificate);this.#check();return compare(record);
   };
   const old=await this.#wait(this.#transaction(alias)),decoded=await this.#decode(alias,old);if(decoded)return finish(decoded);
   const pub=Uint8Array.from(cert.recipient_box.match(/../g),byte=>parseInt(byte,16));
   const record={...expected,blob:this.#recipient.sealPayload(pub,frame)};compare(record);this.#check();
   const encrypted=await this.#encode(alias,record);
   try{await this.#wait(this.#transaction(alias,null,encrypted));}catch(error){
    if(error.code!=='SEALED_OPERATION_CAS')throw error;
    // A competing materializer wins durably; losing ciphertext must never escape.
    const winner=await this.#decode(alias,await this.#wait(this.#transaction(alias)));if(!winner)fail('SEALED_OPERATION_CORRUPT');return finish(winner);
   }
   return finish(record);
  }
 }
 global.DmashAccountSealedOperationV4=AccountSealedOperationV4;if(typeof module!=='undefined')module.exports=AccountSealedOperationV4;
})(typeof window!=='undefined'?window:globalThis);
