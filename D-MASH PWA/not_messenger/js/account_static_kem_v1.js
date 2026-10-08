'use strict';
(function(global){
 const PROFILE='ACCOUNT_STATIC_LEGACY_KYBER768_V1',STORE='pairing_material',DOMAIN='D-MASH|ACCOUNT-STATIC-KEM|V1\0';
 const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),utf=s=>new TextEncoder().encode(s),b64=b=>btoa(String.fromCharCode(...b));
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const decode=(value,size)=>{if(typeof value!=='string'||value.length!==size*2||!/^[0-9a-f]+$/.test(value))fail('ACCOUNT_KEM_CORRUPT');return Uint8Array.from(value.match(/../g),x=>parseInt(x,16));};
 function wasmAdapter(module){
  if(!module?._malloc||!module?._free||!module?._wasm_keypair||!module?._wasm_encapsulate||!module?._wasm_decapsulate)fail('ACCOUNT_KEM_UNAVAILABLE');
  const invoke=(sizes,inputs,method,outputs)=>{const pointers=[];try{
   for(const size of sizes){const ptr=module._malloc(size);if(!ptr)fail('ACCOUNT_KEM_ALLOCATION');pointers.push(ptr);}
   for(const [index,value] of inputs){if(!(value instanceof Uint8Array)||value.length!==sizes[index])fail('ACCOUNT_KEM_INPUT');module.HEAPU8.set(value,pointers[index]);}
   const result=module[method](...pointers),value={success:result===0};for(const [name,index] of outputs)value[name]=module.HEAPU8.slice(pointers[index],pointers[index]+sizes[index]);return value;
  }finally{pointers.forEach((ptr,index)=>{module.HEAPU8.fill(0,ptr,ptr+sizes[index]);module._free(ptr);});}};
  return Object.freeze({generateKeys:()=>invoke([1184,2400],[],'_wasm_keypair',[['pk',0],['sk',1]]),encapsulate:pk=>invoke([1088,32,1184],[[2,pk]],'_wasm_encapsulate',[['ct',0],['ss',1]]),decapsulate:(ct,sk)=>invoke([32,1088,2400],[[1,ct],[2,sk]],'_wasm_decapsulate',[['ss',0]])});
 }
 class AccountStaticKemV1{
  #session;#crypto;#kem;#alias;#account;#closed=false;#transactions=new Set();#secrets=new Set();#abort;
  static async open({session,crypto=global.crypto,kem=null}){
   const store=new AccountStaticKemV1(session,crypto,kem||wasmAdapter(global.KyberModule));
   try{const key=await store.#wait(crypto.subtle.importKey('raw',session.blindSalt,{name:'HMAC',hash:'SHA-256'},false,['sign']));store.#alias=hex(new Uint8Array(await store.#wait(crypto.subtle.sign('HMAC',key,utf(DOMAIN+store.#account)))));return store;}catch(error){store.close();throw error;}
  }
  constructor(session,crypto,kem){
   if(!session?.assertCurrent||!session.signal||!session.keys?.sign?.publicKey||!session.db?.objectStoreNames.contains(STORE)||!Number.isSafeInteger(session.generation)||session.generation<1||!kem?.generateKeys||!kem.encapsulate||!kem.decapsulate)fail('ACCOUNT_KEM_SESSION');
   this.#session=session;this.#crypto=crypto;this.#kem=kem;this.#account=hex(session.keys.sign.publicKey);this.#abort=()=>this.close();this.#check();session.signal.addEventListener('abort',this.#abort,{once:true});
  }
  #check(){if(this.#closed||this.#session.signal.aborted)fail('ACCOUNT_KEM_SESSION_CHANGED');this.#session.assertCurrent();}
  async #wait(p){this.#check();const value=await p;try{this.#check();return value;}catch(error){if(value instanceof ArrayBuffer)new Uint8Array(value).fill(0);else if(ArrayBuffer.isView(value))new Uint8Array(value.buffer,value.byteOffset,value.byteLength).fill(0);throw error;}}
  release(material){const secret=material?.secretKey;if(!this.#secrets.delete(secret))return false;secret.fill(0);return true;}
  close(){if(this.#closed)return;this.#closed=true;for(const tx of this.#transactions){try{tx.abort();}catch(_){}}this.#transactions.clear();for(const secret of this.#secrets)secret.fill(0);this.#secrets.clear();this.#session.signal.removeEventListener('abort',this.#abort);}
  #tx(write){this.#check();return new Promise((resolve,reject)=>{
   let tx,error=null,row;try{tx=this.#session.db.transaction(STORE,write?'readwrite':'readonly');this.#transactions.add(tx);}catch(e){reject(e);return;}
   tx.onabort=()=>{this.#transactions.delete(tx);reject(error||tx.error||Error('ACCOUNT_KEM_ABORTED'));};tx.onerror=()=>{};
   tx.oncomplete=()=>{this.#transactions.delete(tx);try{this.#check();resolve(row??null);}catch(e){reject(e);}};
   const store=tx.objectStore(STORE),request=store.get(this.#alias);request.onsuccess=()=>{try{this.#check();row=request.result;if(write&&!row)store.put(write);}catch(e){error=e;try{tx.abort();}catch(_){reject(e);}}};
  });}
  async #read(row){
   if(!row)return null;let plain,pk,sk;
   try{if(row.alias!==this.#alias||typeof row.blob!=='string'||row.blob.length>16000)fail('ACCOUNT_KEM_CORRUPT');const bytes=Uint8Array.from(atob(row.blob),c=>c.charCodeAt(0));if(bytes.length<28||b64(bytes)!==row.blob)fail('ACCOUNT_KEM_CORRUPT');
    plain=new Uint8Array(await this.#wait(this.#crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(0,12),additionalData:utf(DOMAIN+this.#alias)},this.#session.masterKey,bytes.subarray(12))));const record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));
    if(Object.keys(record).sort().join(',')!=='account,alias,createdSessionGeneration,profile,publicKey,schema,secretKey,type'||record.schema!==1||record.type!=='ACCOUNT_STATIC_KEM'||record.alias!==this.#alias||record.account!==this.#account||record.profile!==PROFILE||!Number.isSafeInteger(record.createdSessionGeneration)||record.createdSessionGeneration<1)fail('ACCOUNT_KEM_CORRUPT');
    pk=decode(record.publicKey,1184);sk=decode(record.secretKey,2400);this.#validate(pk,sk);this.#check();if(this.#secrets.size>=32)fail('ACCOUNT_KEM_HANDLE_QUOTA');this.#secrets.add(sk);
    return Object.freeze({profile:PROFILE,publicKey:pk,secretKey:sk,createdSessionGeneration:record.createdSessionGeneration});
   }catch(error){sk?.fill(0);this.#check();if(error?.code==='ACCOUNT_KEM_HANDLE_QUOTA')throw error;fail('ACCOUNT_KEM_CORRUPT');}finally{plain?.fill(0);}
  }
  #validate(pk,sk){let encapsulated,decapsulated;try{encapsulated=this.#kem.encapsulate(pk);if(!encapsulated?.success)fail('ACCOUNT_KEM_CORRUPT');decapsulated=this.#kem.decapsulate(encapsulated.ct,sk);if(!decapsulated?.success||encapsulated.ss.length!==32||decapsulated.ss.length!==32||encapsulated.ss.some((v,i)=>v!==decapsulated.ss[i]))fail('ACCOUNT_KEM_CORRUPT');}finally{encapsulated?.ss?.fill(0);decapsulated?.ss?.fill(0);}}
  async load(){return this.#read(await this.#wait(this.#tx()));}
  async createExplicit(){
   const old=await this.#wait(this.#tx());if(old)return this.#read(old);this.#check();
   const generated=this.#kem.generateKeys();
   let plain;try{
    if(!generated?.success||!(generated.pk instanceof Uint8Array)||generated.pk.length!==1184||!(generated.sk instanceof Uint8Array)||generated.sk.length!==2400)fail('ACCOUNT_KEM_GENERATION');
    this.#validate(generated.pk,generated.sk);const record={schema:1,type:'ACCOUNT_STATIC_KEM',alias:this.#alias,account:this.#account,profile:PROFILE,createdSessionGeneration:this.#session.generation,publicKey:hex(generated.pk),secretKey:hex(generated.sk)};
    plain=utf(JSON.stringify(record));const iv=this.#crypto.getRandomValues(new Uint8Array(12)),cipher=new Uint8Array(await this.#wait(this.#crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf(DOMAIN+this.#alias)},this.#session.masterKey,plain))),packed=new Uint8Array(12+cipher.length);packed.set(iv);packed.set(cipher,12);
    const row={alias:this.#alias,blob:b64(packed)},winner=await this.#wait(this.#tx(row));return this.#read(winner||row);
   }finally{generated?.sk?.fill(0);plain?.fill(0);}
  }
 }
 AccountStaticKemV1.PROFILE=PROFILE;AccountStaticKemV1.wasmAdapter=wasmAdapter;global.DmashAccountStaticKemV1=AccountStaticKemV1;if(typeof module!=='undefined')module.exports=AccountStaticKemV1;
})(typeof window!=='undefined'?window:globalThis);
