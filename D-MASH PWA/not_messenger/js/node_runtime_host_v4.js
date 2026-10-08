'use strict';
(function(global){
 const source=global.document?.currentScript?.src,owners=new WeakMap();
 class NodeRuntimeHostV4{
  #localOwners=new Map();#preparations=new Map();#commitVerifier=null;#worker=null;#ownerPermit=Object.freeze({});

  static async startForDevice(deviceRoot,{signal,credential=null,localOwnership='legacy-migration'}={}){
   const session=deviceRoot?.state;
   if(!session?.root||typeof deviceRoot.onLock!=='function')throw Error('Unlocked DeviceRoot required');
   if(owners.has(session))throw Error('Node worker already owns this root session');
   const owner={};owners.set(session,owner);
   const release=()=>{if(owners.get(session)===owner)owners.delete(session);};
   const abort=new AbortController();let host,identity,seed,storageKey,baseNcrh;
   const cancel=()=>{abort.abort();host?.close();};
   const unsubscribe=deviceRoot.onLock(cancel);signal?.addEventListener('abort',cancel,{once:true});
   const current=()=>deviceRoot.state===session&&!abort.signal.aborted;
   try{
    if(signal?.aborted)cancel();
    identity=await global.DmashNodeIdentity.unlockDeviceIdentity(deviceRoot,{signal:abort.signal});
    if(!current())throw Error('Device session changed');
    seed=identity.signing.secretKey.slice(0,32);
    storageKey=await deviceRoot.derive(session.root,'dmash/node-storage',4,'directional-relationships');
    if(!current())throw Error('Device session changed');
    baseNcrh=await deviceRoot.deviceMaterial('node-base-ncrh-v4',()=>crypto.getRandomValues(new Uint8Array(32)));
    if(!current())throw Error('Device session changed');
    host=await this.startMaterials({seed,storageKey,baseNcrh,credential},{signal:abort.signal,localOwnership});
    const cleanup=host.cleanup;
    host.cleanup=()=>{cleanup?.();unsubscribe();release();signal?.removeEventListener('abort',cancel);};
    host.rootGuard=current;
    if(!current())throw Error('Device session changed');return host;
   }catch(error){cancel();unsubscribe();release();signal?.removeEventListener('abort',cancel);throw error;}
   finally{for(const key of [identity?.signing.secretKey,seed,storageKey,baseNcrh])if(key?.byteLength)key.fill(0);}
  }
  static async startMaterials({seed,storageKey,baseNcrh,credential=null},{signal,localOwnership='legacy-migration'}={}){
   const material=[seed,storageKey,baseNcrh,...(credential?[credential.key]:[])];
   if(!source||!global.Worker||material.some(key=>!(key instanceof Uint8Array)||key.length!==32))throw Error('Invalid Node worker materials');
   if(signal?.aborted)throw Error('Node worker cancelled');
   const copies=material.map(key=>key.slice());
   if(!['legacy-migration','managed'].includes(localOwnership))throw Error('Invalid local ownership policy');
   const host=new NodeRuntimeHostV4();host.localOwnership=localOwnership;host.closed=false;host.pending=new Map();host.sequence=0;
   try{
   host.#worker=new Worker(new URL('node_runtime_worker_v4.js',source));
   host.#worker.onmessage=({data})=>{
    if(host.closed)return;if(host.rootGuard&&!host.rootGuard()){host.close();return;}const job=host.pending.get(data?.id);if(!job)return;
    host.pending.delete(data.id);clearTimeout(job.timer);
    if(data.ok)job.resolve(data.result);else job.reject(Error('Node worker operation failed'));
   };
   host.#worker.onerror=()=>host.close();
   const cancel=()=>host.close();signal?.addEventListener('abort',cancel,{once:true});
   host.cleanup=()=>signal?.removeEventListener('abort',cancel);
    host.identity=await host.call('INIT',{apiVersion:3,localOwnership,seed:copies[0],storageKey:copies[1],baseNcrh:copies[2],
     credential:credential?{profile:credential.profile,salt:credential.salt,epoch:credential.epoch,key:copies[3]}:null},copies.map(key=>key.buffer));
    if(host.identity?.apiVersion!==3)throw Error('Incompatible Node worker API');
    if(signal?.aborted||host.closed)throw Error('Node worker cancelled');return host;
   }catch(error){host.close();throw error;}
   finally{for(const key of [...material,...copies])if(key.byteLength)key.fill(0);}
  }
  #ownerCall(type,fields={},transfer=[]){return this.call(type,fields,transfer,this.#ownerPermit);}
  call(type,fields={},transfer=[],permit=null){
   if(typeof type!=='string'||!fields||Object.getPrototypeOf(fields)!==Object.prototype||Reflect.ownKeys(fields).some(key=>typeof key!=='string'||key==='id'||key==='type'||!Object.hasOwn(Object.getOwnPropertyDescriptor(fields,key),'value')))return Promise.reject(Error('Invalid worker RPC fields'));
   if(this.localOwnership==='managed'&&['BIND_LOCAL','INSTALL_RECIPIENT_KEYS','INBOX_LIST','INBOX_ACK','SUBMIT'].includes(type))return Promise.reject(Error('Managed owner capability required'));
   if(type.startsWith('OWNER_')&&permit!==this.#ownerPermit)return Promise.reject(Error('Private ownership endpoint'));
   if(this.rootGuard&&!this.rootGuard())this.close();
   if(this.closed)return Promise.reject(Error('Node worker closed'));
   if(this.pending.size>=16)return Promise.reject(Error('Node worker request quota'));
   const id=++this.sequence;
   return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{this.pending.delete(id);reject(Error('Node worker operation expired'));this.close();},type==='CONNECT'?310000:type==='DISCOVER'?190000:30000);
    this.pending.set(id,{resolve,reject,timer});
    try{this.#worker.postMessage({...fields,id,type},transfer);}catch(error){clearTimeout(timer);this.pending.delete(id);reject(error);}
   });
  }
  setCommitReceiptVerifier(verifier){
   if(this.#commitVerifier||typeof verifier!=='function')throw Error('Commit verifier already configured');
   this.#commitVerifier=verifier;
  }
  challengeLocalOwner(accountPublic,certificate){if(this.localOwnership!=='managed')throw Error('Managed ownership profile required');if(!this.rootGuard||!this.rootGuard())throw Error('Root-owned host required');return this.#ownerCall('OWNER_CHALLENGE',{accountPublic,certificate});}
  async registerLocalOwner(challenge,signature,{accountPublic,isAccountCurrent,signal}){
   if(!this.rootGuard?.()||typeof isAccountCurrent!=='function'||!isAccountCurrent()||!signal||signal.aborted)throw Error('Current Account guard required');
   const result=await this.#ownerCall('OWNER_REGISTER',{challenge,signature});
   try{
    if(!this.rootGuard?.()||!isAccountCurrent()||signal.aborted)throw Error('Account changed');
    if(result.accountPublic!==accountPublic)throw Error('Owner Account mismatch');
   }catch(error){
    // Registration may finish after Account abort; release the newly minted
    // actor token even though no Host capability was published.
    try{await this.#ownerCall('OWNER_RELEASE',{ownerToken:result.token});}catch(_){}
    throw error;
   }
   const cap=Object.freeze({});this.#localOwners.set(cap,{...result,isAccountCurrent,signal});signal.addEventListener('abort',()=>{this.#localOwners.delete(cap);for(const [handle,row]of this.#preparations)if(row.cap===cap)this.#preparations.delete(handle);this.#ownerCall('OWNER_RELEASE',{ownerToken:result.token}).catch(()=>{});},{once:true});return cap;
  }
  #owner(cap){const row=this.#localOwners.get(cap);if(!row||this.closed||!this.rootGuard?.()||row.signal.aborted||!row.isAccountCurrent())throw Error('Owner capability expired');return row;}
  async prepareLocalBinding(cap,data){
   const material=[data.discoverySeed,data.discoveryBox,...(Array.isArray(data.recipientKeys)?data.recipientKeys:[])];
   let copies=[];try{
    if(!Array.isArray(data.recipientKeys)||data.recipientKeys.length>2)throw Error('Invalid recipient keys');
    const owner=this.#owner(cap);copies=material.map(v=>{if(!(v instanceof Uint8Array)||v.length!==32)throw Error('Private material required');return v.slice();});
    const result=await this.#ownerCall('OWNER_PREPARE',{...data,ownerToken:owner.token,discoverySeed:copies[0],discoveryBox:copies[1],recipientKeys:copies.slice(2)},copies.map(v=>v.buffer));
    this.#owner(cap);if(this.#preparations.size>=128)throw Error('Preparation handle quota');const handle=Object.freeze({});this.#preparations.set(handle,{cap,tuple:result,accountPublic:owner.accountPublic});return handle;
   }finally{for(const value of [...material,...copies])if(value?.byteLength)value.fill(0);}
  }
  async verifyPreparation(handle,expected={}){
   const row=this.#preparations.get(handle);if(!row)throw Error('Unknown preparation');const owner=this.#owner(row.cap);
   const current=await this.#ownerCall('OWNER_QUERY',{ownerToken:owner.token,migrationId:row.tuple.migrationId});this.#owner(row.cap);
   if(!current||!['NODE_PREPARED','ACTIVE'].includes(current.state)||current.preparationDigest!==row.tuple.preparationDigest)throw Error('Preparation no longer live');
   row.tuple=current;const value={...current,accountPublic:row.accountPublic};
   if(Object.entries(expected).some(([key,v])=>value[key]!==v))throw Error('Preparation context mismatch');return Object.freeze(value);
  }
  async activateLocalBinding(cap,handle,receipt){
   const owner=this.#owner(cap),entry=this.#preparations.get(handle);if(!entry||entry.cap!==cap||!this.#commitVerifier)throw Error('Commit verifier required');
   const tuple=await this.verifyPreparation(handle);
   if(!await this.#commitVerifier(receipt,tuple))throw Error('Durable Account receipt rejected');
   this.#owner(cap);const {state,...stored}=entry.tuple;const result=await this.#ownerCall('OWNER_ACTIVATE',{ownerToken:owner.token,tuple:stored});this.#owner(cap);entry.tuple=result;return Object.freeze({...result});
  }
  async queryLocalBinding(cap,migrationId){const owner=this.#owner(cap),result=await this.#ownerCall('OWNER_QUERY',{ownerToken:owner.token,migrationId});this.#owner(cap);if(!result)return null;if(this.#preparations.size>=128)throw Error('Preparation handle quota');const handle=Object.freeze({});this.#preparations.set(handle,{cap,tuple:result,accountPublic:owner.accountPublic});return {handle,...result};}
  async ownerInboxList(cap,limit=32,after=null){const owner=this.#owner(cap),result=await this.#ownerCall('OWNER_INBOX_LIST',{ownerToken:owner.token,limit,after});this.#owner(cap);return result;}
  async ownerAcknowledgeInbox(cap,handle){const owner=this.#owner(cap),result=await this.#ownerCall('OWNER_INBOX_ACK',{ownerToken:owner.token,handle});this.#owner(cap);return result;}
  async ownerSubmit(cap,handle,payload){const owner=this.#owner(cap),result=await this.#ownerCall('OWNER_SUBMIT',{ownerToken:owner.token,handle,payload});this.#owner(cap);return result;}
  async retireLocalBinding(cap,handle,expectedGeneration,replacementDigest){const owner=this.#owner(cap),entry=this.#preparations.get(handle);if(!entry||entry.cap!==cap||entry.tuple.generation!==expectedGeneration||entry.tuple.bindingDigest!==replacementDigest)throw Error('Retirement tuple mismatch');const {state,...tuple}=entry.tuple;return this.#ownerCall('OWNER_RETIRE',{ownerToken:owner.token,tuple});}
  connect({url,nodeId,password}){return this.call('CONNECT',{url,nodeId,password});}
  // These key-bearing APIs consume the supplied private byte arrays.
  async bindLocal({certificate,accountSlot,discoverySeed,discoveryBox,recipientKeys=[]}){
   if(this.localOwnership==='managed'){for(const v of [discoverySeed,discoveryBox,...recipientKeys])v?.fill?.(0);throw Error('Legacy binding forbidden in managed mode');}
   if(!Array.isArray(recipientKeys)||recipientKeys.length>2)throw Error('Invalid recipient keys');
   const material=[discoverySeed,discoveryBox,...recipientKeys];
   if(material.some(value=>!(value instanceof Uint8Array)||value.length!==32))throw Error('Invalid local route material');
   const copies=material.map(value=>value.slice());
   try{return await this.call('BIND_LOCAL',{certificate,accountSlot,discoverySeed:copies[0],discoveryBox:copies[1],recipientKeys:copies.slice(2)},copies.map(value=>value.buffer));}
   finally{for(const value of [...material,...copies])if(value.byteLength)value.fill(0);}
  }
  async installRecipientKeys(routeId,recipientKeys){
   if(!Array.isArray(recipientKeys)||recipientKeys.length<1||recipientKeys.length>2||recipientKeys.some(value=>!(value instanceof Uint8Array)||value.length!==32))throw Error('Invalid recipient keys');
   const copies=recipientKeys.map(value=>value.slice());
   try{return await this.call('INSTALL_RECIPIENT_KEYS',{routeId,recipientKeys:copies},copies.map(value=>value.buffer));}
   finally{for(const value of [...recipientKeys,...copies])if(value.byteLength)value.fill(0);}
  }
  discover(certificate){return this.call('DISCOVER',{certificate});}
  submit(handle,payload,replyRouteId){return this.call('SUBMIT',{handle,payload,replyRouteId});}
  inboxList(accountSlot,limit=32,after=null){return this.call('INBOX_LIST',{accountSlot,limit,after});}
  acknowledgeInbox(handle,accountSlot){return this.call('INBOX_ACK',{handle,accountSlot});}
  stats(){return this.call('STATS');}
  injectCoverOnce(size=1024){return this.call('INJECT_COVER',{size});}
  coverPolicy(enabled,policy){return this.call('COVER_POLICY',{enabled,policy});}
  close(){
   if(this.closed)return;this.closed=true;this.#localOwners.clear();this.#preparations.clear();this.#commitVerifier=null;this.cleanup?.();this.cleanup=null;this.rootGuard=null;
   for(const job of this.pending.values()){clearTimeout(job.timer);job.reject(Error('Node worker closed'));}this.pending.clear();
   // Stop can abort nested mining before termination. The bounded termination
   // also works if an unexpectedly busy actor cannot process its next message.
   try{this.#worker.postMessage({id:++this.sequence,type:'STOP'});}catch(_){}
   const worker=this.#worker;this.#worker=null;
   setTimeout(()=>{if(worker){worker.onmessage=null;worker.onerror=null;worker.terminate();}},250);
  }
 }
 global.DmashNodeRuntimeHostV4=NodeRuntimeHostV4;
 if(typeof module!=='undefined')module.exports=NodeRuntimeHostV4;
})(typeof window!=='undefined'?window:globalThis);
