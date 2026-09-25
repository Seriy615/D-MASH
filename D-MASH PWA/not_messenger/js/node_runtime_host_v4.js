'use strict';
(function(global){
 const source=global.document?.currentScript?.src,owners=new WeakMap();
 class NodeRuntimeHostV4{
  static async startForDevice(deviceRoot,{signal,credential=null}={}){
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
    host=await this.startMaterials({seed,storageKey,baseNcrh,credential},{signal:abort.signal});
    const cleanup=host.cleanup;
    host.cleanup=()=>{cleanup?.();unsubscribe();release();signal?.removeEventListener('abort',cancel);};
    host.rootGuard=current;
    if(!current())throw Error('Device session changed');return host;
   }catch(error){cancel();unsubscribe();release();signal?.removeEventListener('abort',cancel);throw error;}
   finally{for(const key of [identity?.signing.secretKey,seed,storageKey,baseNcrh])if(key?.byteLength)key.fill(0);}
  }
  static async startMaterials({seed,storageKey,baseNcrh,credential=null},{signal}={}){
   const material=[seed,storageKey,baseNcrh,...(credential?[credential.key]:[])];
   if(!source||!global.Worker||material.some(key=>!(key instanceof Uint8Array)||key.length!==32))throw Error('Invalid Node worker materials');
   if(signal?.aborted)throw Error('Node worker cancelled');
   const copies=material.map(key=>key.slice());
   const host=new NodeRuntimeHostV4();host.closed=false;host.pending=new Map();host.sequence=0;
   try{
   host.worker=new Worker(new URL('node_runtime_worker_v4.js',source));
   host.worker.onmessage=({data})=>{
    if(host.closed)return;if(host.rootGuard&&!host.rootGuard()){host.close();return;}const job=host.pending.get(data?.id);if(!job)return;
    host.pending.delete(data.id);clearTimeout(job.timer);
    if(data.ok)job.resolve(data.result);else job.reject(Error('Node worker operation failed'));
   };
   host.worker.onerror=()=>host.close();
   const cancel=()=>host.close();signal?.addEventListener('abort',cancel,{once:true});
   host.cleanup=()=>signal?.removeEventListener('abort',cancel);
    host.identity=await host.call('INIT',{seed:copies[0],storageKey:copies[1],baseNcrh:copies[2],
     credential:credential?{profile:credential.profile,salt:credential.salt,epoch:credential.epoch,key:copies[3]}:null},copies.map(key=>key.buffer));
    if(signal?.aborted||host.closed)throw Error('Node worker cancelled');return host;
   }catch(error){host.close();throw error;}
   finally{for(const key of [...material,...copies])if(key.byteLength)key.fill(0);}
  }
  call(type,fields={},transfer=[]){
   if(this.rootGuard&&!this.rootGuard())this.close();
   if(this.closed)return Promise.reject(Error('Node worker closed'));
   if(this.pending.size>=16)return Promise.reject(Error('Node worker request quota'));
   const id=++this.sequence;
   return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{this.pending.delete(id);reject(Error('Node worker operation expired'));this.close();},type==='CONNECT'?310000:type==='DISCOVER'?190000:30000);
    this.pending.set(id,{resolve,reject,timer});
    try{this.worker.postMessage({id,type,...fields},transfer);}catch(error){clearTimeout(timer);this.pending.delete(id);reject(error);}
   });
  }
  connect({url,nodeId,password}){return this.call('CONNECT',{url,nodeId,password});}
  // These key-bearing APIs consume the supplied private byte arrays.
  async bindLocal({certificate,accountSlot,discoverySeed,discoveryBox,recipientKeys=[]}){
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
  inboxList(accountSlot,limit=32){return this.call('INBOX_LIST',{accountSlot,limit});}
  acknowledgeInbox(handle,accountSlot){return this.call('INBOX_ACK',{handle,accountSlot});}
  stats(){return this.call('STATS');}
  injectCoverOnce(size=1024){return this.call('INJECT_COVER',{size});}
  coverPolicy(enabled,policy){return this.call('COVER_POLICY',{enabled,policy});}
  close(){
   if(this.closed)return;this.closed=true;this.cleanup?.();this.cleanup=null;this.rootGuard=null;
   for(const job of this.pending.values()){clearTimeout(job.timer);job.reject(Error('Node worker closed'));}this.pending.clear();
   // Stop can abort nested mining before termination. The bounded termination
   // also works if an unexpectedly busy actor cannot process its next message.
   try{this.worker.postMessage({id:++this.sequence,type:'STOP'});}catch(_){}
   const worker=this.worker;this.worker=null;
   setTimeout(()=>{if(worker){worker.onmessage=null;worker.onerror=null;worker.terminate();}},250);
  }
 }
 global.DmashNodeRuntimeHostV4=NodeRuntimeHostV4;
 if(typeof module!=='undefined')module.exports=NodeRuntimeHostV4;
})(typeof window!=='undefined'?window:globalThis);
