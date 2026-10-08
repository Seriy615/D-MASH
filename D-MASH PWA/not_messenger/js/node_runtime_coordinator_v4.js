'use strict';
(function(global){
 const failure=(code,message)=>Object.assign(new Error(message),{code});
 function descriptor(value){
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!['version','nodeId','url'].includes(key))||value.version!==4||!/^[0-9a-f]{64}$/.test(value.nodeId||''))throw failure('NODE_DESCRIPTOR_INVALID','Explicit v4 descriptor and pinned NodeID required');
  let url;try{url=new URL(value.url);}catch(_){throw failure('NODE_DESCRIPTOR_INVALID','Invalid Node endpoint');}
  if(url.protocol!=='wss:'||url.username||url.password||url.search||url.hash||url.pathname!=='/mesh/v4')throw failure('NODE_DESCRIPTOR_INVALID','Explicit credential-free v4 WSS endpoint required');
  return Object.freeze({version:4,nodeId:value.nodeId,url:url.href});
 }
 class NodeRuntimeCoordinatorV4{
  #root;#factory;#unsubscribe;#job=null;#generation=0;#closed=false;#peers=new Map();
  // trustedDescriptors is an application-owned, independently provisioned catalog
  // snapshot. This constructor does not authenticate a directory or learn pins
  // from sockets. The caller must establish its publisher/OOB trust beforehand.
  constructor(deviceRoot,{trustedDescriptors=[],hostFactory=global.DmashNodeRuntimeHostV4}={}){
   if(typeof deviceRoot?.onLock!=='function'||typeof hostFactory?.startForDevice!=='function')throw failure('NODE_RUNTIME_UNAVAILABLE','Node root lifecycle/host unavailable');
   if(!Array.isArray(trustedDescriptors)||trustedDescriptors.length>32)throw failure('NODE_DESCRIPTOR_INVALID','Node catalog quota exceeded');
   const urls=new Set(),ids=new Set();
   for(const item of trustedDescriptors){const value=descriptor(item);if(urls.has(value.url)||ids.has(value.nodeId))throw failure('NODE_DESCRIPTOR_INVALID','Duplicate Node catalog entry');urls.add(value.url);ids.add(value.nodeId);this.#peers.set(Object.freeze({}),value);}
   this.#root=deviceRoot;this.#factory=hostFactory;
   this.#unsubscribe=deviceRoot.onLock(()=>this.stop());
  }
  peers(){return Object.freeze([...this.#peers].map(([token,value])=>Object.freeze({token,descriptor:value})));}
  #current(job){return !this.#closed&&this.#job===job&&!job.abort.signal.aborted&&this.#root.state===job.session&&!!job.session?.root&&!job.host?.closed;}
  status(){const job=this.#job;return Object.freeze({state:this.#closed?'CLOSED':job&&this.#current(job)?job.host?'READY':'STARTING':'STOPPED',generation:this.#generation});}
  start(){
   if(this.#closed)return Promise.reject(failure('NODE_COORDINATOR_CLOSED','Node coordinator closed'));
   const session=this.#root.state;
   if(!session?.root){this.stop();return Promise.reject(failure('NODE_ROOT_LOCKED','Unlocked local root required'));}
   if(this.#job&&this.#current(this.#job))return this.#job.promise;
   this.stop();
   const job={session,abort:new AbortController(),host:null,token:Object.freeze({}),generation:++this.#generation,connections:new Map(),promise:null};this.#job=job;
   let onAbort;
   const cancelled=new Promise((_,reject)=>{onAbort=()=>reject(failure('NODE_SESSION_CHANGED','Node root session changed'));job.abort.signal.addEventListener('abort',onAbort,{once:true});});
   const started=Promise.resolve().then(()=>{
    if(!this.#current(job))throw failure('NODE_SESSION_CHANGED','Node root session changed');
    return this.#factory.startForDevice(this.#root,{signal:job.abort.signal});
   }).then(host=>{
    if(!this.#current(job)){host?.close();throw failure('NODE_SESSION_CHANGED','Node root session changed');}
    if(!host||host.closed||typeof host.close!=='function'||typeof host.connect!=='function'){host?.close?.();throw failure('NODE_RUNTIME_UNAVAILABLE','Invalid Node host');}
    job.host=host;return host;
   });
   job.promise=Promise.race([started,cancelled]).catch(error=>{
    if(this.#job===job)this.stop();throw error;
   }).finally(()=>job.abort.signal.removeEventListener('abort',onAbort));
   return job.promise;
  }
  capture(){
   const job=this.#job;
   if(!job?.host||!this.#current(job))throw failure('NODE_RUNTIME_UNAVAILABLE','Node runtime not ready');
   // This token identifies a root session. It is not a route/Account owner grant.
   return Object.freeze({host:job.host,token:job.token,generation:job.generation,current:()=>this.#current(job)});
  }
  isCurrentToken(token){const job=this.#job;return !!job?.host&&token===job.token&&this.#current(job);}
  async connect(peerToken,{password}={}){
   const peer=this.#peers.get(peerToken);
   if(!peer)throw failure('NODE_DESCRIPTOR_UNTRUSTED','Registered pinned Node capability required');
   const host=await this.start(),job=this.#job;
   if(!job||host!==job.host||!this.#current(job))throw failure('NODE_SESSION_CHANGED','Node root session changed');
   const existing=job.connections.get(peerToken);
   if(existing){if(existing.password!==password)throw failure('NODE_CONNECT_IN_PROGRESS','Node connection with different credential already pending');return existing.task;}
   let onAbort;
   const cancelled=new Promise((_,reject)=>{onAbort=()=>reject(failure('NODE_SESSION_CHANGED','Node root session changed'));job.abort.signal.addEventListener('abort',onAbort,{once:true});});
   const operation=Promise.resolve().then(()=>{if(!this.#current(job))throw failure('NODE_SESSION_CHANGED','Node root session changed');return host.connect({url:peer.url,nodeId:peer.nodeId,password});}).then(result=>{if(!this.#current(job))throw failure('NODE_SESSION_CHANGED','Node root session changed');return result;});
   const entry={password,task:null};
   entry.task=Promise.race([operation,cancelled]).finally(()=>{job.abort.signal.removeEventListener('abort',onAbort);if(job.connections.get(peerToken)===entry)job.connections.delete(peerToken);entry.password=undefined;});
   job.connections.set(peerToken,entry);return entry.task;
  }
  stop(){
   const job=this.#job;if(!job)return;this.#job=null;++this.#generation;
   job.abort.abort();job.host?.close();job.connections.clear();
  }
  close(){if(this.#closed)return;this.#closed=true;this.stop();this.#unsubscribe?.();this.#unsubscribe=null;this.#peers.clear();}
 }
 global.DmashNodeRuntimeCoordinatorV4=NodeRuntimeCoordinatorV4;
 if(typeof module!=='undefined')module.exports=NodeRuntimeCoordinatorV4;
})(typeof window!=='undefined'?window:globalThis);
