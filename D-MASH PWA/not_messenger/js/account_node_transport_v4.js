'use strict';
(function(global){
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const key=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 const FIELDS=['ownerSlot','routeAuthorityDigest','routeId','migrationId','bindingDigest','generation','preparationDigest','accountPublic'];
 class AccountNodeTransportV4{
  #session;#journal;#sealed;#resolveOwner;#routes=new WeakMap();#peerRoutes=new Map();#routeTasks=new Map();#abort;
  constructor(host,core,storage=global.DMashStorage||global.Storage,options={}){
   if(!host?.ownerDiscover||!host?.verifyPreparation||!host?.ownerSubmitSealed||!core?.captureAccountSessionV4||!options.journal?.readRouteSnapshot||!options.sealedStore?.materialize||typeof options.resolveOwner!=='function')fail('AUTHENTICATED_NODE_ADAPTER_REQUIRED');
   this.host=host;this.closed=false;this.#session=core.captureAccountSessionV4();this.#journal=options.journal;this.#sealed=options.sealedStore;this.#resolveOwner=options.resolveOwner;
   if(this.#session.db!==storage.db||this.#session.masterKey!==storage.masterKey)fail('ACCOUNT_VAULT_MISMATCH');
   this.#abort=()=>this.close();this.#session.signal.addEventListener('abort',this.#abort,{once:true});this.#check();
  }
  #check(){if(this.closed||this.host.closed)fail('ACCOUNT_TRANSPORT_UNAVAILABLE');this.#session.assertCurrent();}
  async #wait(promise){this.#check();const value=await promise;this.#check();return value;}
  async configurePeer(){fail('SIGNED_PAIRING_V2_REQUIRED');}
  async readRouteSnapshot(peer){this.#check();if(!key(peer))fail('ACCOUNT_PEER');return this.#wait(this.#journal.readRouteSnapshot(peer));}
  #ready(snapshot){
   if(!snapshot)fail('ACCOUNT_ROUTE_UPGRADE_REQUIRED');
   if(snapshot.readiness!=='NODE_PROOF_REQUIRED')fail(snapshot.readiness||'ACCOUNT_ROUTE_UNAVAILABLE');
   if(!snapshot.preparation)fail('NODE_PREPARATION_REQUIRED');
  }
  async #validate(data){
   const latest=await this.readRouteSnapshot(data.peer);this.#ready(latest);
   if(latest.digest!==data.snapshot.digest||latest.generation!==data.snapshot.generation||FIELDS.some(name=>latest.preparation[name]!==data.snapshot.preparation[name]))fail('ACCOUNT_ROUTE_CHANGED');
   const proof=await this.#wait(this.host.verifyPreparation(data.owner.preparation,latest.preparation));
   if(!proof||proof.state!=='ACTIVE'||FIELDS.some(name=>proof[name]!==latest.preparation[name]))fail('NODE_ROUTE_NOT_ACTIVE');
   // A root/Account abort during Worker verification must not authorize a send.
   this.#check();return latest;
  }
  #route(route){this.#check();const data=this.#routes.get(route);if(!data)fail('UNVERIFIED_ACCOUNT_ROUTE');return data;}
  async getRoute(peer){
   this.#check();if(!key(peer))fail('ACCOUNT_PEER');
   if(this.#routeTasks.has(peer))return this.#wait(this.#routeTasks.get(peer));
   const task=this.#buildRoute(peer);this.#routeTasks.set(peer,task);
   try{return await this.#wait(task);}finally{if(this.#routeTasks.get(peer)===task)this.#routeTasks.delete(peer);}
  }
  async #buildRoute(peer){
   const snapshot=await this.readRouteSnapshot(peer);if(!snapshot)return null;this.#ready(snapshot);
   const cached=this.#peerRoutes.get(peer),previous=cached&&this.#routes.get(cached);
   if(previous&&previous.snapshot.digest===snapshot.digest&&previous.snapshot.generation===snapshot.generation&&FIELDS.every(name=>previous.snapshot.preparation[name]===snapshot.preparation[name])){await this.#validate(previous);return cached;}
   if(!cached&&this.#peerRoutes.size>=32)fail('ACCOUNT_ROUTE_QUOTA');
   const owner=await this.#wait(this.#resolveOwner(peer,snapshot));if(!owner?.capability||!owner.preparation)fail('LOCAL_OWNER_REQUIRED');
   const data={peer,snapshot,owner,grant:null,task:null};await this.#validate(data);
   const route=Object.freeze({peer,bindingDigest:snapshot.digest,generation:snapshot.generation,routeLocator:snapshot.remoteCertificate.route_id,backRouteLocator:snapshot.localCertificate.route_id});
   this.#routes.set(route,data);this.#peerRoutes.set(peer,route);return route;
  }
  async prepare(route){
   const data=this.#route(route);await this.#validate(data);
   if(!data.grant||data.grant.expiresAt<=Math.floor(Date.now()/1000)){
    if(!data.task){const task=this.#wait(this.host.ownerDiscover(data.owner.capability,data.snapshot.remoteCertificate)).then(grant=>{
     if(!key(grant?.handle)||!Number.isSafeInteger(grant.expiresAt)||grant.expiresAt<=Math.floor(Date.now()/1000))fail('LOCAL_GRANT_INVALID');data.grant=Object.freeze({handle:grant.handle,expiresAt:grant.expiresAt});
    });data.task=task;task.finally(()=>{if(data.task===task)data.task=null;}).catch(()=>{});}
    await this.#wait(data.task);
   }
   await this.#validate(data);return {state:'LOCAL_ROUTE_READY'};
  }
  async submit(route,intent){
   const data=this.#route(route);
   if(!intent||!key(intent.operationId)||intent.peer!==data.peer||intent.bindingDigest!==data.snapshot.digest||intent.generation!==data.snapshot.generation||typeof intent.frame!=='string')fail('AUTHENTICATED_DURABLE_INTENT_REQUIRED');
   const sealed=await this.#wait(this.#sealed.materialize(intent));
   if(sealed.operationId!==intent.operationId||sealed.peer!==intent.peer||sealed.bindingDigest!==intent.bindingDigest||sealed.generation!==intent.generation||sealed.state!=='DURABLE_SEALED_OPERATION')fail('SEALED_INTENT_CONTEXT');
   await this.prepare(route);this.#check();
   try{const result=await this.#wait(this.host.ownerSubmitSealed(data.owner.capability,data.grant.handle,{certificateDigest:sealed.certificateDigest,blob:sealed.blob}));
    if(result?.queued!==true)fail('LOCAL_NODE_REFUSED');return Object.freeze({state:'LOCAL_NODE_QUEUED',queued:true});
   }catch(error){data.grant=null;throw error;}
  }
  async prepareAndSubmitIntent(intent){const route=await this.getRoute(intent?.peer);if(!route)fail('ACCOUNT_ROUTE_UPGRADE_REQUIRED');return this.submit(route,intent);}
  close(){if(this.closed)return;this.closed=true;this.#session.signal.removeEventListener('abort',this.#abort);this.#routes=new WeakMap();this.#peerRoutes.clear();this.#routeTasks.clear();}
 }
 global.DmashAccountNodeTransportV4=AccountNodeTransportV4;
 if(typeof module!=='undefined')module.exports=AccountNodeTransportV4;
})(typeof window!=='undefined'?window:globalThis);
