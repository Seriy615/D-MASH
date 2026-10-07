'use strict';
(function(global){
 class AccountNodeTransportV4{
  constructor(host,core){
   if(!host?.discover||!host?.submit||!core)throw Error('Local Node transport unavailable');
   this.host=host;this.core=core;this.closed=false;this.routes=new WeakMap();
  }
  capture(){
   const core=this.core,keys=core.keys,salt=core.blindSalt,slot=core.activeIdentity;
   const current=()=>!this.closed&&!this.host.closed&&!core._accountTransitioning&&
    core.keys===keys&&core.blindSalt===salt&&core.activeIdentity===slot;
   if(!keys?.sign||!salt||typeof slot!=='string'||!slot||!current())throw Error('Account unavailable');
   return {keys,slot,current};
  }
  check(session){if(!session.current())throw Error('Account session changed');}
  async configurePeer(peerId,certificate,localRouteId){
   const session=this.capture();
   if(!/^[0-9a-f]{64}$/.test(peerId||'')||!/^[0-9a-f]{64}$/.test(localRouteId||''))throw Error('Invalid Account route mapping');
   global.DmashRouteDiscoveryV4.verifyCertificate(certificate);
   certificate={...certificate};
   const inbound=await global.Storage.getAlias('node-route-v4:'+localRouteId,'L2');this.check(session);
   const previous=await global.Storage.getBox('pairing_material',inbound);this.check(session);
   if(previous&&previous.peerId!==peerId)throw Error('Local route already belongs to another peer');
   const outbound=await global.Storage.getAlias('node-peer-v4:'+peerId,'L2');this.check(session);
   await global.Storage.putBox('pairing_material',{alias:inbound,data:{peerId}});this.check(session);
   await global.Storage.putBox('pairing_material',{alias:outbound,data:{certificate,localRouteId}});this.check(session);
   this.routes.get(session.keys)?.delete(peerId);
   return this.getRoute(peerId);
  }
  async getRoute(peerId){
   const session=this.capture();
   if(!/^[0-9a-f]{64}$/.test(peerId||''))throw Error('Invalid Account peer');
   let routes=this.routes.get(session.keys);
   if(!routes){routes=new Map();this.routes.set(session.keys,routes);}
   const cached=routes.get(peerId);
   if(cached&&cached.session.current())return cached;
   const alias=await global.Storage.getAlias('node-peer-v4:'+peerId,'L2');this.check(session);
   const saved=await global.Storage.getBox('pairing_material',alias);this.check(session);
   if(!saved)return null;
   global.DmashRouteDiscoveryV4.verifyCertificate(saved.certificate);
   if(!/^[0-9a-f]{64}$/.test(saved.localRouteId||''))throw Error('Invalid local reply route');
   const route={session,certificate:Object.freeze({...saved.certificate}),localRouteId:saved.localRouteId,
    routeLocator:saved.certificate.route_id,backRouteLocator:saved.localRouteId,grant:null,task:null};
   routes.set(peerId,route);return route;
  }
  async prepare(route){
   this.check(route.session);
   global.DmashRouteDiscoveryV4.verifyCertificate(route.certificate);
   if(route.grant?.expiresAt>Math.floor(Date.now()/1000))return {state:'LOCAL_ROUTE_READY'};
   if(!route.task){
    const task=this.host.discover({...route.certificate}).then(grant=>{
     this.check(route.session);
     if(!/^[0-9a-f]{64}$/.test(grant?.handle||'')||!Number.isSafeInteger(grant.expiresAt)||grant.expiresAt<=Math.floor(Date.now()/1000))throw Error('Invalid local route grant');
     route.grant={handle:grant.handle,expiresAt:grant.expiresAt};
    });
    route.task=task;task.finally(()=>{if(route.task===task)route.task=null;}).catch(()=>{});
   }
   await route.task;this.check(route.session);return {state:'LOCAL_ROUTE_READY'};
  }
  async submit(route,envelope){
   this.check(route.session);
   if(!envelope||envelope.version!==1||!/^(?:[0-9a-f]{2})+$/.test(envelope.ciphertext||'')||!/^[0-9a-f]{128}$/.test(envelope.sender_proof||''))throw Error('Invalid Account envelope');
   const payload=JSON.stringify(envelope);
   if(new TextEncoder().encode(payload).length>16000)throw Error('Account envelope exceeds local payload bound');
   await this.prepare(route);this.check(route.session);
   try{
    const result=await this.host.submit(route.grant.handle,payload,route.localRouteId);
    this.check(route.session);
    if(result?.queued!==true)throw Error('Local Node refused Account packet');
    return {state:'LOCAL_NODE_QUEUED'};
   }catch(error){route.grant=null;throw error;}
  }
  close(){this.closed=true;this.routes=new WeakMap();}
 }
 global.DmashAccountNodeTransportV4=AccountNodeTransportV4;
 if(typeof module!=='undefined')module.exports=AccountNodeTransportV4;
})(typeof window!=='undefined'?window:globalThis);
