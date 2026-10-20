'use strict';
(function(g){
 const installed=new WeakMap();
 function attach(root,catalog=g.DmashManagedNodeCatalogV4){
  if(typeof root?.onUnlock!=='function'||typeof root.onLock!=='function'||typeof catalog?.coordinator!=='function')throw Error('NODE_ROOT_LIFECYCLE_UNAVAILABLE');
  if(installed.has(root))return installed.get(root);
  let closed=false,job=null,generation=0,state='LOCKED',error=null;
  const stop=()=>{generation++;job=null;state='LOCKED';error=null;};
  const start=()=>{
   if(closed)return Promise.reject(Error('NODE_ROOT_LIFECYCLE_CLOSED'));
   if(!root.state?.root)return Promise.reject(Error('NODE_ROOT_LOCKED'));
   if(job?.session===root.state)return job.promise;
   const session=root.state,epoch=++generation,entry={session,promise:null};job=entry;state='STARTING';error=null;
   const current=()=>!closed&&job===entry&&generation===epoch&&root.state===session&&!!session.root;
   entry.promise=Promise.resolve().then(async()=>{
    if(!current())throw Error('NODE_SESSION_CHANGED');
    const coordinator=catalog.coordinator(root);await coordinator.start();
    if(!current())throw Error('NODE_SESSION_CHANGED');
    for(const peer of coordinator.peers()){await coordinator.connect(peer.token);if(!current())throw Error('NODE_SESSION_CHANGED');}
    state='READY';return coordinator.capture();
   }).catch(cause=>{if(current()){job=null;state='UNAVAILABLE';error=String(cause.code||cause.message||'NODE_UNAVAILABLE');}throw cause;});
   return entry.promise;
  };
  const unlocked=()=>{void start().catch(()=>{});};
  const offUnlock=root.onUnlock(unlocked),offLock=root.onLock(stop);
  const api=Object.freeze({start,status:()=>Object.freeze({state,error}),close(){if(closed)return;closed=true;offUnlock();offLock();stop();state='CLOSED';}});
  installed.set(root,api);if(root.state?.root)unlocked();return api;
 }
 g.DmashNodeRootLifecycleV4=Object.freeze({attach});
 // DeviceRoot is loaded lazily by the shell. Install once its genuine lifecycle
 // and the independently pinned catalog exist, without waiting for an Account.
 function install(){if(g.DMASH_NODE_PROFILE!=='managed-v4')return true;if(!g.DeviceRoot||!g.DmashManagedNodeCatalogV4)return false;attach(g.DeviceRoot);return true;}
 if(g.DmashRuntimeReadiness){let ready=false;g.DmashRuntimeReadiness.register('node-root-lifecycle',90,()=>{ready=install();},()=>ready,['acceptance-v51']);return;}
 if(typeof document!=='undefined'&&!install()){const timer=setInterval(()=>{if(install())clearInterval(timer);},250);}
 if(typeof module!=='undefined')module.exports=g.DmashNodeRootLifecycleV4;
})(globalThis);
