'use strict';
(function(g){
 // Provisioned from EMS signing public key through the authenticated SSH
 // management path on 2026-10-08. Never derive this pin from a socket or v3 URL.
 const entries=Object.freeze([Object.freeze({version:4,nodeId:'3e4a0e3f796f8d594e5473249f49460c769bfdd293b4788cdaf78bc314f12b17',url:'wss://proxy.d-mash.ru/mesh/v4'})]);
 const coordinators=new WeakMap();
 function coordinator(root){
  if(!root||typeof root.onLock!=='function')throw Error('NODE_ROOT_REQUIRED');
  let value=coordinators.get(root);if(value?.status().state==='CLOSED')value=null;
  if(!value){if(typeof g.DmashNodeRuntimeCoordinatorV4!=='function')throw Error('NODE_COORDINATOR_UNAVAILABLE');value=new g.DmashNodeRuntimeCoordinatorV4(root,{trustedDescriptors:entries,localOwnership:'managed',bootstrapProfile:'public-v1'});coordinators.set(root,value);}
  return value;
 }
 function mount(container,{deviceRoot,onReady=()=>{}}={}){
  if(!container?.ownerDocument||typeof onReady!=='function')throw Error('NODE_VIEW_CONTEXT');
  const doc=container.ownerDocument,section=doc.createElement('section'),title=doc.createElement('p'),status=doc.createElement('p'),connect=doc.createElement('button');
  title.textContent='EMS staging · Node v4';status.textContent='Не подключено';status.setAttribute('role','status');connect.type='button';connect.textContent='Подключить Node';connect.dataset.dmashManagedNodeConnect='';section.append(title,status,connect);container.append(section);
  let disposed=false,pending=false;const unsubscribe=deviceRoot?.onLock?.(()=>{if(!disposed)status.textContent='Node заблокирована';});
  const click=async()=>{
   if(disposed||pending)return;pending=true;connect.disabled=true;status.textContent='Подключение…';
   try{
    const runtime=coordinator(deviceRoot),host=await runtime.start(),capture=runtime.capture();
    for(const peer of runtime.peers())await runtime.connect(peer.token);
    if(!capture.current()||capture.host!==host)throw Error('NODE_SESSION_CHANGED');
    if(!disposed){status.textContent='Node подключена';await onReady(Object.freeze({coordinator:runtime,host}));}
   }catch(error){if(!disposed)status.textContent='Подключение недоступно: '+String(error.code||error.message||'NODE_UNAVAILABLE');}
   finally{pending=false;if(!disposed)connect.disabled=false;}
  };
  connect.addEventListener('click',click);
  return Object.freeze({close(){if(disposed)return;disposed=true;unsubscribe?.();connect.removeEventListener('click',click);section.remove();}});
 }
 const api=Object.freeze({entries:()=>entries,coordinator,mount});g.DmashManagedNodeCatalogV4=api;if(typeof module!=='undefined')module.exports=api;
})(globalThis);
