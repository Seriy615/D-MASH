'use strict';
(function(g){
 // Provisioned EMS service identity/endpoint, never learned from invitations.
 const provision=Object.freeze({nodeId:'3e4a0e3f796f8d594e5473249f49460c769bfdd293b4788cdaf78bc314f12b17',signalingWss:'wss://proxy.d-mash.ru/signal/v1'});
 function create(coordinator){let selected=null;const clock=()=>Math.floor(Date.now()/1000);
  async function select({file=false}={}){selected=null;const capture=coordinator.capture();if(!capture.current())throw Error('NODE_SESSION_CHANGED');const descriptor=await capture.host.serviceDescriptor(provision);if(!capture.current())throw Error('NODE_SESSION_CHANGED');if(descriptor.issuer!==provision.nodeId||descriptor.signaling_wss!==provision.signalingWss||descriptor.expires_at<=clock()||!descriptor.can_s_turn||file&&!descriptor.can_relay_blob)throw Error('NODE_STURN_UNAVAILABLE');selected={descriptor,capture};return provision.signalingWss;}
  function verifyService(service,{file=false}={}){const s=selected;if(!s||!s.capture.current()||s.descriptor.expires_at<=clock()||service.nodeId!==provision.nodeId||service.wssEndpoint!==provision.signalingWss||!s.descriptor.can_s_turn||file&&!s.descriptor.can_relay_blob)return false;return true;}
  return Object.freeze({select,verifyService,provision:()=>provision,clear(){selected=null;}});
 }
 g.DmashNodeSTurnServiceV4=Object.freeze({create,provision});if(typeof module!=='undefined')module.exports=g.DmashNodeSTurnServiceV4;
})(globalThis);
