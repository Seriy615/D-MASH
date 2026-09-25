'use strict';
(function(global){
 const MAX_HOPS=15,DEFAULT_MIN_HOPS=4;
 const bytes32=(value,name)=>{if(!(value instanceof Uint8Array)||value.length!==32)throw Error('Invalid '+name);return value;};
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 async function derive(base,domain,value){
  bytes32(base,'BaseNCRH');bytes32(value,'NCRH input');
  const prefix=new TextEncoder().encode('D-MASH|NCRH|V4|'+domain+'\0');
  const message=new Uint8Array(prefix.length+32);message.set(prefix);message.set(value,prefix.length);
  const key=await crypto.subtle.importKey('raw',base,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC',key,message)));
 }
 function routeNcrh(base,routeId){return derive(base,'ROUTE',routeId);}
 function extendNcrh(base,incoming){
  if(typeof incoming!=='string'||!/^[0-9a-f]{64}$/.test(incoming))throw Error('Invalid NCRH');
  return derive(base,'HOP',Uint8Array.from(incoming.match(/../g),b=>parseInt(b,16)));
 }
 function sampleHopTtl(minimum=DEFAULT_MIN_HOPS,maximum=MAX_HOPS){
  if(!Number.isInteger(minimum)||!Number.isInteger(maximum)||minimum<1||minimum>=maximum||maximum>MAX_HOPS)throw Error('Invalid random hop range');
  const width=maximum-minimum+1,limit=Math.floor(0x100000000/width)*width;
  const sample=new Uint32Array(1);
  do{crypto.getRandomValues(sample);}while(sample[0]>=limit);
  return minimum+sample[0]%width;
 }
 function consumeHop(ttl){
  if(!Number.isInteger(ttl)||ttl<1||ttl>MAX_HOPS)throw Error('Invalid hop TTL');
  return ttl-1;
 }
 const api=Object.freeze({MAX_HOPS,DEFAULT_MIN_HOPS,routeNcrh,extendNcrh,sampleHopTtl,consumeHop});
 global.DmashProbePrimitivesV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
