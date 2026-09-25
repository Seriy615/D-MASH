'use strict';
(function(global){
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 function sealPayload(recipientPublic,payload){
  if(typeof payload!=='string')throw Error('Opaque Account payload must be a string');
  return global.DmashRouteDiscoveryV4.seal(recipientPublic,{type:'RECIPIENT_PAYLOAD',version:2,packet_id:hex(crypto.getRandomValues(new Uint8Array(32))),payload});
 }
 function openPayload(privateKeys,blob){
  if(privateKeys==null||(Array.isArray(privateKeys)&&privateKeys.length===0))return {status:'deferred'};
  if(!Array.isArray(privateKeys)||privateKeys.length>2||privateKeys.some(key=>!(key instanceof Uint8Array)||key.length!==32))throw Error('Invalid recipient key set');
  if(!global.nacl?.box?.open||!global.DmashRouteDiscoveryV4)throw Error('Recipient crypto unavailable');
  for(const key of privateKeys){
   let value;try{value=global.DmashRouteDiscoveryV4.openBox(key,blob);}catch(_){continue;}
   if(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')==='packet_id,payload,type,version'&&value.type==='RECIPIENT_PAYLOAD'&&value.version===2&&typeof value.packet_id==='string'&&/^[0-9a-f]{64}$/.test(value.packet_id)&&typeof value.payload==='string')return {status:'accepted',packet_id:value.packet_id,payload:value.payload};
  }
  return {status:'discard'};
 }
 function coverBox(size=1024){
  if(!Number.isInteger(size)||size<256||size>16384)throw Error('Invalid cover size');
  const ephemeral=global.nacl.box.keyPair();
  try{const bytes=crypto.getRandomValues(new Uint8Array(size));bytes.set(ephemeral.publicKey);return btoa(String.fromCharCode(...bytes));}
  finally{ephemeral.secretKey.fill(0);}
 }
 const api=Object.freeze({sealPayload,openPayload,coverBox});global.DmashRecipientPayloadV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
