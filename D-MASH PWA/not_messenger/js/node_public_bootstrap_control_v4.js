'use strict';
// Local public-contact controls. Never invoked on transit ciphertext.
(function(g){
 const text=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
 const canonical=v=>g.DmashSecureSession.canonical(v);
 const unhex=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Public control encoding');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 const hash=async v=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(v))));
 const exact=(v,keys)=>{if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!==keys.split(',').sort().join(','))throw Error('Public control schema');};
 const profiles=Object.freeze(['NODE_TRANSPORT_V4','DMASH_PAIRING_V2']);
 function fits(wire){if(typeof wire!=='string')throw Error('Public control required');const expanded=JSON.stringify({type:'RECIPIENT_PAYLOAD',version:2,packet_id:'0'.repeat(64),payload:wire});if(text(expanded).length+72>16384)throw Error('Public control envelope too large');return wire;}
 function createCodec({pairing,binding,discovery=g.DmashRouteDiscoveryV4,clock=()=>Math.floor(Date.now()/1000)}){
  const requests=new WeakMap(),accepts=new WeakMap(),confirms=new WeakMap();
  function parse(wire,fields,type){fits(wire);const value=JSON.parse(wire);exact(value,fields);if(canonical(value)!==wire||value.type!==type||value.version!==2)throw Error('Public control canonical profile');return value;}
  function dates(value,ceiling){const now=clock();if(!Number.isSafeInteger(value.issued_at)||!Number.isSafeInteger(value.expires_at)||value.issued_at<0||value.issued_at>now+60||value.expires_at<=now||value.expires_at<=value.issued_at||value.expires_at-value.issued_at>86400||value.expires_at>ceiling)throw Error('Public control expiry');}
  const transcript=(kind,body)=>text('D-MASH|PUBLIC-CONTACT|'+kind+'|V2\0'+canonical(body));
  function verify(kind,value,signer){discovery.validateEd25519PublicEncoding(signer);discovery.validateEd25519SignatureEncoding(value.signature);const {signature,...body}=value;if(!g.nacl.sign.detached.verify(transcript(kind,body),Uint8Array.from(signature.match(/../g),x=>parseInt(x,16)),unhex(signer)))throw Error('Public control signature');}
  function sign(kind,body,secret,expected){const keys=g.nacl.sign.keyPair.fromSecretKey(secret);try{if(hex(keys.publicKey)!==expected)throw Error('Public control signer mismatch');return fits(canonical({...body,signature:hex(g.nacl.sign.detached(transcript(kind,body),secret))}));}finally{keys.secretKey.fill(0);}}
  async function inspectRequest(targetCertificate,wire){
   discovery.verifyCertificate(targetCertificate,clock());const value=parse(wire,'type,version,request_id,target_digest,issued_at,expires_at,display_name,introduction,reply_certificate,bootstrap_box,profiles,nonce,signature','CONTACT_REQUEST_V2');
   unhex(value.request_id);unhex(value.nonce);unhex(value.target_digest);discovery.verifyCertificate(value.reply_certificate,clock());discovery.validateX25519PublicKey(value.bootstrap_box);
   if(value.target_digest!==await hash(canonical(targetCertificate))||canonical(value.profiles)!==canonical(profiles))throw Error('Public target/profile mismatch');
   if(typeof value.display_name!=='string'||!text(value.display_name).length||text(value.display_name).length>128||typeof value.introduction!=='string'||text(value.introduction).length>4096)throw Error('Public introduction size');
   dates(value,Math.min(targetCertificate.expires_at,value.reply_certificate.expires_at));verify('REQUEST',value,value.reply_certificate.route_id);
   const handle=Object.freeze({requestId:value.request_id,digest:await hash(wire),expiresAt:value.expires_at,displayName:value.display_name,introduction:value.introduction,identityStatus:'ACCOUNT_NEUTRAL'});requests.set(handle,{value,wire,targetCertificate});return handle;
  }
  async function request(targetCertificate,{requestId,replyCertificate,bootstrapBox,displayName,introduction,nonce,expiresAt},routeSecret){
   const body={type:'CONTACT_REQUEST_V2',version:2,request_id:requestId,target_digest:await hash(canonical(targetCertificate)),issued_at:clock(),expires_at:expiresAt??Math.min(clock()+86400,targetCertificate.expires_at,replyCertificate.expires_at),display_name:displayName,introduction,reply_certificate:replyCertificate,bootstrap_box:bootstrapBox,profiles:[...profiles],nonce};
   const wire=sign('REQUEST',body,routeSecret,replyCertificate.route_id);await inspectRequest(targetCertificate,wire);return wire;
  }
  async function inspectAccept(requestHandle,wire){
   const request=requests.get(requestHandle);if(!request||requestHandle.expiresAt<=clock())throw Error('Public request capability expired');
   const value=parse(wire,'type,version,request_digest,request_id,bundle,bootstrap_box,issued_at,expires_at,signature','CONTACT_ACCEPT_V2');
   if(value.request_digest!==requestHandle.digest||value.request_id!==requestHandle.requestId)throw Error('Public accept context');
   discovery.validateX25519PublicKey(value.bootstrap_box);const offer=pairing.parse(value.bundle,{now:clock()});
   if([offer.bundle.account_keys.box,offer.bundle.inbound_certificate.discovery_box,offer.bundle.inbound_certificate.recipient_box].includes(value.bootstrap_box))throw Error('Fresh public bootstrap box required');
   if(offer.bundle.intended_peer!==null||offer.bundle.generation!==1)throw Error('Public accept must be fresh neutral offer');
   dates(value,Math.min(requestHandle.expiresAt,offer.bundle.expires_at));verify('ACCEPT',value,offer.bundle.account_keys.signing);
   const handle=Object.freeze({requestId:requestHandle.requestId,requestDigest:requestHandle.digest,digest:await hash(wire),accountPublic:offer.bundle.account_keys.signing,expiresAt:value.expires_at,identityStatus:'UNSELECTED_CANDIDATE'});accepts.set(handle,{requestHandle,request,value,wire,offer});return handle;
  }
  async function accept(requestHandle,{bundle,bootstrapBox,expiresAt},accountSecret){
   const request=requests.get(requestHandle);if(!request)throw Error('Public request capability required');const offer=pairing.parse(bundle,{now:clock()});
   const body={type:'CONTACT_ACCEPT_V2',version:2,request_digest:requestHandle.digest,request_id:requestHandle.requestId,bundle,bootstrap_box:bootstrapBox,issued_at:clock(),expires_at:expiresAt??Math.min(requestHandle.expiresAt,offer.bundle.expires_at)};
   const wire=sign('ACCEPT',body,accountSecret,offer.bundle.account_keys.signing);await inspectAccept(requestHandle,wire);return wire;
  }
  async function inspectConfirm(acceptHandle,wire){
   const accepted=accepts.get(acceptHandle);if(!accepted||acceptHandle.expiresAt<=clock())throw Error('Public accept capability expired');
   const value=parse(wire,'type,version,request_digest,accept_digest,bundle,accept_receipt,issued_at,expires_at,signature','CONTACT_CONFIRM_V2');
   if(value.request_digest!==acceptHandle.requestDigest||value.accept_digest!==acceptHandle.digest)throw Error('Public confirm context');
   const offer=pairing.parse(value.bundle,{now:clock(),localAccount:acceptHandle.accountPublic});
   if(offer.bundle.intended_peer!==acceptHandle.accountPublic||offer.bundle.generation!==1)throw Error('Public confirm targeted offer required');
   dates(value,Math.min(acceptHandle.expiresAt,offer.bundle.expires_at));const remote=offer.bundle.account_keys.signing;verify('CONFIRM',value,remote);
   const candidate=await binding.prepare([accepted.value.bundle,value.bundle],{expectedParticipants:[acceptHandle.accountPublic,remote],committed:null});
   if(remote<acceptHandle.accountPublic){if(value.accept_receipt===null)throw Error('Public lower requester needs reserved ACCEPT');binding.verifyReceipt(candidate,value.accept_receipt,'ACCEPT');}else if(value.accept_receipt!==null)throw Error('Public premature binding receipt');
   const handle=Object.freeze({requestId:acceptHandle.requestId,digest:await hash(wire),bindingDigest:candidate.digest,expiresAt:value.expires_at,localAccount:acceptHandle.accountPublic,remoteAccount:remote});confirms.set(handle,{accepted,value,wire,candidate});return handle;
  }
  async function confirm(acceptHandle,{bundle,acceptReceipt=null,expiresAt},accountSecret){
   const accepted=accepts.get(acceptHandle);if(!accepted)throw Error('Public accept capability required');const offer=pairing.parse(bundle,{now:clock(),localAccount:acceptHandle.accountPublic});
   const body={type:'CONTACT_CONFIRM_V2',version:2,request_digest:acceptHandle.requestDigest,accept_digest:acceptHandle.digest,bundle,accept_receipt:acceptReceipt,issued_at:clock(),expires_at:expiresAt??Math.min(acceptHandle.expiresAt,offer.bundle.expires_at)};
   const wire=sign('CONFIRM',body,accountSecret,offer.bundle.account_keys.signing);await inspectConfirm(acceptHandle,wire);return wire;
  }
  function receipt(confirmHandle,wire,phase){const state=confirms.get(confirmHandle);if(!state||confirmHandle.expiresAt<=clock())throw Error('Public confirmed context expired');if(typeof wire!=='string'||text(wire).length>2048)throw Error('Public receipt size');return Object.freeze({...binding.verifyReceipt(state.candidate,wire,phase)});}
  return Object.freeze({request,inspectRequest,accept,inspectAccept,confirm,inspectConfirm,receipt,fits});
 }
 g.DmashNodePublicBootstrapControlV4=Object.freeze({createCodec,fits,profiles});if(typeof module!=='undefined')module.exports=g.DmashNodePublicBootstrapControlV4;
})(globalThis);
