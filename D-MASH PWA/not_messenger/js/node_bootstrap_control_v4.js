'use strict';
// Local recipient control parser. No Account private key is retained; no transit
// path calls this parser. REQUEST identity remains a candidate until selection.
(function(g){
 const text=v=>new TextEncoder().encode(v),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),unhex=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Invalid bootstrap digest');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 const fields=['type','version','exchange_id','target_bundle_digest','bundle','accept_receipt','expires_at','signature'];
 const canonical=v=>g.DmashSecureSession.canonical(v),hash=async v=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(v))));
 // Exact envelope expansion, including JSON escaping, is checked BEFORE mining.
 function fits(payload){if(typeof payload!=='string')throw Error('Bootstrap payload required');const envelope=JSON.stringify({type:'RECIPIENT_PAYLOAD',version:2,packet_id:'0'.repeat(64),payload});if(text(envelope).length+72>16384)throw Error('Bootstrap recipient envelope too large');return payload;}
 function createCodec({pairing,binding,discovery=g.DmashRouteDiscoveryV4,clock=()=>Math.floor(Date.now()/1000)}){
  const verified=new WeakMap();
  function exact(v){if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!==[...fields].sort().join(','))throw Error('Bootstrap REQUEST schema');}
  const signedBytes=body=>text('D-MASH|NODE-BOOTSTRAP-REQUEST|V4\0'+canonical(body));
  async function inspect(localBundle,serialized){
   fits(serialized);const request=JSON.parse(serialized);exact(request);if(canonical(request)!==serialized)throw Error('Noncanonical bootstrap REQUEST');
   const now=clock();if(request.type!=='NODE_BOOTSTRAP_REQUEST_V4'||request.version!==4||!Number.isSafeInteger(request.expires_at)||request.expires_at<=now||request.expires_at>now+86400)throw Error('Bootstrap REQUEST expiry/profile');
   unhex(request.exchange_id);unhex(request.target_bundle_digest);
   if(await hash(localBundle)!==request.target_bundle_digest)throw Error('Wrong bootstrap target');
   const local=pairing.parse(localBundle,{now}),localAccount=local.bundle.account_keys.signing;
   const remote=pairing.parse(request.bundle,{now,localAccount}),remoteAccount=remote.bundle.account_keys.signing;
   if(request.expires_at>Math.min(local.bundle.expires_at,remote.bundle.expires_at))throw Error('Bootstrap request outlives offer');
   if(local.bundle.generation!==1||remote.bundle.generation!==1)throw Error('Existing-contact recovery requires separate authority');
   const {signature,...body}=request;discovery.validateEd25519SignatureEncoding(signature);
   if(!g.nacl.sign.detached.verify(signedBytes(body),Uint8Array.from(signature.match(/../g),x=>parseInt(x,16)),unhex(remoteAccount)))throw Error('Bootstrap REQUEST signature');
   const candidate=await binding.prepare([localBundle,request.bundle],{expectedParticipants:[localAccount,remoteAccount],committed:null});
   if(remote.bundle.intended_peer!==localAccount)throw Error('Requester bundle must target local offer owner');
   if(remoteAccount<localAccount&&request.accept_receipt===null)throw Error('Lower requester must include durable ACCEPT receipt');
   if(request.accept_receipt!==null){if(remoteAccount>localAccount)throw Error('Premature receipt phase');binding.verifyReceipt(candidate,request.accept_receipt,'ACCEPT');}
   const result=Object.freeze({exchangeId:request.exchange_id,requestDigest:await hash(serialized),bindingDigest:candidate.digest,localAccount,remoteAccount,expiresAt:request.expires_at,identityStatus:'UNSELECTED_CANDIDATE'});
   verified.set(result,{request,candidate,localBundle});return result;
  }
  async function request(localTargetBundle,senderBundle,exchangeId,secretKey,{acceptReceipt=null,expiresAt}={}){
   const target=pairing.parse(localTargetBundle,{now:clock()}),sender=pairing.parse(senderBundle,{now:clock(),localAccount:target.bundle.account_keys.signing});
   const signer=g.nacl.sign.keyPair.fromSecretKey(secretKey);try{if(hex(signer.publicKey)!==sender.bundle.account_keys.signing)throw Error('Request signer mismatch');}finally{signer.secretKey.fill(0);}
   const body={type:'NODE_BOOTSTRAP_REQUEST_V4',version:4,exchange_id:exchangeId,target_bundle_digest:await hash(localTargetBundle),bundle:senderBundle,accept_receipt:acceptReceipt,expires_at:expiresAt??Math.min(target.bundle.expires_at,sender.bundle.expires_at)};
   const wire=fits(canonical({...body,signature:hex(g.nacl.sign.detached(signedBytes(body),secretKey))}));await inspect(localTargetBundle,wire);return wire;
  }
  function receipt(handle,serialized,phase){const state=verified.get(handle);if(!state||handle.expiresAt<=clock())throw Error('Bootstrap candidate unavailable');if(typeof serialized!=='string'||text(serialized).length>2048)throw Error('Bootstrap receipt size');const value=binding.verifyReceipt(state.candidate,serialized,phase);return Object.freeze({...value});}
  async function localOffer(serialized,owner){
   if(typeof serialized!=='string'||text(serialized).length>12288)throw Error('Bootstrap bundle size');
   const raw=JSON.parse(serialized),checked=pairing.parse(serialized,{now:clock(),expectedPeer:owner.accountPublic,localAccount:raw.intended_peer??undefined});
   if(checked.bundle.inbound_certificate.route_id!==owner.routeId||await hash(canonical(checked.bundle.inbound_certificate))!==owner.routeAuthorityDigest)throw Error('Bootstrap local certificate authority mismatch');
   return Object.freeze({expiresAt:checked.bundle.expires_at});
  }
  return Object.freeze({inspect,request,receipt,localOffer,fits});
 }
 g.DmashNodeBootstrapControlV4=Object.freeze({createCodec,fits});if(typeof module!=='undefined')module.exports=g.DmashNodeBootstrapControlV4;
})(globalThis);
