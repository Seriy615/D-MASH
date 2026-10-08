'use strict';
(function(global){
 const RECEIPT_FIELDS=['type','version','phase','binding_digest','signer','signature'];
 const CERT_FIELDS=['version','route_id','discovery_sign','discovery_box','recipient_box','generation','issued_at','expires_at','signature'];
 const MAX_BINDING=4096,MAX_RECEIPT=2048,MAX_BUNDLE=12288;
 const text=value=>new TextEncoder().encode(value);
 const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const unhex=(value,size=32)=>{if(typeof value!=='string'||!new RegExp('^[0-9a-f]{'+size*2+'}$').test(value))fail('ENCODING');return Uint8Array.from(value.match(/../g),b=>parseInt(b,16));};
 const integer=value=>{if(!Number.isSafeInteger(value)||value<0||Object.is(value,-0))fail('INTEGER');};
 const join=(a,b)=>{const out=new Uint8Array(a.length+b.length);out.set(a);out.set(b,a.length);return out;};
 function exact(value,keys){
  if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('SCHEMA');
  const actual=Reflect.ownKeys(value);
  if(actual.length!==keys.length||actual.some(k=>!keys.includes(k)))fail('SCHEMA');
  for(const key of actual)if(!Object.hasOwn(Object.getOwnPropertyDescriptor(value,key),'value'))fail('SCHEMA');
 }
 function participants(value){
  if(!Array.isArray(value)||value.length!==2)fail('PARTICIPANTS');
  const copy=value.map(key=>{unhex(key);return key;}).sort();
  if(copy[0]===copy[1])fail('SELF_PAIRING');return copy;
 }
 function committedSnapshot(value){
  if(value===null)return null;
  exact(value,['generation','binding_digest','participants']);integer(value.generation);
  if(value.generation<1)fail('GENERATION');unhex(value.binding_digest);
  return Object.freeze({generation:value.generation,binding_digest:value.binding_digest,participants:Object.freeze(participants(value.participants))});
 }
 function createBindingCodec({nacl,discovery,pairing,subtle=global.crypto?.subtle,clock=()=>Math.floor(Date.now()/1000)}){
  if(!nacl?.sign?.detached?.verify||!discovery?.validateEd25519SignatureEncoding||!discovery?.validateEd25519PublicEncoding||!pairing?.parse||!subtle?.digest)fail('DEPENDENCY');
  const prepared=new WeakMap();
  const now=()=>{const value=clock();integer(value);return value;};
  const digest=async bytes=>hex(new Uint8Array(await subtle.digest('SHA-256',bytes)));
  function current(candidate){const data=prepared.get(candidate);if(!data)fail('UNVERIFIED_BINDING');if(data.binding.expires_at<=now())fail('EXPIRED');return data;}
  function checkGeneration(data,committed){
   const binding=data.binding,ids=binding.participants.map(p=>p.account);
   if(committed===null){if(binding.generation!==1||binding.previous_binding!==null)fail('PREDECESSOR_REQUIRED');return 'BILATERAL_CANDIDATE';}
   if(ids.some((id,i)=>id!==committed.participants[i]))fail('IDENTITY_MISMATCH');
   if(binding.generation<committed.generation)fail('GENERATION_ROLLBACK');
   if(binding.generation===committed.generation){if(data.digest!==committed.binding_digest)fail('GENERATION_CONFLICT');return 'IDEMPOTENT_REPLAY';}
   if(binding.previous_binding!==committed.binding_digest)fail('PREDECESSOR_MISMATCH');
   return 'BILATERAL_CANDIDATE';
  }
  async function prepare(serializedBundles,context){
   if(!Array.isArray(serializedBundles)||serializedBundles.length!==2)fail('BUNDLES');
   if(!context||!Object.hasOwn(context,'committed'))fail('COMMITTED_CONTEXT_REQUIRED');
   const expected=participants(context.expectedParticipants),committed=committedSnapshot(context.committed),checkedAt=now();
   const verified=serializedBundles.map(serialized=>{
    if(typeof serialized!=='string'||serialized.length>MAX_BUNDLE||text(serialized).length>MAX_BUNDLE)fail('SIZE');
    let raw;try{raw=JSON.parse(serialized);}catch{fail('JSON');}
    const index=expected.indexOf(raw?.account_keys?.signing);if(index<0)fail('IDENTITY_MISMATCH');
    return pairing.parse(serialized,{now:checkedAt,expectedPeer:expected[index],localAccount:expected[1-index]});
   }).sort((a,b)=>a.bundle.account_keys.signing<b.bundle.account_keys.signing?-1:1);
   const [a,b]=verified.map(v=>v.bundle);
   if(a.account_keys.signing===b.account_keys.signing)fail('SELF_PAIRING');
   if(a.generation!==b.generation||a.previous_binding!==b.previous_binding)fail('BINDING_CONTEXT');
   if(a.account_keys.kem_profile!==b.account_keys.kem_profile)fail('PROFILE');
   if(a.generation>1&&(a.intended_peer===null||b.intended_peer===null))fail('TARGET_REQUIRED');
   if(a.account_keys.kem_public===b.account_keys.kem_public)fail('KEY_ROLE_REUSE');
   if(a.pairing_id===b.pairing_id||a.contribution===b.contribution)fail('DUPLICATE_OFFER');
   const roles=[a,b].flatMap(v=>[v.account_keys.signing,v.account_keys.box,v.inbound_certificate.route_id,v.inbound_certificate.discovery_sign,v.inbound_certificate.discovery_box,v.inbound_certificate.recipient_box]);
   if(new Set(roles).size!==roles.length)fail('KEY_ROLE_REUSE');
   const members=await Promise.all(verified.map(async v=>Object.freeze({
    account:v.bundle.account_keys.signing,
    bundle_digest:await digest(text(v.serialized)),
    contribution:v.bundle.contribution,
    certificate_digest:await digest(text(JSON.stringify(Object.fromEntries(CERT_FIELDS.map(k=>[k,v.bundle.inbound_certificate[k]])))))
   })));
   const binding=Object.freeze({type:'DMASH_ACCOUNT_ROUTE_BINDING_V2',version:2,transport_version:4,kem_profile:a.account_keys.kem_profile,generation:a.generation,previous_binding:a.previous_binding,participants:Object.freeze(members),expires_at:Math.min(a.expires_at,b.expires_at)});
   const serialized=JSON.stringify(binding);if(text(serialized).length>MAX_BINDING)fail('SIZE');
   const bindingDigest=await digest(join(text('D-MASH|ACCOUNT-ROUTE-BINDING|V2\0'),text(serialized)));
   // No mutable Account/root/storage authority is retained across these awaits.
   const finishedAt=now();for(const v of verified)pairing.parse(v.serialized,{now:finishedAt,expectedPeer:v.bundle.account_keys.signing,localAccount:expected.find(id=>id!==v.bundle.account_keys.signing)});
   const data={binding,digest:bindingDigest,serialized};checkGeneration(data,committed);
   const candidate=Object.freeze({binding,digest:bindingDigest,serialized,status:'UNSIGNED_CANDIDATE'});
   prepared.set(candidate,data);return candidate;
  }
  function receiptBody(receipt){return JSON.stringify(Object.fromEntries(RECEIPT_FIELDS.slice(0,-1).map(k=>[k,receipt[k]])));}
  function receiptTranscript(receipt){
   const body=text(receiptBody(receipt)),prefix=text('D-MASH|ACCOUNT-ROUTE-RECEIPT|V2|'+receipt.phase+'\0'),length=new Uint8Array(4);
   new DataView(length.buffer).setUint32(0,body.length);return join(join(prefix,length),body);
  }
  function verifyReceipt(candidate,serialized,phase){
   const data=current(candidate);
   if(typeof serialized!=='string'||serialized.length>MAX_RECEIPT||text(serialized).length>MAX_RECEIPT)fail('SIZE');
   let receipt;try{receipt=JSON.parse(serialized);}catch{fail('JSON');}
   exact(receipt,RECEIPT_FIELDS);
   const canonical=JSON.stringify(Object.fromEntries(RECEIPT_FIELDS.map(k=>[k,receipt[k]])));
   if(serialized!==canonical)fail('NON_CANONICAL');
   if(receipt.type!=='DMASH_ACCOUNT_ROUTE_RECEIPT_V2'||receipt.version!==2||!['ACCEPT','CONFIRM'].includes(receipt.phase))fail('RECEIPT_SCHEMA');
   if(phase!==undefined&&receipt.phase!==phase)fail('PHASE');
   unhex(receipt.binding_digest);unhex(receipt.signer);unhex(receipt.signature,64);
   const expected=data.binding.participants[receipt.phase==='ACCEPT'?0:1].account;
   if(receipt.signer!==expected||receipt.binding_digest!==data.digest)fail('RECEIPT_CONTEXT');
   discovery.validateEd25519PublicEncoding(receipt.signer);discovery.validateEd25519SignatureEncoding(receipt.signature);
   if(!nacl.sign.detached.verify(receiptTranscript(receipt),unhex(receipt.signature,64),unhex(receipt.signer)))fail('RECEIPT_SIGNATURE');
   return Object.freeze(receipt);
  }
  function signReceipt(candidate,phase,secretKey,acceptReceipt){
   const data=current(candidate);if(!['ACCEPT','CONFIRM'].includes(phase))fail('PHASE');
   if(phase==='CONFIRM')verifyReceipt(candidate,acceptReceipt,'ACCEPT');
   const signer=data.binding.participants[phase==='ACCEPT'?0:1].account;
   if(!(secretKey instanceof Uint8Array)||secretKey.length!==64||hex(nacl.sign.keyPair.fromSecretKey(secretKey).publicKey)!==signer)fail('SIGNER_MISMATCH');
   const receipt={type:'DMASH_ACCOUNT_ROUTE_RECEIPT_V2',version:2,phase,binding_digest:data.digest,signer,signature:''};
   receipt.signature=hex(nacl.sign.detached(receiptTranscript(receipt),secretKey));
   const serialized=JSON.stringify(receipt);verifyReceipt(candidate,serialized,phase);return serialized;
  }
  function verifyReceipts(candidate,receipts,context){
   const data=current(candidate);if(!context||!Object.hasOwn(context,'committed'))fail('COMMITTED_CONTEXT_REQUIRED');
   if(!Array.isArray(receipts)||receipts.length!==2)fail('BOTH_RECEIPTS_REQUIRED');
   const checked=receipts.map(receipt=>verifyReceipt(candidate,receipt));
   if(new Set(checked.map(r=>r.phase)).size!==2)fail('BOTH_RECEIPTS_REQUIRED');
   const status=checkGeneration(data,committedSnapshot(context.committed)),verifiedAt=now();
   if(data.binding.expires_at<=verifiedAt)fail('EXPIRED');
   return Object.freeze({status,binding:data.binding,digest:data.digest,verifiedAt,receipts:Object.freeze(['ACCEPT','CONFIRM'].map(phase=>receipts[checked.findIndex(r=>r.phase===phase)]))});
  }
  async function verifyCommitted(serializedBundles,receipts,context){
   // The caller must obtain this epoch from its authenticated durable journal.
   // This validates history only and never creates a currently signable candidate.
   integer(context?.verifiedAt);if(context.verifiedAt>now())fail('COMMIT_EPOCH_FUTURE');
   const historical=createBindingCodec({nacl,discovery,pairing,subtle,clock:()=>context.verifiedAt});
   const candidate=await historical.prepare(serializedBundles,context);
   return historical.verifyReceipts(candidate,receipts,context);
  }
  function compareCandidates(left,right){
   const a=current(left),b=current(right);
   if(a.binding.generation!==b.binding.generation||a.binding.previous_binding!==b.binding.previous_binding||a.binding.participants.some((p,i)=>p.account!==b.binding.participants[i].account))fail('INCOMPARABLE_CANDIDATES');
   for(let i=0;i<2;i++){const x=a.binding.participants[i].bundle_digest,y=b.binding.participants[i].bundle_digest;if(x!==y)return x<y?-1:1;}return 0;
  }
  return Object.freeze({prepare,signReceipt,verifyReceipt,verifyReceipts,verifyCommitted,compareCandidates});
 }
 const api=Object.freeze({createBindingCodec,MAX_BINDING,MAX_RECEIPT});global.DmashAccountRouteBindingV2=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
