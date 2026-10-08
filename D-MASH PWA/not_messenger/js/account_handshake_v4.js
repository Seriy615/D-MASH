'use strict';
// Account-only frames. Never put serialized frames or identities in Node metadata.
(function(global) {
 const SUITE='X25519_LEGACY_KYBER768_HKDF_SHA256_V1';
 const FIELDS=['type','version','suite','kind','binding_digest','binding_generation','session_generation','attempt_id','sender','recipient','issued_at','expires_at','previous_session','body','signature'];
 const BODIES={
  INIT:['suites','ephemeral','kem_public','nonce','authorization'],
  FINAL:['init_digest','ephemeral','capsule','nonce','session_id','mac'],
  CONFIRM:['init_digest','final_digest','session_id','mac'],
  CONFIRM_ACK:['init_digest','final_digest','confirm_digest','session_id','mac'],
  RECOVERY_REQUEST:['init_digest','request_nonce'],
  RECOVERY_CHALLENGE:['request_digest','init_digest','request_nonce','challenge_nonce','ticket','confirmed_session','confirmed_generation','next_generation'],
  RECOVERY_PROOF:['request_digest','challenge_digest','init_digest','ticket'],
  REFUSE:['reference_digest','reason','supported_version','supported_suites']
 };
 const LIMITS=Object.freeze({INIT:4096,FINAL:4096,CONFIRM:2048,CONFIRM_ACK:2048,RECOVERY_REQUEST:2048,RECOVERY_CHALLENGE:3072,RECOVERY_PROOF:2048,REFUSE:2048});
 const fail=code=>{throw Object.assign(Error(code),{code});};
 const utf8=s=>new TextEncoder().encode(s), hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
 const unhex=(s,n=32)=>{if(typeof s!=='string'||!new RegExp('^[a-f0-9]{'+n*2+'}$').test(s))fail('ENCODING');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 const integer=(n,min=0)=>{if(!Number.isSafeInteger(n)||n<min||Object.is(n,-0))fail('INTEGER');};
 function exact(o,fields){if(!o||![Object.prototype,null].includes(Object.getPrototypeOf(o)))fail('SCHEMA');const keys=Reflect.ownKeys(o);if(keys.length!==fields.length||keys.some(k=>!fields.includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(o,k),'value')))fail('SCHEMA');}
 const ordered=(o,fields)=>Object.fromEntries(fields.map(k=>[k,o[k]]));
 const join=(...a)=>{const out=new Uint8Array(a.reduce((n,b)=>n+b.length,0));let at=0;for(const b of a){out.set(b,at);at+=b.length;}return out;};
 const lengthPrefix=b=>{const h=new Uint8Array(4);new DataView(h.buffer).setUint32(0,b.length);return join(h,b);};
 const domain=(name,...parts)=>join(utf8('D-MASH|ACCOUNT-HANDSHAKE|V4|'+name+'\0'),...parts.map(lengthPrefix));
 function suites(a){if(!Array.isArray(a)||a.length!==1||a[0]!==SUITE||Object.keys(a).length!==1)fail('SUITE_REQUIRED');}
 function canonical(f,signature=true){exact(f,FIELDS);if(!Object.hasOwn(BODIES,f.kind))fail('KIND');exact(f.body,BODIES[f.kind]);const out=ordered(f,signature?FIELDS:FIELDS.slice(0,-1));out.body=ordered(f.body,BODIES[f.kind]);return JSON.stringify(out);}
 function shape(f){
  canonical(f);if(f.type!=='ACCOUNT_HANDSHAKE'||f.version!==4)fail('VERSION_REQUIRED');if(f.suite!==SUITE)fail('SUITE_REQUIRED');
  for(const k of ['binding_digest','attempt_id','sender','recipient'])unhex(f[k]);unhex(f.signature,64);if(f.sender===f.recipient)fail('SELF');
  for(const k of ['binding_generation','session_generation'])integer(f[k],1);for(const k of ['issued_at','expires_at'])integer(f[k]);
  if(f.expires_at<=f.issued_at||f.expires_at-f.issued_at>86400)fail('VALIDITY');if(f.previous_session!==null)unhex(f.previous_session);
  const b=f.body;
  for(const k of BODIES[f.kind]){
   if(['suites','supported_suites'].includes(k))suites(b[k]);
   else if(['confirmed_generation','next_generation'].includes(k))integer(b[k],k==='confirmed_generation'?0:1);
   else if(k==='confirmed_session'){if(b[k]!==null)unhex(b[k]);}
   else if(k==='supported_version'){if(b[k]!==4)fail('VERSION_REQUIRED');}
   else if(k==='reason'){if(!['VERSION_REQUIRED','SUITE_REQUIRED','RECOVERY_REQUIRED','EXPIRED','SUPERSEDED','PREDECESSOR_MISMATCH'].includes(b[k]))fail('REASON');}
   else if(k==='authorization'){if(b[k]!==null)unhex(b[k]);}
   else unhex(b[k],k==='kem_public'?1184:k==='capsule'?1088:32);
  }
  if(f.kind==='RECOVERY_CHALLENGE'&&((b.confirmed_session===null)!==(b.confirmed_generation===0)))fail('RECOVERY_CONTEXT');
  if(f.kind==='RECOVERY_CHALLENGE'&&(b.next_generation!==b.confirmed_generation+1||f.expires_at-f.issued_at>600))fail('RECOVERY_CONTEXT');
  if(utf8(canonical(f)).length>LIMITS[f.kind])fail('SIZE');
 }
 function createCodec({nacl,discovery,crypto=global.crypto,clock=()=>Math.floor(Date.now()/1000)}){
  if(!nacl?.sign?.detached||!discovery?.validateEd25519SignatureEncoding||!crypto?.subtle)fail('DEPENDENCY');
  const digest=async(name,...parts)=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',domain(name,...parts))));
  const transcript=f=>{shape(f);return domain(f.kind,utf8(canonical(f,false)));};
  function verify(input,context){
   if(!context||!context.peer||!context.local||!context.bindingDigest||!context.bindingGeneration)fail('PINNED_CONTEXT_REQUIRED');
   if(typeof input!=='string'||input.length>12288)fail('SIZE');let f;try{f=JSON.parse(input);}catch{fail('JSON');}shape(f);if(canonical(f)!==input)fail('NON_CANONICAL');
   if(f.sender!==context.peer||f.recipient!==context.local)fail('IDENTITY_MISMATCH');if(f.binding_digest!==context.bindingDigest||f.binding_generation!==context.bindingGeneration)fail('BINDING_MISMATCH');
   if(context.requiredSuite!==SUITE)fail('SUITE_REQUIRED');const now=clock();integer(now);if(f.issued_at>now+60||f.expires_at<=now)fail('EXPIRED');
   discovery.validateEd25519PublicEncoding(f.sender);discovery.validateEd25519PublicEncoding(f.recipient);discovery.validateEd25519SignatureEncoding(f.signature);
   if(!nacl.sign.detached.verify(transcript(f),unhex(f.signature,64),unhex(f.sender)))fail('SIGNATURE');
   if(f.body.ephemeral){discovery.validateX25519PublicKey(f.body.ephemeral);if([f.sender,f.recipient].includes(f.body.ephemeral))fail('KEY_ROLE_REUSE');}
   if(f.body.suites)Object.freeze(f.body.suites);if(f.body.supported_suites)Object.freeze(f.body.supported_suites);Object.freeze(f.body);Object.freeze(f);return f;
  }
  function sign(body,secretKey){exact(body,FIELDS.slice(0,-1));const f={...body,body:JSON.parse(JSON.stringify(body.body)),signature:'00'.repeat(64)};shape(f);if(!(secretKey instanceof Uint8Array)||secretKey.length!==64||hex(nacl.sign.keyPair.fromSecretKey(secretKey).publicKey)!==f.sender)fail('SIGNER');f.signature=hex(nacl.sign.detached(transcript(f),secretKey));return canonical(f);}
  async function frameDigest(raw){if(typeof raw!=='string')fail('ENCODING');const f=JSON.parse(raw);shape(f);if(canonical(f)!==raw)fail('NON_CANONICAL');return digest('FRAME',utf8(raw));}
  async function sessionTranscript(initRaw,finalCore){
   const i=JSON.parse(initRaw);shape(i);if(i.kind!=='INIT'||canonical(i)!==initRaw)fail('TRANSCRIPT');
   exact(finalCore,['init_digest','ephemeral','capsule','nonce']);for(const k of ['init_digest','ephemeral','nonce'])unhex(finalCore[k]);unhex(finalCore.capsule,1088);
   if(finalCore.init_digest!==await frameDigest(initRaw))fail('TRANSCRIPT');
   return digest('SESSION',utf8(initRaw),utf8(JSON.stringify(ordered(finalCore,['init_digest','ephemeral','capsule','nonce']))));
  }
  // Explicit legacy-Kyber migration combiner. No ML-KEM conformance or PCS claim.
  async function derive(xSecret,kemSecret,sessionId){
   if(!(xSecret instanceof Uint8Array)||xSecret.length!==32||!xSecret.some(Boolean)||!(kemSecret instanceof Uint8Array)||kemSecret.length!==32)fail('SECRET');unhex(sessionId);
   const ikm=join(lengthPrefix(xSecret),lengthPrefix(kemSecret));
   const key=await crypto.subtle.importKey('raw',ikm,'HKDF',false,['deriveBits']);ikm.fill(0);
   const out={};for(const label of ['root','final','confirm','ack'])out[label]=new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:unhex(sessionId),info:domain('KEY|'+label,utf8(SUITE))},key,256));return out;
  }
  async function mac(key,kind,...digests){if(!(key instanceof Uint8Array)||key.length!==32||!['FINAL','CONFIRM','CONFIRM_ACK'].includes(kind))fail('MAC');const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(new Uint8Array(await crypto.subtle.sign('HMAC',k,domain('CONFIRM|'+kind,...digests.map(x=>unhex(x))))));}
  async function verifyMac(key,kind,tag,...digests){unhex(tag);const expected=await mac(key,kind,...digests);if(!nacl.verify(unhex(expected),unhex(tag)))fail('KEY_CONFIRMATION');}
  return Object.freeze({verify,sign,frameDigest,sessionTranscript,derive,mac,verifyMac,transcript});
 }
 const api=Object.freeze({createCodec,SUITE,LIMITS,hex,unhex,domain});global.DmashAccountHandshakeV4=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
