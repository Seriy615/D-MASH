'use strict';
(function(global){
 const FIELDS=['type','version','transport_version','pairing_id','generation','issued_at','expires_at','previous_binding','intended_peer','contribution','account_keys','inbound_certificate','signature'];
 const KEYS=['signing','box','kem_profile','kem_public'];
 const CERT=['version','route_id','discovery_sign','discovery_box','recipient_box','generation','issued_at','expires_at','signature'];
 const MAX_BYTES=12288,PROFILE='LEGACY_KYBER768_BUNDLE_V1';
 const utf8=s=>new TextEncoder().encode(s);
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const hex=(s,n=32)=>{if(typeof s!=='string'||!new RegExp('^[0-9a-f]{'+n*2+'}$').test(s))fail('ENCODING');return Uint8Array.from(s.match(/../g),v=>parseInt(v,16));};
 const toHex=a=>Array.from(a,v=>v.toString(16).padStart(2,'0')).join('');
 const integer=n=>{if(!Number.isSafeInteger(n)||n<0||Object.is(n,-0))fail('INTEGER');};
 function exact(o,fields){
  if(!o||typeof o!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(o)))fail('SCHEMA');
  const names=Reflect.ownKeys(o);if(names.length!==fields.length||names.some(k=>!fields.includes(k)))fail('SCHEMA');
  for(const k of names)if(!Object.hasOwn(Object.getOwnPropertyDescriptor(o,k),'value'))fail('SCHEMA');
 }
 function ordered(o,fields){return Object.fromEntries(fields.map(k=>[k,o[k]]));}
 function canonical(value,withSignature=true){
  exact(value,FIELDS);exact(value.account_keys,KEYS);exact(value.inbound_certificate,CERT);
  for(const [object,fields] of [[value,FIELDS.filter(k=>!['account_keys','inbound_certificate'].includes(k))],[value.account_keys,KEYS],[value.inbound_certificate,CERT]])
   for(const k of fields){if(object[k]!==null&&!['string','number'].includes(typeof object[k]))fail('SCHEMA');if(typeof object[k]==='string'&&object[k].length>MAX_BYTES)fail('SIZE');}
  const o=ordered(value,withSignature?FIELDS:FIELDS.slice(0,-1));
  o.account_keys=ordered(value.account_keys,KEYS);o.inbound_certificate=ordered(value.inbound_certificate,CERT);
  return JSON.stringify(o);
 }
 function schema(b){
  canonical(b);
  if(b.type!=='DMASH_PAIRING_V2'||b.version!==2||b.transport_version!==4)fail('UPGRADE_REQUIRED_V2');
  hex(b.pairing_id);hex(b.contribution);hex(b.signature,64);
  for(const k of ['generation','issued_at','expires_at'])integer(b[k]);
  if(b.generation<1||b.expires_at<=b.issued_at||b.expires_at-b.issued_at>86400)fail('VALIDITY');
  if(b.previous_binding!==null)hex(b.previous_binding);if(b.intended_peer!==null)hex(b.intended_peer);
  const a=b.account_keys,c=b.inbound_certificate;
  hex(a.signing);hex(a.box);
  if(a.kem_profile!==PROFILE)fail('PROFILE');
  if(typeof a.kem_public!=='string'||!/^[A-Za-z0-9_-]{1579}$/.test(a.kem_public))fail('KEM_ENCODING');
  const raw=atob(a.kem_public.replace(/-/g,'+').replace(/_/g,'/')+'=');
  if(raw.length!==1184||btoa(raw).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==a.kem_public)fail('KEM_ENCODING');
  for(const k of ['route_id','discovery_sign','discovery_box','recipient_box'])hex(c[k]);
  hex(c.signature,64);for(const k of ['generation','issued_at','expires_at'])integer(c[k]);
  if(c.version!==4||c.generation!==b.generation||c.expires_at<b.expires_at)fail('CERTIFICATE_CONTEXT');
  const roles=[a.signing,a.box,c.route_id,c.discovery_sign,c.discovery_box,c.recipient_box];
  if(new Set(roles).size!==roles.length)fail('KEY_ROLE_REUSE');
 }
 function createCodec({nacl,discovery}){
  if(!nacl?.sign?.detached?.verify||!discovery?.verifyCertificate||!discovery?.validateEd25519PublicEncoding||!discovery?.validateEd25519SignatureEncoding||!discovery?.validateX25519PublicKey)fail('DEPENDENCY');
  function transcript(b){schema(b);const body=utf8(canonical(b,false)),out=new Uint8Array(utf8('D-MASH|ACCOUNT-PAIRING|V2\0').length+4+body.length),prefix=utf8('D-MASH|ACCOUNT-PAIRING|V2\0');out.set(prefix);new DataView(out.buffer).setUint32(prefix.length,body.length);out.set(body,prefix.length+4);return out;}
  function verify(b,context={}){
   // Copy before cryptographic checks: callers cannot mutate the returned candidate.
   schema(b);const serialized=canonical(b);if(utf8(serialized).length>MAX_BYTES)fail('SIZE');b=JSON.parse(serialized);schema(b);
   const now=context.now??Math.floor(Date.now()/1000);integer(now);
   if(b.issued_at>now+60||b.expires_at<=now)fail('EXPIRED');
   for(const key of [b.account_keys.signing,b.inbound_certificate.route_id,b.inbound_certificate.discovery_sign])discovery.validateEd25519PublicEncoding(key);
   discovery.validateEd25519SignatureEncoding(b.signature);discovery.validateEd25519SignatureEncoding(b.inbound_certificate.signature);
   if(!nacl.sign.detached.verify(transcript(b),hex(b.signature,64),hex(b.account_keys.signing)))fail('ACCOUNT_SIGNATURE');
   discovery.verifyCertificate(b.inbound_certificate,now);
   discovery.validateX25519PublicKey(b.account_keys.box);
   if(context.expectedPeer!==undefined){hex(context.expectedPeer);if(b.account_keys.signing!==context.expectedPeer)fail('IDENTITY_MISMATCH');}
   if(context.localAccount!==undefined){hex(context.localAccount);if(b.account_keys.signing===context.localAccount)fail('SELF_PAIRING');}
   if(b.intended_peer!==null&&b.intended_peer!==context.localAccount)fail('TARGET_MISMATCH');
   if(context.expectedGeneration!==undefined){integer(context.expectedGeneration);if(b.generation!==context.expectedGeneration)fail('GENERATION_MISMATCH');}
   if(Object.hasOwn(context,'previousBinding')){if(context.previousBinding!==null)hex(context.previousBinding);if(b.previous_binding!==context.previousBinding)fail('PREDECESSOR_MISMATCH');}
   Object.freeze(b.account_keys);Object.freeze(b.inbound_certificate);Object.freeze(b);
   return Object.freeze({bundle:b,serialized,identityStatus:context.expectedPeer===undefined?'UNPINNED_CANDIDATE':'PINNED_CANDIDATE'});
  }
  function parse(input,context){
   if(typeof input!=='string')fail('ENCODING');if(input.length>MAX_BYTES||utf8(input).length>MAX_BYTES)fail('SIZE');
   let b;try{b=JSON.parse(input);}catch{fail('JSON');}
   if(b?.type==='DMASH_PAIRING_V1'||b?.version===1)fail('UPGRADE_REQUIRED_V2');
   if(canonical(b)!==input)fail('NON_CANONICAL');return verify(b,context);
  }
  function sign(body,secretKey,context){
   exact(body,FIELDS.slice(0,-1));
   const b={...body,signature:'00'.repeat(64)};schema(b);
   if(!(secretKey instanceof Uint8Array)||secretKey.length!==64||toHex(nacl.sign.keyPair.fromSecretKey(secretKey).publicKey)!==b.account_keys.signing)fail('SIGNER_MISMATCH');
   b.signature=toHex(nacl.sign.detached(transcript(b),secretKey));return verify(b,context);
  }
  return Object.freeze({parse,verify,sign,transcript});
 }
 const api=Object.freeze({createCodec,MAX_BYTES,PROFILE});global.DmashAccountPairingV2=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
