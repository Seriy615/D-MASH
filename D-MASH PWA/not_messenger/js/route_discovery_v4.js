'use strict';
(function(global){
 const MAX_BLOB=16384,MAX_LIFETIME=30*86400;
 const text=value=>new TextEncoder().encode(value);
 const join=(...parts)=>{const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const part of parts){out.set(part,at);at+=part.length;}return out;};
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const unhex=(value,size=32)=>{if(typeof value!=='string'||!(new RegExp('^[0-9a-f]{'+size*2+'}$')).test(value))throw Error('Invalid discovery encoding');return Uint8Array.from(value.match(/../g),b=>parseInt(b,16));};
 const integer=value=>{if(!Number.isSafeInteger(value)||value<0)throw Error('Invalid discovery integer');const out=new Uint8Array(8);new DataView(out.buffer).setBigUint64(0,BigInt(value));return out;};
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 // Public encoding guards only; group/signature verification remains in the vendor.
 // Small-order y encodings: libsodium 1.0.18 ge25519_has_small_order:
 // https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1022
 // Adapted encoding constants, source SHA256:
 // 40291bba865beab9817381460cda1d977a106c11cf4c393f854e25979d84bfc7
 // Lines 1022–1075. This is not a prime-subgroup membership proof.
/*
 * ISC License
 *
 * Copyright (c) 2013-2019
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 const ED_SMALL=new Set(['00'.repeat(32),'01'+'00'.repeat(31),
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ec'+'ff'.repeat(30)+'7f','ed'+'ff'.repeat(30)+'7f','ee'+'ff'.repeat(30)+'7f']);
 const P=unhex('ed'+'ff'.repeat(30)+'7f'),L=unhex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
 function lessLE(a,b){for(let i=a.length-1;i>=0;i--){if(a[i]!==b[i])return a[i]<b[i];}return false;}
 function edPoint(value){const y=unhex(value);y[31]&=127;if(!lessLE(y,P))fail('NON_CANONICAL_POINT');if(ED_SMALL.has(hex(y)))fail('SMALL_ORDER_POINT');}
 function edSignature(value){const sig=unhex(value,64);edPoint(hex(sig.subarray(0,32)));if(!lessLE(sig.subarray(32),L))fail('NON_CANONICAL_SIGNATURE');}
 function xPoint(value){const u=unhex(value);if(!lessLE(u,P))fail('NON_CANONICAL_POINT');const scalar=new Uint8Array(32);scalar[0]=8;if(!global.nacl.scalarMult(scalar,u).some(Boolean))fail('LOW_ORDER_KEY');}
 function certificateTranscript(cert){
  if(!exact(cert,'discovery_box,discovery_sign,expires_at,generation,issued_at,recipient_box,route_id,signature,version')||cert.version!==4)throw Error('Invalid discovery certificate');
  const keys=['route_id','discovery_sign','discovery_box','recipient_box'].map(name=>unhex(cert[name]));
  const dates=['generation','issued_at','expires_at'].map(name=>integer(cert[name]));
  if(cert.generation<1||cert.expires_at<=cert.issued_at||cert.expires_at-cert.issued_at>MAX_LIFETIME)throw Error('Invalid discovery validity');
  return join(text('D-MASH|DISCOVERY-CERT|V4\0'),...keys,...dates);
 }
 function verifyCertificate(cert,now=Math.floor(Date.now()/1000)){
  const transcript=certificateTranscript(cert);
  if(cert.issued_at>now+60||cert.expires_at<=now)throw Error('Discovery certificate expired');
  edPoint(cert.route_id);edPoint(cert.discovery_sign);xPoint(cert.discovery_box);xPoint(cert.recipient_box);edSignature(cert.signature);
  if(!global.nacl.sign.detached.verify(transcript,unhex(cert.signature,64),unhex(cert.route_id)))throw Error('Invalid discovery certificate signature');
  return transcript;
 }
 function issueCertificate(routeSign,discoverySign,discoveryBox,recipientBox,{generation,issuedAt,expiresAt}){
  const cert={version:4,route_id:hex(routeSign.publicKey),discovery_sign:hex(discoverySign),discovery_box:hex(discoveryBox),recipient_box:hex(recipientBox),generation,issued_at:issuedAt,expires_at:expiresAt,signature:''};
  cert.signature=hex(global.nacl.sign.detached(certificateTranscript(cert),routeSign.secretKey));return cert;
 }
 const b64=value=>btoa(String.fromCharCode(...value));
 function seal(publicKey,value){
  const raw=text(JSON.stringify(value));if(raw.length>MAX_BLOB-72)throw Error('Discovery payload too large');
  const ephemeral=global.nacl.box.keyPair(),nonce=global.nacl.randomBytes(24);
  try{return b64(join(ephemeral.publicKey,nonce,global.nacl.box(raw,nonce,publicKey,ephemeral.secretKey)));}
  finally{ephemeral.secretKey.fill(0);}
 }
 function openBox(privateKey,value){
  if(typeof value!=='string'||value.length>Math.ceil(MAX_BLOB/3)*4)throw Error('Invalid discovery box');
  const raw=Uint8Array.from(atob(value),c=>c.charCodeAt(0));
  if(raw.length<72||raw.length>MAX_BLOB||b64(raw)!==value)throw Error('Invalid discovery box');
  const plain=global.nacl.box.open(raw.subarray(56),raw.subarray(32,56),raw.subarray(0,32),privateKey);
  if(!plain)throw Error('Discovery authentication failed');
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}finally{plain.fill(0);}
 }
 function checkQuery(query,cert,now){
  if(!exact(query,'challenge,expires_at,reply_key,route_id,type,version')||query.type!=='ROUTE_QUERY'||query.version!==4||query.route_id!==cert.route_id)throw Error('Invalid discovery context');
  unhex(query.challenge);unhex(query.reply_key);integer(query.expires_at);
  if(query.expires_at<=now||query.expires_at>Math.min(now+180,cert.expires_at))throw Error('Discovery query expired');
  return query;
 }
 async function replyTranscript(query,cert){
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',join(certificateTranscript(cert),unhex(cert.signature,64))));
  return join(text('D-MASH|DISCOVERY-REPLY|V4\0'),unhex(query.challenge),unhex(query.reply_key),integer(query.expires_at),digest);
 }
 function createQuery(cert,{now=Math.floor(Date.now()/1000)}={}){
  verifyCertificate(cert,now);cert=Object.freeze({...cert});
  const reply=global.nacl.box.keyPair();
  try{
   const query=Object.freeze({type:'ROUTE_QUERY',version:4,route_id:cert.route_id,challenge:hex(global.nacl.randomBytes(32)),reply_key:hex(reply.publicKey),expires_at:Math.min(now+180,cert.expires_at)});
   return {blob:seal(unhex(cert.discovery_box),query),state:{query,certificate:cert,replyPrivate:reply.secretKey}};
  }catch(error){reply.secretKey.fill(0);throw error;}
 }
 async function answerQuery(blob,cert,discoverySign,discoveryBox,options={}){
  const clock=options.clock||(()=>options.now??Math.floor(Date.now()/1000)),now=clock();
  verifyCertificate(cert,now);cert={...cert};
  if(hex(discoverySign.publicKey)!==cert.discovery_sign||hex(discoveryBox.publicKey)!==cert.discovery_box)throw Error('Discovery key mismatch');
  const query=checkQuery(openBox(discoveryBox.secretKey,blob),cert,now);
  const signature=hex(global.nacl.sign.detached(await replyTranscript(query,cert),discoverySign.secretKey));
  checkQuery(query,cert,clock());
  const reply=seal(unhex(query.reply_key),{type:'ROUTE_REPLY',version:4,challenge:query.challenge,expires_at:query.expires_at,certificate:cert,signature});
  return options.withContext?{reply,expiresAt:query.expires_at}:reply;
 }
 async function verifyReply(blob,state,options={}){
  const clock=options.clock||(()=>options.now??Math.floor(Date.now()/1000)),now=clock();
  const cert=state.certificate;verifyCertificate(cert,now);const query=checkQuery(state.query,cert,now);
  const response=openBox(state.replyPrivate,blob);
  if(!exact(response,'certificate,challenge,expires_at,signature,type,version')||response.type!=='ROUTE_REPLY'||response.version!==4||response.challenge!==query.challenge||response.expires_at!==query.expires_at)throw Error('Discovery reply context mismatch');
  verifyCertificate(response.certificate,now);
  if(Object.keys(cert).some(key=>cert[key]!==response.certificate[key]))throw Error('Discovery certificate mismatch');
  edSignature(response.signature);
  if(!global.nacl.sign.detached.verify(await replyTranscript(query,cert),unhex(response.signature,64),unhex(cert.discovery_sign)))throw Error('Invalid discovery reply signature');
  checkQuery(query,cert,clock());
  return true;
 }
 const api=Object.freeze({validateEd25519PublicEncoding:edPoint,validateEd25519SignatureEncoding:edSignature,validateX25519PublicKey:xPoint,certificateTranscript,verifyCertificate,issueCertificate,seal,openBox,createQuery,answerQuery,verifyReply});
 global.DmashRouteDiscoveryV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
