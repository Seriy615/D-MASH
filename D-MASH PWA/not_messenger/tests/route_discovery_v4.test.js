'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
const api=require('../js/route_discovery_v4.js');
(async()=>{
 const owner=nacl.sign.keyPair(),sign=nacl.sign.keyPair(),box=nacl.box.keyPair(),recipient=nacl.box.keyPair();
 const now=1800000000;
 const cert=api.issueCertificate(owner,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600});
 assert(api.verifyCertificate(cert,now));
 const strict=require('./fixtures/route_discovery_strict_v4.json');
 const h=bytes=>Buffer.from(bytes).toString('hex');
 const signed=patch=>{const candidate={...cert,...patch};candidate.signature=h(nacl.sign.detached(api.certificateTranscript(candidate),owner.secretKey));return candidate;};
 for(const key of strict.ed_reject){
  assert.throws(()=>api.verifyCertificate(signed({discovery_sign:key}),now));
  assert.throws(()=>api.verifyCertificate({...cert,route_id:key,signature:'01'+'00'.repeat(63)},now));
  assert.throws(()=>api.verifyCertificate({...cert,signature:key+cert.signature.slice(64)},now));
 }
 for(const field of ['discovery_box','recipient_box']){
  for(const key of strict.x_reject)assert.throws(()=>api.verifyCertificate(signed({[field]:key}),now));
  const alias=Buffer.from(cert[field],'hex');alias[31]|=128;
  assert.throws(()=>api.verifyCertificate(signed({[field]:h(alias)}),now));
 }
 const addL=signature=>{const bytes=Buffer.from(signature,'hex'),order=Buffer.from(strict.scalar_order_le,'hex');let carry=0;for(let i=0;i<32;i++){const n=bytes[i+32]+order[i]+carry;bytes[i+32]=n&255;carry=n>>>8;}return h(bytes);};
 assert.throws(()=>api.verifyCertificate({...cert,signature:addL(cert.signature)},now));
 const {blob,state}=api.createQuery(cert,{now});
 const reply=await api.answerQuery(blob,cert,sign,box,{now});
 assert(await api.verifyReply(reply,state,{now}));
 const noncanonicalReply=api.openBox(state.replyPrivate,reply);noncanonicalReply.signature=addL(noncanonicalReply.signature);
 await assert.rejects(api.verifyReply(api.seal(nacl.box.keyPair.fromSecretKey(state.replyPrivate).publicKey,noncanonicalReply),state,{now}),e=>e.code==='NON_CANONICAL_SIGNATURE');
 let clockCalls=0;await assert.rejects(api.verifyReply(reply,state,{clock:()=>clockCalls++?now+181:now}));
 clockCalls=0;await assert.rejects(api.answerQuery(blob,cert,sign,box,{clock:()=>clockCalls++?now+181:now}));
 const payload=api.seal(recipient.publicKey,{opaque:'test payload'});
 assert.deepEqual(api.openBox(recipient.secretKey,payload),{opaque:'test payload'});
 assert.throws(()=>api.openBox(box.secretKey,payload));
 await assert.rejects(api.answerQuery(blob,cert,owner,box,{now}));
 await assert.rejects(api.verifyReply(reply,state,{now:now+180}));
 const other=api.createQuery(cert,{now});
 await assert.rejects(api.verifyReply(reply,other.state,{now}));
 const forged=api.openBox(state.replyPrivate,reply);forged.signature='00'.repeat(64);
 await assert.rejects(api.verifyReply(api.seal(nacl.box.keyPair.fromSecretKey(state.replyPrivate).publicKey,forged),state,{now}));
 for(const patch of [{generation:true},{version:3},{expires_at:now+31*86400},{issued_at:now+61},{signature:'ff'.repeat(64)},{extra:1}])assert.throws(()=>api.verifyCertificate({...cert,...patch},now));
 const tampered=api.openBox(state.replyPrivate,reply);tampered.certificate={...cert,generation:true};
 await assert.rejects(api.verifyReply(api.seal(nacl.box.keyPair.fromSecretKey(state.replyPrivate).publicKey,tampered),state,{now}));
 for(const invalid of ['?',blob+'\n','A'.repeat(22000)])assert.throws(()=>api.openBox(box.secretKey,invalid));
 assert.throws(()=>api.seal(box.publicKey,{data:'x'.repeat(16384)}));
 for(const key of [owner.secretKey,sign.secretKey,box.secretKey,recipient.secretKey,state.replyPrivate,other.state.replyPrivate])key.fill(0);
 console.log('PASS encrypted discovery authority, delegated key isolation, pinned certificate, context/expiry/forgery rejection');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
