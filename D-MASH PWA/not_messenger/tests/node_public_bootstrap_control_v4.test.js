'use strict';
const assert=require('node:assert/strict');global.nacl=require('../js/vendor/nacl-fast.min.js');require('../js/secure_session.js');const discovery=require('../js/route_discovery_v4.js'),pairing=require('../js/account_pairing_v2.js').createCodec({nacl,discovery});const now=Math.floor(Date.now()/1000),binding=require('../js/account_route_binding_v2.js').createBindingCodec({nacl,discovery,pairing,clock:()=>now}),codec=require('../js/node_public_bootstrap_control_v4.js').createCodec({pairing,binding,clock:()=>now});
const hex=b=>Buffer.from(b).toString('hex');
function person(n){const key=()=>nacl.sign.keyPair(),box=()=>nacl.box.keyPair();return {account:key(),box:box(),route:key(),sign:key(),discovery:box(),recipient:box(),n};}
const a=person(1),b=person(2);
function bundle(p,target=null){const certificate=discovery.issueCertificate(p.route,p.sign.publicKey,p.discovery.publicKey,p.recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600});return pairing.sign({type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(crypto.getRandomValues(new Uint8Array(32))),generation:1,issued_at:now,expires_at:now+1800,previous_binding:null,intended_peer:target,contribution:hex(crypto.getRandomValues(new Uint8Array(32))),account_keys:{signing:hex(p.account.publicKey),box:hex(p.box.publicKey),kem_profile:'LEGACY_KYBER768_BUNDLE_V1',kem_public:Buffer.alloc(1184,p.n).toString('base64url')},inbound_certificate:certificate},p.account.secretKey,{now,localAccount:target??undefined}).serialized;}
(async()=>{
 for(const [receiver,sender] of [[a,b],[b,a]]){
  const target=person(3),reply=person(4),certificate=p=>discovery.issueCertificate(p.route,p.sign.publicKey,p.discovery.publicKey,p.recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600}),targetCert=certificate(target),replyCert=certificate(reply);
  const requestWire=await codec.request(targetCert,{requestId:'a'.repeat(64),replyCertificate:replyCert,bootstrapBox:hex(reply.box.publicKey),displayName:'Public stranger',introduction:'Neutral request',nonce:'b'.repeat(64)},reply.route.secretKey);
  const request=await codec.inspectRequest(targetCert,requestWire);assert.equal(request.identityStatus,'ACCOUNT_NEUTRAL');
  assert(!requestWire.includes(hex(sender.account.publicKey)));assert(!requestWire.includes(hex(receiver.account.publicKey)));
  const localBundle=bundle(receiver),remoteBundle=bundle(sender,hex(receiver.account.publicKey));
  const acceptWire=await codec.accept(request,{bundle:localBundle,bootstrapBox:hex(nacl.box.keyPair().publicKey)},receiver.account.secretKey),accepted=await codec.inspectAccept(request,acceptWire);
  assert.equal(accepted.identityStatus,'UNSELECTED_CANDIDATE');
  const people=[receiver,sender].sort((x,y)=>hex(x.account.publicKey).localeCompare(hex(y.account.publicKey))),candidate=await binding.prepare([localBundle,remoteBundle],{expectedParticipants:people.map(p=>hex(p.account.publicKey)),committed:null});
  const receiptA=binding.signReceipt(candidate,'ACCEPT',people[0].account.secretKey),receiptB=binding.signReceipt(candidate,'CONFIRM',people[1].account.secretKey,receiptA);
  const confirmWire=await codec.confirm(accepted,{bundle:remoteBundle,acceptReceipt:people[0]===sender?receiptA:null},sender.account.secretKey),confirmed=await codec.inspectConfirm(accepted,confirmWire);
  assert.equal(confirmed.bindingDigest,candidate.digest);assert.equal(codec.receipt(confirmed,receiptA,'ACCEPT').phase,'ACCEPT');assert.equal(codec.receipt(confirmed,receiptB,'CONFIRM').phase,'CONFIRM');
  await assert.rejects(codec.inspectRequest(replyCert,requestWire));await assert.rejects(codec.inspectRequest(targetCert,' '+requestWire));
  await assert.rejects(codec.inspectRequest(targetCert,DmashSecureSession.canonical({...JSON.parse(requestWire),nonce:'c'.repeat(64)})));
  await assert.rejects(codec.inspectRequest(targetCert,DmashSecureSession.canonical({...JSON.parse(requestWire),account_id:hex(sender.account.publicKey)})));
  await assert.rejects(codec.inspectAccept({...request},acceptWire));await assert.rejects(codec.inspectConfirm({...accepted},confirmWire));
  await assert.rejects(codec.request(targetCert,{requestId:'a'.repeat(64),replyCertificate:replyCert,bootstrapBox:hex(reply.box.publicKey),displayName:'x'.repeat(129),introduction:'',nonce:'b'.repeat(64)},reply.route.secretKey));
  await assert.rejects(codec.request(targetCert,{requestId:'a'.repeat(64),replyCertificate:replyCert,bootstrapBox:'0'.repeat(64),displayName:'ok',introduction:'',nonce:'b'.repeat(64)},reply.route.secretKey));
  const expired=require('../js/node_public_bootstrap_control_v4.js').createCodec({pairing,binding,clock:()=>now+4000});await assert.rejects(expired.inspectRequest(targetCert,requestWire));
 }
 assert.throws(()=>codec.fits('"'.repeat(10000)));
 console.log('PASS public neutral REQUEST authority/target/expiry/bounds and both Account ACCEPT-CONFIRM lexical branches; no runtime or UI claim');
})().catch(e=>{console.error(e);process.exitCode=1;});
