'use strict';
// Reproduce the remaining inline recorded-note transport failure without
// publishing plaintext, keys or Account identifiers. No network connection.
const fs=require('node:fs'),vm=require('node:vm');
const {createCore,nacl}=require('../D-MASH PWA/not_messenger/tests/fixtures/core_vm.cjs');
global.nacl=nacl;require('../D-MASH PWA/not_messenger/js/secure_session.js');
const Envelope=require('../D-MASH PWA/not_messenger/js/device_envelope.js');
(async()=>{
 const [a,b]=await Promise.all([createCore(),createCore()]);
 for(const name of ['account_ratchet.js','account_ratchet_runtime.js'])vm.runInContext(fs.readFileSync(require.resolve('../D-MASH PWA/not_messenger/js/'+name),'utf8'),a.ctx);
 a.core.activeIdentity='size-fixture';a.core.blindSalt=nacl.randomBytes(32);
 const shared=Buffer.from(nacl.randomBytes(32)).toString('hex');
 await a.storage.putBox('blind_peers',{alias:b.core.keys.pub_hex,data:{curvePub:Buffer.from(b.core.keys.box.publicKey).toString('hex')}});
 await a.storage.putBox('blind_secrets',{alias:b.core.keys.pub_hex,data:{staticShared:shared,ratchetRoot:shared,ratchetEpoch:1}});
 const recordedBytes=33700;
 const ciphertext=await a.core.encrypt(JSON.stringify({type:'dmash_message',id:crypto.randomUUID(),body:{type:'video_note',name:'recorded-size-fixture',data:'data:video/webm;base64,'+Buffer.alloc(recordedBytes).toString('base64')}}),b.core.keys.pub_hex);
 const envelope={version:1,ciphertext,sender_proof:Buffer.from(nacl.sign.detached(Buffer.from(ciphertext,'hex'),a.core.keys.sign.secretKey)).toString('hex')};
 const payload=JSON.stringify(envelope);
 try{
  const device=Envelope.create(Buffer.from(nacl.sign.keyPair().publicKey).toString('base64url'),'MSG',payload);
  Envelope.seal(nacl.box.keyPair().publicKey,device);
  console.log(JSON.stringify({recordedBytes,accountEnvelopeBytes:Buffer.byteLength(payload),inlineAccepted:true}));
 }catch(error){
  console.log(JSON.stringify({recordedBytes,accountEnvelopeBytes:Buffer.byteLength(payload),inlineAccepted:false,reason:error.message}));
  process.exitCode=1;
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
