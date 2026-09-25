'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
const discovery=require('../js/route_discovery_v4.js'),api=require('../js/recipient_payload_v4.js');
const recipient=nacl.box.keyPair(),previous=nacl.box.keyPair();
try{
 for(const size of [256,1024,16384]){
  const cover=api.coverBox(size);assert.equal(atob(cover).length,size);
  assert.deepEqual(api.openPayload([recipient.secretKey],cover),{status:'discard'});
  assert.deepEqual(api.openPayload(null,cover),{status:'deferred'});
 }
 const real=api.sealPayload(recipient.publicKey,'opaque Account envelope');
 const accepted=api.openPayload([previous.secretKey,recipient.secretKey],real);
 assert.equal(accepted.status,'accepted');assert.equal(accepted.payload,'opaque Account envelope');assert.equal(accepted.packet_id.length,64);
 assert.deepEqual(api.openPayload([],real),{status:'deferred'});
 assert.deepEqual(api.openPayload([previous.secretKey],real),{status:'discard'});
 for(const invalid of [false,0,'',[32],[new Uint8Array(31)],[recipient.secretKey,recipient.secretKey,recipient.secretKey]])assert.throws(()=>api.openPayload(invalid,real));
 for(const size of [true,255,16385,1.5])assert.throws(()=>api.coverBox(size));
 assert.deepEqual(api.openPayload([recipient.secretKey],discovery.seal(recipient.publicKey,{payload:'not a valid envelope'})),{status:'discard'});
 console.log('PASS opaque cover discard, unavailable-key deferral, recipient rotation and real payload after cover');
}finally{recipient.secretKey.fill(0);previous.secretKey.fill(0);}
