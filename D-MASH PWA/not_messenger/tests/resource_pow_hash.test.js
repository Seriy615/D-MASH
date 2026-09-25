'use strict';
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {sha256, activationDigest, mineActivationPow} = require('../js/resource_pow.js');
// Exercise SHA padding boundaries and overflowing round sums against an
// independent implementation, not a second copy of the compression function.
for (const size of [0,1,31,55,56,63,64,65,119,120,127,128,200,255,256,1024,4096]) {
 for (const pattern of [0,255,73]) {
  const input=Uint8Array.from({length:size},(_,i)=>pattern===73?(i*73+19)&255:pattern);
  assert.deepEqual(Buffer.from(sha256(input)),createHash('sha256').update(input).digest());
 }
}
const digest=activationDigest('aa'.repeat(32),'DNSS','bb'.repeat(32),new Uint8Array(16),42,2000000000);
assert.equal(digest.length,32);
console.log('PoW SHA-256 matches native SHA-256 at block/padding boundaries');

(async()=>{
 const field=(size,value)=>{const out=Buffer.alloc(size);size===2?out.writeUInt16BE(value):out.writeUInt32BE(value);return out;};
 const wide=value=>{const out=Buffer.alloc(8);out.writeBigUInt64BE(BigInt(value));return out;};
 const nodeId='aa'.repeat(32),deviceTransportKey='bb'.repeat(32),expiresAt=2000000000;
 // Cover every prefix remainder, both SHA padding paths and uint32 carry.
 for(let length=0;length<=130;length++)for(const nonce of [0,1,0xffffffff,0x100000000,Number.MAX_SAFE_INTEGER]){
  const resource=Uint8Array.from({length},(_,i)=>(i*73+19)&255);
  const proof=await mineActivationPow({nodeId,deviceTransportKey,activationType:'DNSS',resource,expiresAt,difficulty:0,startNonce:nonce});
  const bytes=Buffer.concat([Buffer.from('D-MASH|ACTIVATION-POW|V2\0'),field(2,64),Buffer.from(nodeId),Buffer.from('DNSS\0'),field(2,64),Buffer.from(deviceTransportKey),field(4,length),Buffer.from(resource),wide(expiresAt),wide(nonce)]);
  assert.equal(proof.nonce,nonce);
  assert.equal(proof.digest,createHash('sha256').update(bytes).digest('hex'));
 }
 console.log('Cached-prefix PoW matches independent native SHA-256 for every block remainder and safe-integer nonce boundary');
})().catch(error=>{console.error(error);process.exitCode=1;});
