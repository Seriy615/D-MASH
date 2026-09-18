'use strict';
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {sha256, activationDigest} = require('../js/resource_pow.js');
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
