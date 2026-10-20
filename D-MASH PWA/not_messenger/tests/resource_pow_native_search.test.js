'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),{createHash}=require('node:crypto');
const source=fs.readFileSync(require('node:path').join(__dirname,'../js/resource_pow.js'),'utf8');
function context(search){
 const calls=[];const scope={Uint8Array,Uint32Array,DataView,ArrayBuffer,TextEncoder,Date,Number,Error,Set,Math,Promise,setTimeout,performance,importScripts(){},DmashNativeNonceHasher(prefix){
  const digest=nonce=>{const suffix=Buffer.alloc(8);suffix.writeBigUInt64BE(BigInt(nonce));return new Uint8Array(createHash('sha256').update(prefix).update(suffix).digest());};
  digest.search=(nonce,count,difficulty)=>{calls.push({nonce,count,difficulty});return search({nonce,count,difficulty,digest});};return digest;
 }};vm.runInNewContext(source,scope);return {pow:scope.DmashResourcePow,calls};
}
const input={nodeId:'peer',activationType:'DNSS',deviceTransportKey:'node',resource:new Uint8Array([1,2,3]),expiresAt:2000000000,difficulty:0};
(async()=>{
 // Search skips a complete bounded batch; the protocol still verifies the
 // returned nonce/digest using its independent complete-transcript SHA.
 const {pow,calls}=context(({nonce,digest})=>nonce===0?null:{nonce,digest:digest(nonce)});const progress=[];
 const result=await pow.mineActivationPow({...input,onProgress:p=>progress.push(p)});
 assert.equal(result.nonce,4096);assert.equal(calls.length,2);assert.equal(calls[0].count,4096);assert.equal(progress[0].attempts,4096);
 assert.equal(result.digest,Buffer.from(pow.activationDigest(input.nodeId,input.activationType,input.deviceTransportKey,input.resource,4096,input.expiresAt)).toString('hex'));
 for(const faulty of [({nonce,count,digest})=>({nonce:nonce+count,digest:digest(nonce+count)}),({nonce,digest})=>{const bytes=digest(nonce);bytes[0]^=1;return {nonce,digest:bytes};},()=>({nonce:0,digest:new Uint8Array(32)})]){
  await assert.rejects(context(faulty).pow.mineActivationPow(input),/Native PoW search/);
 }
 const edge=context(({nonce,count,digest})=>{assert.equal(count,1);return {nonce,digest:digest(nonce)};});assert.equal((await edge.pow.mineActivationPow({...input,startNonce:Number.MAX_SAFE_INTEGER})).nonce,Number.MAX_SAFE_INTEGER);
 const cancelled=context(()=>null);await assert.rejects(cancelled.pow.mineActivationPow({...input,onProgress(){throw Error('deadline/cancel');}}),/deadline\/cancel/);assert.equal(cancelled.calls.length,1);
 await assert.rejects(context(()=>null).pow.mineActivationPow({...input,startNonce:Number.MAX_SAFE_INTEGER}),/nonce space exhausted/);
 console.log('optional native nonce search: bounded batches, independent full digest, progress/cancel, invalid result rejection and safe-integer edge PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
