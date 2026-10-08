'use strict';
// Public challenge transcript only. No Account keys, media, tickets, or root state.
// Reuse the audited synchronous SHA-256 implementation in this dedicated
// worker: a WebCrypto promise per nonce dominates short media setup on phones.
importScripts('resource_pow.js');
const hashCounter=self.DmashResourcePow.decimalSuffixHasher;
let started=false;
self.onmessage=async({data})=>{
 if(started)return;started=true;
 try{
  const {nonce,callId,verifier,difficulty}=data||{};
  if(![nonce,callId,verifier].every(v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v))||!Number.isInteger(difficulty)||difficulty<1||difficulty>20)throw Error('Invalid challenge');
  const hash=hashCounter(new TextEncoder().encode(`${nonce}:${callId}:${verifier}:`)),deadline=Date.now()+25000;
  for(let counter=0;Number.isSafeInteger(counter);counter++){
   const digest=hash(counter);
   if(Date.now()>deadline)throw Error('Admission timeout');
   let bits=difficulty,valid=true;
   for(const byte of digest){const take=Math.min(bits,8);if(byte>>>(8-take)){valid=false;break;}bits-=take;if(!bits)break;}
   if(valid){self.postMessage({counter});return;}
  }
 }catch(_){self.postMessage({error:'Admission work failed'});}
};
