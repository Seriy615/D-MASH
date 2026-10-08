'use strict';
// Public challenge transcript only. No Account keys, media, tickets, or root state.
let started=false;
self.onmessage=async({data})=>{
 if(started)return;started=true;
 try{
  const {nonce,callId,verifier,difficulty}=data||{};
  if(![nonce,callId,verifier].every(v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v))||!Number.isInteger(difficulty)||difficulty<1||difficulty>20)throw Error('Invalid challenge');
  const encoder=new TextEncoder(),deadline=Date.now()+25000;
  for(let counter=0;Number.isSafeInteger(counter);counter++){
   const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(`${nonce}:${callId}:${verifier}:${counter}`)));
   if(Date.now()>deadline)throw Error('Admission timeout');
   let bits=difficulty,valid=true;
   for(const byte of hash){const take=Math.min(bits,8);if(byte>>>(8-take)){valid=false;break;}bits-=take;if(!bits)break;}
   if(valid){self.postMessage({counter});return;}
  }
 }catch(_){self.postMessage({error:'Admission work failed'});}
};
