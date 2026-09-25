'use strict';
// Kpwd is password-equivalent, not PAKE. Never store it outside encrypted Node storage.
(function(global){
 const PROFILE='ARGON2ID_64M_T3_P1_V1',scriptUrl=global.document?.currentScript?.src;
 const text=value=>new TextEncoder().encode(value),hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 const field=(value,length)=>{if(typeof value!=='string'||!(new RegExp('^[0-9a-f]{'+length+'}$')).test(value))throw Error('Invalid admission field');};
 function challengeBytes(challenge,issuer,applicant,transcriptHash){
  if(!challenge||Object.keys(challenge).sort().join(',')!=='epoch,expires_at,nonce,profile,salt,type,version'||challenge.type!=='NODE_PASSWORD_CHALLENGE'||challenge.version!==4||challenge.profile!==PROFILE)throw Error('Unsupported Node password profile');
  const salt=Uint8Array.from(atob(challenge.salt),c=>c.charCodeAt(0));
  if(salt.length!==16||btoa(String.fromCharCode(...salt))!==challenge.salt)throw Error('Invalid Node salt');
  field(challenge.epoch,32);field(challenge.nonce,64);field(issuer,64);field(applicant,64);
  if(issuer===applicant||!(transcriptHash instanceof Uint8Array)||transcriptHash.length!==32||!Number.isSafeInteger(challenge.expires_at)||challenge.expires_at<0)throw Error('Invalid admission context');
  return text('D-MASH|NODE-ADMISSION|V4\0'+[issuer,applicant,hex(transcriptHash),PROFILE,challenge.salt,challenge.epoch,challenge.nonce,challenge.expires_at].join('|'));
 }
 async function passwordProof(key,challenge,session,{now=Math.floor(Date.now()/1000)}={}){
  if(session.version!==4||session.closed||session.localRole!=='NODE'||session.peerRole!=='NODE'||!global.DmashNodeIdentity.verify(session.localId)||!global.DmashNodeIdentity.verify(session.peerId))throw Error('Authenticated Node work required');
  if(!Number.isSafeInteger(now)||!(now<challenge.expires_at&&challenge.expires_at<=now+90))throw Error('Node password challenge expired');
  if(!(key instanceof Uint8Array)||key.length!==32)throw Error('Invalid Node password key');
  const bytes=challengeBytes(challenge,session.peerId,session.localId,session.transcriptHash);
  const cryptoKey=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const proof=hex(new Uint8Array(await crypto.subtle.sign('HMAC',cryptoKey,bytes)));
  if(session.closed)throw Error('Node session closed');
  return {type:'NODE_PASSWORD_PROOF',version:4,proof};
 }
 let job=null;
 function derivePasswordKey(password,salt,{signal}={}){
  if(typeof password!=='string'||!password||text(password).length>1024||!(salt instanceof Uint8Array)||salt.length!==16)return Promise.reject(Error('Invalid Node password parameters'));
  if(signal?.aborted)return Promise.reject(Error('Node password derivation cancelled'));
  if(job)return Promise.reject(Error('Node password worker busy'));
  if(!global.Worker||!scriptUrl)return Promise.reject(Error('Node password Worker required'));
  return new Promise((resolve,reject)=>{
   const worker=new Worker(scriptUrl);job=worker;
   const finish=(error,key)=>{
    if(job!==worker){key?.fill(0);return;}
    clearTimeout(timer);signal?.removeEventListener('abort',cancel);worker.terminate();job=null;
    if(error){key?.fill(0);reject(error);}else resolve(key);
   };
   const cancel=()=>finish(Error('Node password derivation cancelled'));
   const timer=setTimeout(()=>finish(Error('Node password derivation expired')),90000);
   signal?.addEventListener('abort',cancel,{once:true});
   worker.onerror=()=>finish(Error('Node password Worker failed'));
   worker.onmessage=({data})=>{
    if(!(data?.key instanceof Uint8Array)||data.key.length!==32)finish(Error('Node password derivation failed'));
    else finish(null,data.key);
   };
   worker.postMessage({password,salt});
  });
 }
 if(typeof WorkerGlobalScope!=='undefined'&&global instanceof WorkerGlobalScope){
  importScripts('vendor/argon2-bundled.min.js');
  let used=false;
  global.onmessage=async({data})=>{
   if(used)return;used=true;
   try{
    if(typeof data?.password!=='string'||!data.password||text(data.password).length>1024||!(data.salt instanceof Uint8Array)||data.salt.length!==16)throw Error();
    const result=await global.argon2.hash({pass:data.password,salt:data.salt,time:3,mem:65536,parallelism:1,hashLen:32,type:global.argon2.ArgonType?.Argon2id??2});
    const key=new Uint8Array(result.hash);result.hash.fill(0);
    global.postMessage({key},[key.buffer]);
   }catch(_){global.postMessage({error:true});}
  };
 }
 const api=Object.freeze({PROFILE,challengeBytes,passwordProof,derivePasswordKey});
 global.DmashNodeAdmissionV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
