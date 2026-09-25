'use strict';
// Kpwd is password-equivalent, not PAKE. Never store it outside encrypted Node storage.
(function(global){
 const PROFILE='ARGON2ID_64M_T3_P1_V1',scriptUrl=global.document?.currentScript?.src||global.DMASH_NODE_WORKER_URLS?.admission;
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
 function context(session){
  if(session.version!==4||session.closed||session.localRole!=='NODE'||session.peerRole!=='NODE'||session.localId===session.peerId||!global.DmashNodeIdentity.verify(session.localId)||!global.DmashNodeIdentity.verify(session.peerId))throw Error('Authenticated Node work required');
 }
 async function passwordCredential(password,options={}){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  return {profile:PROFILE,salt:btoa(String.fromCharCode(...salt)),epoch:hex(crypto.getRandomValues(new Uint8Array(16))),key:await derivePasswordKey(password,salt,options)};
 }
 class PasswordGate{
  constructor(credential,{clock=()=>Date.now()/1000}={}){
   if(credential?.profile!==PROFILE||!(credential.key instanceof Uint8Array)||credential.key.length!==32)throw Error('Invalid Node password credential');
   this.credential={...credential,key:credential.key.slice()};this.clock=clock;
   this.pending=new Map();this.attempted=new Map();this.authorized=new Set();this.failures=new Map();
   this.overloadUntil=0;this.generation=0;this.closed=false;
  }
  challenge(session){
   context(session);if(this.closed)throw Error('Node gate closed');
   const now=Math.floor(this.clock());
   for(const [peer,row] of this.failures)if(row.expires<=now)this.failures.delete(peer);
   const failure=this.failures.get(session.peerId);
   if(now<this.overloadUntil||(failure&&failure.until>now))throw Error('Node admission cooldown');
   if(!failure&&this.failures.size>=4096)throw Error('Node admission failure quota');
   if(this.attempted.has(session)||this.attempted.size>=256)throw Error('Node admission attempt limit');
   const challenge={type:'NODE_PASSWORD_CHALLENGE',version:4,profile:PROFILE,salt:this.credential.salt,epoch:this.credential.epoch,nonce:hex(crypto.getRandomValues(new Uint8Array(32))),expires_at:now+90};
   challengeBytes(challenge,session.localId,session.peerId,session.transcriptHash);
   const token={challenge,generation:this.generation};
   this.pending.set(session,token);this.attempted.set(session,token);return {...challenge};
  }
  async verify(session,response){
   context(session);if(this.closed)throw Error('Node gate closed');
   const token=this.pending.get(session);this.pending.delete(session);
   if(!token)return false;
   const failed=()=>{
    const now=Math.floor(this.clock());
    if(!this.failures.has(session.peerId)&&this.failures.size>=4096){this.overloadUntil=now+60;return false;}
    const count=Math.min(7,(this.failures.get(session.peerId)?.count||0)+1);
    this.failures.set(session.peerId,{count,until:now+Math.min(60,2**(count-1)),expires:now+600});return false;
   };
   if(Math.floor(this.clock())>=token.challenge.expires_at)return failed();
   if(!response||Object.keys(response).sort().join(',')!=='proof,type,version'||response.type!=='NODE_PASSWORD_PROOF'||response.version!==4)return failed();
   try{
    field(response.proof,64);
    const signature=Uint8Array.from(response.proof.match(/../g),b=>parseInt(b,16));
    const key=await crypto.subtle.importKey('raw',this.credential.key,{name:'HMAC',hash:'SHA-256'},false,['verify']);
    const valid=await crypto.subtle.verify('HMAC',key,signature,challengeBytes(token.challenge,session.localId,session.peerId,session.transcriptHash));
    if(this.closed||session.closed||token.generation!==this.generation||this.attempted.get(session)!==token)return false;
    if(Math.floor(this.clock())>=token.challenge.expires_at||!valid)return failed();
    this.failures.delete(session.peerId);this.authorized.add(session);return true;
   }catch(_){return failed();}
  }
  require(session){context(session);if(this.closed||!this.authorized.has(session))throw Error('Node password admission required');}
  forget(session){this.pending.delete(session);this.attempted.delete(session);this.authorized.delete(session);}
  revokeAll(){this.generation++;this.pending.clear();this.attempted.clear();this.authorized.clear();}
  close(){this.revokeAll();this.closed=true;this.credential.key.fill(0);}
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
 const api=Object.freeze({PROFILE,challengeBytes,passwordProof,derivePasswordKey,passwordCredential,PasswordGate});
 global.DmashNodeAdmissionV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);
