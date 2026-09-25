'use strict';
(function(global){
 const workerUrl=global.document?.currentScript?.src||global.DMASH_NODE_WORKER_URLS?.channel,workers=new Set();
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
 const policy=value=>{
  if(!exact(value,'difficulty,password_challenge,type,version')||value.type!=='NODE_POLICY'||value.version!==4||!Number.isInteger(value.difficulty)||value.difficulty<20||value.difficulty>24||!(value.password_challenge===null||typeof value.password_challenge==='object'))throw Error('Invalid Node policy');
  return value;
 };
 function mine(options,signal){
  if(signal.aborted)return Promise.reject(Error('Node work cancelled'));
  if(!workerUrl||!global.Worker)return Promise.reject(Error('Node work Worker required'));
  if(workers.size>=2)return Promise.reject(Error('Node work admission limit'));
  return new Promise((resolve,reject)=>{
   const worker=new Worker(workerUrl);workers.add(worker);
   const finish=(error,proof)=>{
    if(!workers.has(worker))return;
    workers.delete(worker);clearTimeout(timer);signal.removeEventListener('abort',cancel);worker.terminate();
    if(error)reject(error);else resolve(proof);
   };
   const cancel=()=>finish(Error('Node work cancelled'));
   const timer=setTimeout(()=>finish(Error('Node work expired')),180000);
   signal.addEventListener('abort',cancel,{once:true});
   worker.onerror=()=>finish(Error('Node work Worker failed'));
   worker.onmessage=({data})=>data?.proof?finish(null,data.proof):finish(Error('Node work failed'));
   worker.postMessage(options);
  });
 }
 class NodeChannelV4{
  static async authorize(secure,relationships,{passwordGate=null,peerPasswordKey=null,requirePeerPassword=false,difficulty=22,signal}={}){
   const session=secure.session,abort=new AbortController(),cancel=()=>{abort.abort();secure.close();};
   signal?.addEventListener('abort',cancel,{once:true});
   secure.signal?.addEventListener('abort',cancel,{once:true});
   const timer=setTimeout(cancel,300000);
   try{
    if(signal?.aborted)throw Error('Node authorization cancelled');
    if(session.version!==4||session.closed||session.localRole!=='NODE'||session.peerRole!=='NODE'||!global.DmashNodeIdentity.verify(session.localId)||!global.DmashNodeIdentity.verify(session.peerId)||session.localId===session.peerId)throw Error('Authenticated Node work required');
    await secure.sendJson(policy({type:'NODE_POLICY',version:4,difficulty,password_challenge:passwordGate?await passwordGate.challenge(session):null}));
    const remote=policy(await secure.receiveJson()),challenge=remote.password_challenge;
    if(requirePeerPassword&&challenge===null)throw Error('Node password policy downgrade');
    let proof=null;
    if(challenge!==null){
     await global.DmashNodeAdmissionV4.passwordProof(new Uint8Array(32),challenge,session);
     if(!peerPasswordKey)throw Error('Node password credential missing');
     proof=await global.DmashNodeAdmissionV4.passwordProof(await peerPasswordKey(session.peerId,challenge),challenge,session);
    }
    await secure.sendJson({type:'NODE_ADMISSION',version:4,proof});
    const admission=await secure.receiveJson();
    if(!exact(admission,'proof,type,version')||admission.type!=='NODE_ADMISSION'||admission.version!==4)throw Error('Invalid Node admission');
    if(passwordGate){if(!await passwordGate.verify(session,admission.proof))throw Error('Node admission rejected');}
    else if(admission.proof!==null)throw Error('Unexpected Node password proof');
    await secure.sendJson({type:'NODE_ADMITTED',version:4});
    const admitted=await secure.receiveJson();
    if(!exact(admitted,'type,version')||admitted.type!=='NODE_ADMITTED'||admitted.version!==4)throw Error('Node admission incomplete');
    let relationship=await relationships.relationship(session.peerId);
    const sendRegistration=async()=>{
     const proof=await mine({nodeId:session.peerId,activationType:'DNSS',deviceTransportKey:session.localId,
       resource:global.DmashNodeRegistrationV4.resource(session.localId,session.peerId,relationship.outbound,session.transcriptHash),
       expiresAt:Math.floor(Date.now()/1000)+180,difficulty:remote.difficulty},abort.signal);
     await secure.sendJson({type:'NODE_REGISTER',dnss:relationship.outbound,pow:proof});
    };
    const receiveRegistration=async()=>{
     const value=await secure.receiveJson();
     if(!global.DmashNodeRegistrationV4.verifyRegistration(session,value,difficulty,{expectedDnss:relationship.inbound}))throw Error('Node registration rejected');
     return value;
    };
    const [,request]=await Promise.all([sendRegistration(),receiveRegistration()]);
    if(!global.DmashNodeRegistrationV4.verifyRegistration(session,request,difficulty,{expectedDnss:relationship.inbound}))throw Error('Node registration rejected');
    if(passwordGate)await passwordGate.require(session);
    relationship=await relationships.relationship(session.peerId,{inbound:request.dnss});
    await secure.sendJson({type:'NODE_AUTHORIZED',version:4,dnss:request.dnss});
    const authorized=await secure.receiveJson();
    if(!exact(authorized,'dnss,type,version')||authorized.type!=='NODE_AUTHORIZED'||authorized.version!==4||authorized.dnss!==relationship.outbound)throw Error('Node authorization incomplete');
    const channel=new NodeChannelV4();channel.secure=secure;channel.relationship=relationship;channel.passwordGate=passwordGate;channel.closed=false;
    await channel.requireAuthorized();return channel;
   }catch(error){passwordGate?.forget(session);secure.close();throw error;}
   finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);secure.signal?.removeEventListener('abort',cancel);abort.abort();}
  }
  async requireAuthorized(){
   if(this.closed||this.secure.session.closed)throw Error('Node channel closed');
   if(this.passwordGate)await this.passwordGate.require(this.secure.session);
  }
  async sendOperation(value){await this.requireAuthorized();return this.secure.sendJson(value);}
  async receiveOperation(){await this.requireAuthorized();const value=await this.secure.receiveJson();await this.requireAuthorized();return value;}
  close(){this.closed=true;this.passwordGate?.forget(this.secure.session);this.secure.close();}
 }
 if(typeof WorkerGlobalScope!=='undefined'&&global instanceof WorkerGlobalScope){
  importScripts('resource_pow.js');let used=false;
  global.onmessage=async({data})=>{
   if(used)return;used=true;
   try{
    if(!Number.isInteger(data?.difficulty)||data.difficulty<20||data.difficulty>24||!Number.isSafeInteger(data.expiresAt)||data.expiresAt<=Date.now()/1000||data.expiresAt>Math.floor(Date.now()/1000)+180)throw Error();
    const deadline=Date.now()+180000;
    const proof=await global.DmashResourcePow.mineActivationPow({...data,onProgress:()=>{if(Date.now()>=deadline)throw Error('Node work expired');}});
    const {elapsed_ms,...wire}=proof;
    global.postMessage({proof:wire});
   }catch(_){global.postMessage({error:true});}
  };
 }
 global.DmashNodeChannelV4=NodeChannelV4;
 if(typeof module!=='undefined')module.exports=NodeChannelV4;
})(typeof window!=='undefined'?window:globalThis);
