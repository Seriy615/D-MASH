'use strict';
(function(global){
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const hex=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 class AccountManagedInboxV4{
  #host;#session;#journal;#owners;#consume;#progress;#revision=null;#closed=false;#task=null;#cursors=new Map();#next=0;#abort;
  constructor(host,{session,journal,resolveOwners,consume,progress=null}){
   if(!host?.ownerInboxList||!host?.ownerAcknowledgeInbox||!session?.assertCurrent||!session.signal||!journal?.readRouteSnapshot||typeof resolveOwners!=='function'||typeof consume!=='function')fail('MANAGED_INBOX_DEPENDENCY');
   if(progress&&(!progress.load||!progress.save||progress.kind!=='managed'))fail('MANAGED_INBOX_PROGRESS');
   this.#host=host;this.#session=session;this.#journal=journal;this.#owners=resolveOwners;this.#consume=consume;this.#progress=progress;
   this.#abort=()=>this.close();session.signal.addEventListener('abort',this.#abort,{once:true});this.#check();
  }
  #check(){if(this.#closed||this.#host.closed||this.#session.signal.aborted)fail('ACCOUNT_INBOX_UNAVAILABLE');this.#session.assertCurrent();}
  async #wait(promise){this.#check();const value=await promise;this.#check();return value;}
  async #snapshot(peer){
   const value=await this.#wait(this.#journal.readRouteSnapshot(peer));
   if(!value||!['NODE_PROOF_REQUIRED','ROUTE_EXPIRED'].includes(value.readiness)||!value.preparation||!hex(value.localCertificate?.route_id))fail('AUTHENTICATED_INBOX_MAPPING_REQUIRED');
   return value;
  }
  drain(){
   this.#check();if(this.#task)return this.#task;
   const task=this.#run();this.#task=task;task.finally(()=>{if(this.#task===task)this.#task=null;}).catch(()=>{});return task;
  }
  async #checkpoint(){
   if(!this.#progress)return;
   const peers=[...this.#cursors].map(([peer,row])=>({peer,digest:row.digest,generation:row.generation,after:row.after}));
   this.#revision=await this.#wait(this.#progress.save(this.#revision,{next:this.#next,peers}));
  }
  async #run(){
   if(this.#progress){
    const saved=await this.#wait(this.#progress.load());this.#revision=saved.revision;
    this.#cursors=new Map((saved.cursor?.peers||[]).map(row=>[row.peer,{digest:row.digest,generation:row.generation,after:row.after}]));
    this.#next=saved.cursor?.next||0;
   }
   const result={processed:0,deferred:0,failed:0,resync:0},owners=await this.#wait(this.#owners());
   if(!Array.isArray(owners)||owners.length>32||owners.some(x=>!hex(x?.peer)||!x.capability)||new Set(owners.map(x=>x.peer)).size!==owners.length)fail('MANAGED_INBOX_OWNERS');
   const peers=new Set(owners.map(x=>x.peer));let removed=false;for(const peer of this.#cursors.keys())if(!peers.has(peer)){this.#cursors.delete(peer);removed=true;}
   if(removed)await this.#checkpoint();
   if(!owners.length)return result;
   // At most 128 observations/pass; rotate owners and retain cursor even on failure.
   // Rejected frames are never ACKed or deleted and are revisited after wraparound.
   const exhausted=new Set();
   for(let batch=0;batch<4&&exhausted.size<owners.length;batch++){
    this.#check();const owner=owners[this.#next%owners.length];this.#next=(this.#next+1)%owners.length;if(exhausted.has(owner.peer)){batch--;continue;}
    const snapshot=await this.#snapshot(owner.peer),prior=this.#cursors.get(owner.peer);
    const cursor=prior?.digest===snapshot.digest&&prior?.generation===snapshot.generation?prior.after:null;
    const page=await this.#wait(this.#host.ownerInboxList(owner.capability,32,cursor));
    if(!Array.isArray(page?.records)||page.records.length>32)fail('MANAGED_INBOX_PAGE');
    if(!page.records.length){this.#cursors.delete(owner.peer);await this.#checkpoint();exhausted.add(owner.peer);continue;}
    for(const record of page.records){
     this.#check();if(!hex(record?.handle)||!Number.isSafeInteger(record.receivedAt)||record.receivedAt<0)fail('MANAGED_INBOX_RECORD');
     const next={digest:snapshot.digest,generation:snapshot.generation,after:{receivedAt:record.receivedAt,handle:record.handle}};
     if(record.accountSlot!==snapshot.preparation.ownerSlot||record.routeId!==snapshot.localCertificate.route_id||typeof record.payload!=='string'||new TextEncoder().encode(record.payload).length>16000){result.failed++;this.#cursors.set(owner.peer,next);continue;}
     try{
      const accepted=await this.#wait(this.#consume(Object.freeze({peer:owner.peer,frame:record.payload,localRouteId:record.routeId,bindingDigest:snapshot.digest,generation:snapshot.generation})));
      if(accepted?.persisted!==true){result.deferred++;}
      else {
      const latest=await this.#snapshot(owner.peer);
      if(latest.digest!==snapshot.digest||latest.generation!==snapshot.generation||latest.localCertificate.route_id!==record.routeId||latest.preparation.ownerSlot!==record.accountSlot){result.resync++;this.#cursors.delete(owner.peer);await this.#checkpoint();return result;}
      if(await this.#wait(this.#host.ownerAcknowledgeInbox(owner.capability,record.handle)))result.processed++;else result.deferred++;
      }
     }catch(error){this.#check();result.failed++;}
     // Checkpoint once per page. A crash before it replays at most 32 exact
     // opaque records; Account state and wire IDs make the replay idempotent.
     this.#cursors.set(owner.peer,next);
    }
    if(page.records.length<32){this.#cursors.delete(owner.peer);exhausted.add(owner.peer);}
    await this.#checkpoint();
   }
   return result;
  }
  close(){if(this.#closed)return;this.#closed=true;this.#session.signal.removeEventListener('abort',this.#abort);this.#cursors.clear();}
 }
 global.DmashAccountManagedInboxV4=AccountManagedInboxV4;if(typeof module!=='undefined')module.exports=AccountManagedInboxV4;
})(typeof window!=='undefined'?window:globalThis);
