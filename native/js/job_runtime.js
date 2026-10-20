'use strict';
// Trusted native adapter around unchanged NodeRouting/LocalDelivery classes.
// All attempt markers are sidecars: none are serialized into mesh packets.
(function(g){
 const text=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
 const decode=s=>new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(s),c=>c.charCodeAt(0)));
 const summary=j=>j&&({id:j.id,state:j.state,attempts:j.attempts,expiresAt:j.expiresAt,retentionUntil:j.retentionUntil,revision:j.revision});
 class NativeJobRuntime{
  constructor({host,routing,local,inbox,ownership,current,report}){
   Object.assign(this,{host,routing,local,inbox,ownership,current,report});
   this.closed=false;this.running=false;this.timer=null;this.busy=new Map();this.destinations=new Set();this.packetJobs=new WeakMap();this.routeJobs=new WeakMap();
   let active=null;const send=routing.send.bind(routing),enqueue=routing.enqueue.bind(routing);
   routing.send=(route,payload,reply)=>{const previous=active,tag=this.routeJobs.get(route);active=tag?.blob===payload?[{id:tag.id,attemptToken:tag.attemptToken}]:null;try{return send(route,payload,reply);}finally{active=previous;}};
   routing.enqueue=(peer,packet)=>{const result=enqueue(peer,packet);if(active)this.packetJobs.set(packet,active.slice());return result;};
  }
  check(){if(this.closed||!this.current())throw Error('Native jobs closed');}
  changed(id){if(this.closed)return;this.report({event:'job-state',id});}
  wrapChannel(channel){
   const runtime=this;return {secure:channel.secure,
    requireAuthorized:()=>channel.requireAuthorized(),receiveOperation:()=>channel.receiveOperation(),close:()=>channel.close(),
    async sendOperation(value){
     const unique=new Map();for(const packet of value?.packets||[])for(const job of runtime.packetJobs.get(packet)||[])unique.set(job.id+'|'+job.attemptToken,job);
     const jobs=[...unique.values()];let guard=null,error=null;
     try{runtime.check();guard=runtime.host('batchGuardBegin',channel.secure.socket._id,JSON.stringify(jobs));await channel.sendOperation(value);}
     catch(e){error=e;throw e;}
     finally{if(guard!==null)try{runtime.host('batchGuardEnd',channel.secure.socket._id,guard);}catch(_){}for(const job of jobs)runtime.result(job,error);}
    }};
  }
  owner(token,archive=false){this.check();return this.ownership.owner(token,{archiveAllowed:archive});}
  async activeReply(owner){const row=await this.ownership.read(owner.routeId);this.check();this.ownership.matches(row,owner);if(row.state!=='ACTIVE'||!this.local.bindings.has(owner.routeId))throw Error('Reply binding unavailable');return row;}
  async install(token,certificate,replyRouteId){
   const owner=this.owner(token);if(replyRouteId!==owner.routeId)throw Error('Reply owner mismatch');
   g.DmashRouteDiscoveryV4.verifyCertificate(certificate);const reply=await this.activeReply(owner);this.owner(token);
   const expiresAt=Math.min(certificate.expires_at,reply.certificate.expires_at)*1000;
   const material=text(g.DmashSecureSession.canonical({v:1,certificate,replyRouteId,replyAuthorityDigest:owner.routeAuthorityDigest}));
   return {handle:this.host('jobsInstall',owner.ownerSlot,material,certificate.generation,expiresAt),expiresAt};
  }
  async submit(token,params,guard){
   const owner=this.owner(token,true);const {destination,operationId,blob,expiresAt}=params;
   if(typeof blob!=='string'||blob.length<96||blob.length>21848)throw Error('Prepared box limit');
   const raw=Uint8Array.from(atob(blob),c=>c.charCodeAt(0));if(raw.length<72||raw.length>16384||btoa(String.fromCharCode(...raw))!==blob)throw Error('Prepared box encoding');
   const body=text(JSON.stringify({v:1,profile:'recipient-box-v2',blob}));
   const previous=this.host('jobsExisting',owner.ownerSlot,destination,operationId,body,expiresAt);if(previous)return {accepted:true,...summary(previous)};
   this.owner(token);const saved=this.host('jobsDestination',owner.ownerSlot,destination);if(!saved)throw Error('Destination unavailable');
   const material=JSON.parse(decode(saved.material));if(material.v!==1||material.replyRouteId!==owner.routeId||material.replyAuthorityDigest!==owner.routeAuthorityDigest)throw Error('Destination owner mismatch');
   g.DmashRouteDiscoveryV4.verifyCertificate(material.certificate);g.DmashRouteDiscoveryV4.validateX25519PublicKey(hex(raw.subarray(0,32)));
   await this.activeReply(owner);this.owner(token);guard();
   const job=this.host('jobsAccept',owner.ownerSlot,destination,operationId,body,expiresAt);this.changed(job.id);this.wake();return {accepted:true,...summary(job)};
  }
  query(token,id){const owner=this.owner(token,true);return summary(this.host('jobsRead',owner.ownerSlot,id));}
  cancel(token,id){const owner=this.owner(token);const result=this.host('jobsCancel',owner.ownerSlot,id);if(result){const busy=this.busy.get(id);if(busy)this.retire(busy);this.changed(id);this.wake();}return {cancelled:result};}
  arm(){
   if(this.closed)return;if(this.timer!==null)clearTimeout(this.timer);this.timer=null;
   const deadline=this.host('jobsNext');if(deadline===null)return;
   this.timer=setTimeout(()=>{this.timer=null;this.tick();},Math.max(25,Math.min(2147483647,deadline-Date.now())));
  }
  wake(){if(this.closed)return;if(this.timer!==null)clearTimeout(this.timer);this.timer=setTimeout(()=>{this.timer=null;this.tick();},0);}
  tick(){
   if(this.closed||this.running)return;this.running=true;
   try{
    const now=Date.now();this.host('jobsPrune');for(const busy of [...this.busy.values()])if(busy.nextAt<=now)this.result(busy,Error('Attempt deadline'));
    for(const job of this.host('jobsDue',4,this.routing.peers.size>0)){
     if(this.busy.has(job.id))continue;
     if(job.expiresAt<=now){this.host('jobsClaim',job.id,job.revision);this.changed(job.id);continue;}
     if(!this.routing.peers.size){this.host('jobsDefer',job.id,job.revision,'WAITING_BOOTSTRAP',job.expiresAt);continue;}
     if(this.busy.size>=2||this.destinations.has(job.destination)){this.host('jobsDefer',job.id,job.revision,'WAITING_PATH',now+1000);continue;}
     const claimed=this.host('jobsClaim',job.id,job.revision,true);if(!claimed)continue;
     this.busy.set(claimed.id,claimed);this.destinations.add(claimed.destination);void this.run(claimed);
    }
   }catch(_){this.report({event:'error',phase:'job-ledger',code:'JOB_STORAGE_FAILED'});}
   finally{this.running=false;this.arm();}
  }
  async run(job){
   try{
    const saved=this.host('jobsDestination',job.scope,job.destination);if(!saved)throw Error('Missing destination');
    const material=JSON.parse(decode(saved.material)),body=JSON.parse(decode(job.body));
    if(material.v!==1||body.v!==1||body.profile!=='recipient-box-v2')throw Error('Unsupported durable job');
    const reply=this.local.bindings.get(material.replyRouteId);if(!reply||reply.retired||reply.ownership?.ownerSlot!==job.scope||reply.ownership?.routeAuthorityDigest!==material.replyAuthorityDigest)throw Error('Binding unavailable');
    const found=await this.local.discover(material.certificate,{ownerToken:job.id});this.check();
    const entry=this.local.routes.get(found.handle);if(!entry)throw Error('Route expired');
    const digest=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(g.DmashSecureSession.canonical(material.certificate)))));
    const route=entry.route;this.routeJobs.set(route,{blob:body.blob,id:job.id,attemptToken:job.attemptToken});
    try{await this.local.sendSealed(found.handle,body.blob,material.replyRouteId,digest,{ownerToken:job.id,guard:()=>this.current()&&!this.closed&&this.host('jobsMaySend',job.id,job.attemptToken)});}finally{this.routeJobs.delete(route);}
    // Remains IN_FLIGHT until the actual unchanged channel send resolves.
   }catch(error){this.result(job,error);}
  }
  retire(job){const current=this.busy.get(job.id);if(!current||current.attemptToken!==job.attemptToken)return false;this.busy.delete(job.id);this.destinations.delete(current.destination);try{this.local.releaseOwnerGrants(job.id);}catch(_){}return true;}
  result(job,error){
   if(this.closed||!this.current())return;const current=this.busy.get(job.id);if(!current||current.attemptToken!==job.attemptToken)return;
   this.retire(current);const jitter=crypto.getRandomValues(new Uint32Array(1))[0]%251;
   const next=Date.now()+Math.min(60000,1000*2**Math.min(6,Math.max(0,current.attempts-1))+jitter);
   try{this.host('jobsFinish',current.id,current.attemptToken,error?'WAITING_PATH':'TRANSPORT_SENT',error?next:0);this.changed(current.id);}catch(_){this.report({event:'error',phase:'job-result',code:'JOB_STORAGE_FAILED'});}this.wake();
  }
  close(){if(this.closed)return;this.closed=true;if(this.timer!==null)clearTimeout(this.timer);this.timer=null;for(const job of [...this.busy.values()])this.retire(job);}
 }
 g.NativeJobRuntime=NativeJobRuntime;
})(globalThis);
