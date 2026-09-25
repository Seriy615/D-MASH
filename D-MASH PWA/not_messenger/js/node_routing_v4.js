'use strict';
(function(global){
 const token=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const opaque=value=>{
  if(typeof value!=='string'||value.length<96||value.length>21848)throw Error('Invalid opaque box');
  const raw=atob(value);if(raw.length<72||raw.length>16384||btoa(raw)!==value)throw Error('Invalid opaque box');
 };
 const labelKey=(peer,label)=>JSON.stringify([peer,label]);
 const randomLabel=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
 class NodeRoutingV4{
  constructor(base,{clock=()=>Date.now()/1000,monotonic=()=>performance.now()/1000}={}){
   if(!(base instanceof Uint8Array)||base.length!==32)throw Error('Invalid BaseNCRH');
   this.base=base.slice();this.clock=clock;this.monotonic=monotonic;this.peers=new Map();this.owned=[];this.labels=new Map();this.seen=new Map();
   this.queues=new Map();this.timers=new Map();this.senders=new Map();this.tasks=new Set();this.pending=new Set();this.rates=new Map();this.probes=[];
   this.closed=false;this.stats={forwarded:0,received:0,probes:0,batches:0};
  }
  prune(){
   const now=this.clock();this.probes=this.probes.filter(row=>row.packet.expires_at>now&&this.peers.has(row.peer));for(const table of [this.labels,this.seen])for(const [key,row] of table)if(row.expires<=now)table.delete(key);
  }
  label(peer,target,expires){
   this.prune();if(this.labels.size>=4096)throw Error('Node label quota');
   const label=randomLabel();this.labels.set(labelKey(peer,label),{peer,target,expires});return label;
  }
  async dedupe(kind,blob,expires){
   const hash=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(blob))));
   if(this.closed)throw Error('Node runtime closed');
   this.prune();const key=kind+hash;if(this.seen.has(key))return false;
   if(this.seen.size>=4096)throw Error('Node duplicate quota');this.seen.set(key,{expires});return true;
  }
  bindLocal(certificate,sign,box,handler){
   global.DmashRouteDiscoveryV4.verifyCertificate(certificate,Math.floor(this.clock()));
   if(this.closed||this.owned.length>=32)throw Error('Local route unavailable');
   if(hex(sign.publicKey)!==certificate.discovery_sign||hex(box.publicKey)!==certificate.discovery_box)throw Error('Discovery key mismatch');
   if(this.owned.some(row=>row.certificate.route_id===certificate.route_id))throw Error('Route already bound');
   const binding={certificate:{...certificate},sign,box,handler};this.owned.push(binding);
   const task=this.answerCached(binding);this.tasks.add(task);task.finally(()=>this.tasks.delete(task));return binding;
  }
  async answerCached(binding){
   this.prune();for(const row of [...this.probes])try{await this.answerBinding(row.peer,row.packet,binding);}catch(_){}
  }
  async answerBinding(peer,packet,binding){
   if(this.closed||!this.peers.has(peer)||packet.expires_at<=this.clock())return;
   let answer;try{answer=await global.DmashRouteDiscoveryV4.answerQuery(packet.box,binding.certificate,binding.sign,binding.box,{clock:()=>Math.floor(this.clock()),withContext:true});}catch(_){return;}
   if(this.closed||!this.peers.has(peer)||packet.expires_at<=this.clock())return;
   const expires=Math.min(packet.expires_at,answer.expiresAt),offer=this.label(peer,binding.handler,expires);
   this.enqueue(peer,{type:'DATA',version:4,label:packet.return_label,offer,payload:answer.reply,expires_at:expires});
  }
  async addPeer(peer,channel){
   if(this.closed||this.peers.has(peer)||this.peers.size>=8)throw Error('Node peer unavailable');
   await channel.requireAuthorized();
   if(this.closed||this.peers.has(peer)||this.peers.size>=8)throw Error('Node peer unavailable');
   this.peers.set(peer,channel);const task=this.read(peer,channel);this.tasks.add(task);task.finally(()=>this.tasks.delete(task));
  }
  async read(peer,channel){
   try{
    while(!this.closed){
     const batch=await channel.receiveOperation();
     if(!exact(batch,'packets,type,version')||batch.type!=='MESH_BATCH'||batch.version!==4||!Array.isArray(batch.packets)||batch.packets.length<1||batch.packets.length>32||JSON.stringify(batch).length>256*1024)throw Error('Invalid Node batch');
     for(const packet of batch.packets){await channel.requireAuthorized();await this.receive(peer,packet);}
    }
   }catch(_){}
   finally{if(this.peers.get(peer)===channel)this.removePeer(peer);channel.close();}
  }
  removePeer(peer){
   this.peers.delete(peer);this.queues.delete(peer);clearTimeout(this.timers.get(peer));this.timers.delete(peer);this.rates.delete(peer);
   for(const [key,row] of this.labels)if(row.peer===peer||(Array.isArray(row.target)&&row.target[0]===peer))this.labels.delete(key);
   if(!this.peers.size)for(const pending of this.pending)pending.reject(Error('Node path unavailable'));
  }
  enqueue(peer,packet){
   if(this.closed||!this.peers.has(peer))throw Error('Node path unavailable');
   const queue=this.queues.get(peer)||[];this.queues.set(peer,queue);
   const size=JSON.stringify(packet).length;
   let total=0;for(const q of this.queues.values())for(const row of q)total+=row.size;
   if(size>32768||queue.length>=128||total+size>1024*1024)throw Error('Node forwarding queue full');
   queue.push({packet,size,deadline:this.monotonic()+0.5});
   if(!this.timers.has(peer)&&!this.senders.has(peer))this.arm(peer);
  }
  arm(peer){
   const queue=this.queues.get(peer);if(!queue?.length||this.closed)return;
   this.timers.set(peer,setTimeout(()=>this.startSend(peer),Math.max(0,queue[0].deadline-this.monotonic())*1000));
  }
  startSend(peer){this.timers.delete(peer);const task=Promise.resolve().then(()=>this.flush(peer));this.senders.set(peer,task);}
  async flush(peer){
   let timer;
   try{
    const queue=this.queues.get(peer)||[],deadline=queue[0]?.deadline||0,batch=[];let size=0;
    while(queue.length&&queue[0].deadline<deadline+0.5&&batch.length<32){
     const row=queue[0];if(size+row.size>240*1024)break;queue.shift();
     if(row.packet.expires_at>this.clock()){batch.push(row.packet);size+=row.size;}
    }
    if(batch.length){
     await Promise.race([this.peers.get(peer).sendOperation({type:'MESH_BATCH',version:4,packets:batch}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Node send timeout')),10000);})]);
     this.stats.batches++;
    }
   }catch(_){const channel=this.peers.get(peer);this.removePeer(peer);channel?.close();}
   finally{clearTimeout(timer);this.senders.delete(peer);this.arm(peer);}
  }
  async discover(certificate){
   if(this.closed||!this.peers.size)throw Error('Node path unavailable');
   const {blob,state}=global.DmashRouteDiscoveryV4.createQuery(certificate,{now:Math.floor(this.clock())}),expires=state.query.expires_at;
   let resolve,reject,timer,done=false;
   const result=new Promise((yes,no)=>{resolve=value=>{done=true;yes(value);};reject=error=>{done=true;no(error);};});
   // An early disconnect may reject while asynchronous NCRH work is pending.
   result.catch(()=>{});const pending={reject};this.pending.add(pending);
   const accept=async(peer,packet)=>{
    if(done)return;
    const valid=await global.DmashRouteDiscoveryV4.verifyReply(packet.payload,state,{clock:()=>Math.floor(this.clock())});
    if(valid&&!done&&!this.closed&&expires>this.clock()&&this.peers.has(peer))resolve({peer,label:packet.offer,expires_at:Math.min(expires,packet.expires_at),channel:this.peers.get(peer)});
   };
   try{
    await this.dedupe('PROBE',blob,expires);
    const ncrh=await global.DmashProbePrimitivesV4.routeNcrh(this.base,Uint8Array.from(certificate.route_id.match(/../g),b=>parseInt(b,16)));
    const ttl=global.DmashProbePrimitivesV4.sampleHopTtl();
    for(const peer of this.peers.keys()){
     const label=this.label(peer,accept,expires);this.enqueue(peer,{type:'PROBE',version:4,box:blob,return_label:label,ncrh,ttl,expires_at:expires});
    }
    timer=setTimeout(()=>reject(Error('Node discovery expired')),Math.max(1,(expires-this.clock())*1000));
    return await result;
   }finally{
    done=true;clearTimeout(timer);this.pending.delete(pending);state.replyPrivate.fill(0);
    for(const row of this.labels.values())if(row.target===accept)row.target=async()=>{};
   }
  }
  send(route,payload,replyHandler){
   if(route.expires_at<=this.clock()||this.peers.get(route.peer)!==route.channel)throw Error('Node route expired or replaced');
   opaque(payload);const offer=this.label(route.peer,replyHandler,route.expires_at);
   this.enqueue(route.peer,{type:'DATA',version:4,label:route.label,offer,payload,expires_at:route.expires_at});
  }
  async receive(peer,packet){
   if(!packet||packet.version!==4||!Number.isSafeInteger(packet.expires_at)||packet.expires_at>this.clock()+180)throw Error('Invalid Node packet');
   const expires=packet.expires_at;if(expires<=this.clock())return;
   if(packet.type==='PROBE'){
    if(!exact(packet,'box,expires_at,ncrh,return_label,ttl,type,version')||!token(packet.return_label)||!token(packet.ncrh))throw Error('Invalid Probe');
    const remaining=global.DmashProbePrimitivesV4.consumeHop(packet.ttl),blob=packet.box;
    opaque(blob);
    const bucket=Math.floor(this.clock()/60),rate=this.rates.get(peer),count=rate?.bucket===bucket?rate.count:0;
    if(count>=32)throw Error('Probe rate limit');this.rates.set(peer,{bucket,count:count+1});
    if(!await this.dedupe('PROBE',blob,expires)||!this.peers.has(peer))return;this.stats.probes++;
    this.probes.push({peer,packet:{...packet}});this.probes=this.probes.slice(-64);
    if(remaining){
     const ncrh=await global.DmashProbePrimitivesV4.extendNcrh(this.base,packet.ncrh);
     if(this.closed||!this.peers.has(peer))return;
     for(const neighbor of this.peers.keys())if(neighbor!==peer){
      const label=this.label(neighbor,[peer,packet.return_label],expires);this.enqueue(neighbor,{...packet,return_label:label,ttl:remaining,ncrh});
     }
    }
    for(const binding of this.owned)await this.answerBinding(peer,packet,binding);
   }else if(packet.type==='DATA'){
    if(!exact(packet,'expires_at,label,offer,payload,type,version')||!token(packet.label)||!token(packet.offer))throw Error('Invalid DATA');
    opaque(packet.payload);this.prune();const binding=this.labels.get(labelKey(peer,packet.label));if(!binding||expires>binding.expires)return;
    if(!await this.dedupe('DATA',packet.payload,expires)||this.labels.get(labelKey(peer,packet.label))!==binding||!this.peers.has(peer))return;this.stats.received++;
    const target=binding.target;
    if(Array.isArray(target)){
     const offer=this.label(target[0],[peer,packet.offer],expires);this.enqueue(target[0],{...packet,label:target[1],offer});this.stats.forwarded++;
    }else await target(peer,packet);
   }else throw Error('Unsupported Node packet');
  }
  async close(){
   this.closed=true;
   for(const pending of this.pending)pending.reject(Error('Node runtime closed'));
   for(const timer of this.timers.values())clearTimeout(timer);
   for(const channel of this.peers.values())channel.close();
   await Promise.allSettled([...this.tasks,...this.senders.values()]);
   this.peers.clear();this.labels.clear();this.queues.clear();this.seen.clear();this.owned=[];this.rates.clear();this.probes=[];this.base.fill(0);
  }
 }
 global.DmashNodeRoutingV4=NodeRoutingV4;
 if(typeof module!=='undefined')module.exports=NodeRoutingV4;
})(typeof window!=='undefined'?window:globalThis);
