'use strict';
(function(g){
 const host=NativePlatform.host;
 let initializing=false,ready=false,closed=false,signing=null,store=null,inbox=null,routing=null,local=null,ownership=null,bootstrap=null,jobs=null,nodeId=null,ownerGeneration=null;
 const localSessions=new Map();let inboxBusy=false;
 const abort=new AbortController(),channels=new Map(),peers=new Map(),connecting=new Set(),groups=new Map();let pumpQueued=false;
 const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
 const report=event=>host('report',JSON.stringify(event));
 const error=(phase,e)=>report({event:'error',phase,code:'NODE_OPERATION_FAILED',stack:typeof e?.stack==='string'?e.stack.slice(0,2048):''});
 const current=()=>!closed;
 const backend={closed:false,async read(key){if(this.closed)throw Error('closed');return host('relRead',key);},async cas(key,revision,row,options){if(this.closed)throw Error('closed');options.guard();return host('relCas',key,revision,row.iv,new Uint8Array(row.ciphertext),options.binding,options.maxRelationships);},close(){this.closed=true;}};
 const inboxBackend={closed:false,
  check(){if(this.closed||closed)throw Error('Inbox closed');},
  async open(){this.check();return this;},
  async read(key){this.check();return host('inboxRead',key);},
  async all(){this.check();return host('inboxAll');},
  async allBindings(){this.check();return host('inboxBindings');},
  async reconcile(){this.check();host('inboxReconcile');},
  async cas(key,revision,row,{guard=()=>true}={}){this.check();if(!guard())throw Error('Inbox owner session changed');this.check();return host('inboxCas',key,revision,row?row.iv:null,row?new Uint8Array(row.ciphertext):null);},
  async promote(source,sourceRevision,target,targetRevision,row){this.check();return host('inboxPromote',source,sourceRevision,target,targetRevision,row?row.iv:null,row?new Uint8Array(row.ciphertext):null);},
  close(){this.closed=true;}
 };
 const bootstrapBackend={closed:false,
  check(){if(this.closed||closed)throw Error('Bootstrap Inbox closed');},
  async open(){this.check();return this;},
  async read(key){this.check();return host('bootstrapInboxRead',key);},
  async all(){this.check();return host('bootstrapInboxAll');},
  async allBindings(){this.check();return host('bootstrapInboxBindings');},
  async reconcile(){this.check();host('bootstrapInboxReconcile');},
  async cas(key,revision,row,{guard=()=>true}={}){this.check();if(!guard())throw Error('Bootstrap owner session changed');this.check();return host('bootstrapInboxCas',key,revision,row?row.iv:null,row?new Uint8Array(row.ciphertext):null);},
  close(){this.closed=true;}
 };
 async function initialize(data){
  if(initializing||ready||closed)throw Error('Node already initialized');initializing=true;
  try{
   for(const key of ['seed','storageKey','baseNcrh'])if(!(data[key] instanceof Uint8Array)||data[key].length!==32)throw Error('Scoped material required');
   if(host('benchmarkEnabled')){
    const timed=(object,key,label)=>{const original=object[key];const wrapped=function(...args){const started=performance.now();try{return original.apply(this,args);}finally{report({event:'benchmark-primitive',primitive:label,elapsedMs:Math.round((performance.now()-started)*1000)/1000});}};Object.assign(wrapped,original);object[key]=wrapped;};
    timed(nacl.sign.detached,'verify','ed25519-verify');timed(nacl.sign.keyPair,'fromSeed','ed25519-public');timed(nacl,'scalarMult','x25519');
   }
   signing=nacl.sign.keyPair.fromSeed(data.seed);nodeId=hex(signing.publicKey);if(!DmashNodeIdentity.verify(nodeId))throw Error('Node identity work required');
   store=await DmashNodeRelationshipsV4.open(data.storageKey,nodeId,{store:backend,isCurrent:current});
   inbox=await DmashNodeInboxV4.open(data.storageKey,nodeId,{store:inboxBackend,isCurrent:current});if(closed)throw Error('Node closed');
   routing=new DmashNodeRoutingV4(data.baseNcrh);
   local=new DmashNodeLocalDeliveryV4(routing,inbox);const restored=await local.restore({managedOnly:true});
   ownership=new DmashNodeLocalOwnershipV4(local,inbox);
   bootstrap=await DmashNodeBootstrapRuntimeV4.open(data.storageKey,nodeId,{runtime:routing,ownership,local,isCurrent:current,store:bootstrapBackend});
   local.finalControl=(routeId,packet,keys)=>bootstrap.receiveFinal(routeId,packet,keys);
   ownership.detachBootstrap=routeId=>bootstrap.detach(routeId);ownership.archiveRowProvider=owner=>bootstrap.archiveRow(owner);
   const policy=host('jobsOpen',nodeId,data.storageKey,data.transportGeneration,data.policyRevision,data.directEnabled);ownerGeneration=policy.ownerGeneration;
   jobs=new NativeJobRuntime({host,routing,local,inbox,ownership,current,report});ready=true;jobs.wake();report({event:'ready',nodeId,ownerGeneration,role:'NODE',accountsLoaded:false,...restored});
  }finally{data.seed?.fill(0);data.storageKey?.fill(0);data.baseNcrh?.fill(0);initializing=false;}
 }
 function schedule(){if(pumpQueued||closed||!host('jobsPolicy').enabled)return;pumpQueued=true;Promise.resolve().then(()=>{pumpQueued=false;if(closed||!host('jobsPolicy').enabled)return;for(const group of groups.values()){if(connecting.size>=2)break;if(!group.connected&&!group.busy&&!group.timer)void attempt(group);}});}
 function connect(peer){
  if(!ready||closed||!Number.isInteger(peer.index)||peer.index<0||peer.index>=8||typeof peer.nodeId!=='string'||typeof peer.url!=='string')throw Error('Invalid endpoint');
  let group=groups.get(peer.nodeId);
  if(!group){if(groups.size>=8)throw Error('Endpoint limit');group={nodeId:peer.nodeId,urls:[],next:0,failures:0,busy:false,connected:false,timer:null};groups.set(peer.nodeId,group);}
  if(group.urls.some(p=>p.url===peer.url))return;
  if([...groups.values()].reduce((n,g)=>n+g.urls.length,0)>=8)throw Error('Endpoint limit');
  group.urls.push(peer);schedule();
 }
 async function attempt(group){
  group.busy=true;connecting.add(group.nodeId);const peer=group.urls[group.next];group.next=(group.next+1)%group.urls.length;let secure,channel;
  try{
   secure=await DmashNodeSocketV4.connect(peer.url,signing,peer.nodeId,{signal:abort.signal});
   channel=jobs.wrapChannel(await DmashNodeChannelV4.authorize(secure,store,{signal:abort.signal}));
   if(closed)throw Error('Node closed');await routing.addPeer(peer.nodeId,channel);if(closed||secure.signal.aborted)throw Error('Node closed');
   channels.set(peer.index,channel);peers.set(peer.index,peer.nodeId);group.connected=true;group.next=0;group.failures=0;
   secure.signal.addEventListener('abort',()=>{
    if(closed||channels.get(peer.index)!==channel)return;
    channels.delete(peer.index);peers.delete(peer.index);routing.removePeer(peer.nodeId);group.connected=false;
    report({event:'disconnected',index:peer.index});retry(group);
   },{once:true});
   report({event:'connected',index:peer.index,role:channel.secure.session.peerRole,version:channel.secure.session.version});jobs.wake();
  }catch(e){channel?.close();secure?.close();if(!closed){report({event:'endpoint-failed',index:peer.index,code:'PEER_UNAVAILABLE'});retry(group);}}
  finally{group.busy=false;connecting.delete(group.nodeId);schedule();}
 }
 function retry(group){if(closed||group.timer||!host('jobsPolicy').enabled)return;group.failures=Math.min(6,group.failures+1);const delay=Math.min(30000,1000*2**group.failures);group.timer=setTimeout(()=>{group.timer=null;schedule();},delay);}
 async function query(index){if(!ready||closed||!peers.has(index))throw Error('Peer unavailable');try{await routing.requestService(peers.get(index));report({event:'service-reply',index});}catch(e){if(e.message==='SERVICE_UNAVAILABLE'){report({event:'service-unavailable',index,authenticated:true});}else throw e;}}
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys.split(',').sort().join(',');
 const requireKeys=(value,keys)=>{if(!exact(value,keys))throw Error('Invalid request shape');};
 const token=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 const unhex=(value,length=32)=>{if(typeof value!=='string'||value.length!==length*2||!/^[0-9a-f]+$/.test(value))throw Error('Invalid local bytes');return Uint8Array.from(value.match(/../g),x=>parseInt(x,16));};
 function openLocal(data){if(!ready||closed||!token(data.connectionId)||!['owner','broker'].includes(data.role)||localSessions.size>=9||localSessions.has(data.connectionId))throw Error('Local session unavailable');localSessions.set(data.connectionId,{role:data.role,ownerToken:null});}
 function closeLocal(id){const ctx=localSessions.get(id);if(!ctx)return;if(ctx.ownerToken){try{local.releaseOwnerGrants(ctx.ownerToken);}catch(_){}ownership.owners.delete(ctx.ownerToken);}localSessions.delete(id);}
 async function dispatchLocal(data){
  let revoke=false;const {connectionId,id,method,params}=data;
  try{
   if(!ready||closed||!token(id))throw Error('Local actor unavailable');const ctx=localSessions.get(connectionId);if(!ctx)throw Error('Local session unavailable');
   const alive=()=>{if(closed||localSessions.get(connectionId)!==ctx)throw Error('Local session ended');};
   let result;
   if(method==='node.status'){
    requireKeys(params,'');const policy=host('jobsPolicy');result={initialized:ready,role:'NODE',bootstrapProfile:'private-v1',connectedPeers:routing.peers.size,ownerGeneration,transportGeneration:policy.transportGeneration,policyRevision:policy.policyRevision,transportEnabled:policy.enabled,directEnabled:policy.directEnabled};
   }else if(method.startsWith('broker.')){
    if(ctx.role!=='broker')throw Error('Broker scope required');
    if(method==='broker.policy'){
     requireKeys(params,'generation,revision,transportEnabled,directEnabled');if(params.generation!==host('jobsPolicy').transportGeneration||typeof params.transportEnabled!=='boolean'||typeof params.directEnabled!=='boolean')throw Error('Policy scope mismatch');
     result=host('jobsSetPolicy',params.revision,params.transportEnabled,params.directEnabled);jobs.wake();
     for(const group of groups.values()){if(group.timer)clearTimeout(group.timer);group.timer=null;if(params.transportEnabled){group.next=0;group.failures=0;}}schedule();
    }else if(method==='broker.revoke'){
     requireKeys(params,'generation,revision,reason');if(!['FULL_ROOT_LOCK','BROKER_SHUTDOWN','ADMIN_REVOKED'].includes(params.reason))throw Error('Revoke reason');result=host('jobsRevoke',params.generation,params.revision);revoke=true;
    }else throw Error('Unknown broker operation');
   }else{
    if(ctx.role!=='owner')throw Error('Owner scope required');
    const owner=(archive=false)=>{alive();if(!ctx.ownerToken)throw Error('Owner registration required');return ownership.owner(ctx.ownerToken,{archiveAllowed:archive});};
    if(method==='owner.challenge'){
     requireKeys(params,'accountPublic,certificate,archive');if(typeof params.archive!=='boolean')throw Error('Archive flag');result=await ownership.challenge(params.accountPublic,params.certificate,{archive:params.archive});
    }else if(method==='owner.register'){
     requireKeys(params,'challenge,signature');if(ctx.ownerToken)throw Error('Owner already registered');const signature=unhex(params.signature,64);try{result=await ownership.register(params.challenge,signature);}finally{signature.fill(0);}
     try{alive();ctx.ownerToken=result.token;}catch(e){ownership.owners.delete(result.token);throw e;}
    }else if(method==='owner.prepare'){
     requireKeys(params,'migrationId,bindingDigest,expectedGeneration,certificate,discoverySeed,discoveryBox,recipientKeys');owner();if(!Array.isArray(params.recipientKeys)||params.recipientKeys.length<1||params.recipientKeys.length>2)throw Error('Recipient keys');
     const material=[];try{const decode=value=>{const bytes=unhex(value);material.push(bytes);return bytes;};result=await ownership.prepare(ctx.ownerToken,{...params,discoverySeed:decode(params.discoverySeed),discoveryBox:decode(params.discoveryBox),recipientKeys:params.recipientKeys.map(decode)});}finally{for(const bytes of material)bytes.fill(0);}
    }else if(method==='owner.activate'||method==='owner.retire'){
     requireKeys(params,'tuple');owner();requireKeys(params.tuple,'accountPublic,ownerSlot,routeAuthorityDigest,routeId,migrationId,bindingDigest,generation,preparationDigest');result=await ownership.change(ctx.ownerToken,params.tuple,method==='owner.activate'?'ACTIVE':'RETIRED');jobs.wake();
    }else if(method==='owner.query'){requireKeys(params,'migrationId');owner(true);result=await ownership.query(ctx.ownerToken,params.migrationId);
    }else if(method==='owner.release'){requireKeys(params,'');owner(true);local.releaseOwnerGrants(ctx.ownerToken);ownership.owners.delete(ctx.ownerToken);ctx.ownerToken=null;result={released:true};
    }else if(method==='owner.discover'){
     requireKeys(params,'certificate');owner();const found=await local.discover(params.certificate,{ownerToken:ctx.ownerToken});try{owner();}catch(e){local.releaseGrant(found.handle,ctx.ownerToken);throw e;}result=found;
    }else if(method==='owner.releaseGrant'){requireKeys(params,'handle');owner();result=local.releaseGrant(params.handle,ctx.ownerToken);owner();
    }else if(method==='bootstrap.provision'){
     requireKeys(params,'localBundle,discoverySeed,discoveryBox,recipientKeys');owner();if(!Array.isArray(params.recipientKeys)||params.recipientKeys.length!==1)throw Error('Bootstrap recipient key');
     const material=[];try{const decode=value=>{const bytes=unhex(value);material.push(bytes);return bytes;};result=await bootstrap.provision(ctx.ownerToken,{localBundle:params.localBundle,discoverySeed:decode(params.discoverySeed),discoveryBox:decode(params.discoveryBox),recipientKeys:params.recipientKeys.map(decode)});}finally{for(const bytes of material)bytes.fill(0);}
    }else if(method==='bootstrap.list'){requireKeys(params,'');owner(true);result={requests:await bootstrap.dispatcher.list(ctx.ownerToken)};owner(true);
    }else if(method==='bootstrap.select'){requireKeys(params,'exchangeId,requestDigest,deny');owner();if(!token(params.exchangeId)||!token(params.requestDigest)||typeof params.deny!=='boolean')throw Error('Bootstrap selection');result=await bootstrap.dispatcher.select(ctx.ownerToken,params.exchangeId,params.requestDigest,{deny:params.deny});owner();
    }else if(method==='bootstrap.submit'){
     requireKeys(params,'handle,control');owner();if(!params.control||typeof params.control!=='object')throw Error('Bootstrap control');
     if(params.control.kind==='REQUEST')requireKeys(params.control,'kind,targetBundle,serialized');else if(params.control.kind==='RECEIPT')requireKeys(params.control,'kind,exchangeId,serialized');else throw Error('Bootstrap control kind');
     result=await bootstrap.submit(ctx.ownerToken,params.handle,params.control);owner();
    }else if(method==='destination.install'){requireKeys(params,'certificate,replyRouteId');owner();result=await jobs.install(ctx.ownerToken,params.certificate,params.replyRouteId);
    }else if(method==='job.submit'){requireKeys(params,'destination,operationId,blob,expiresAt');owner(true);result=await jobs.submit(ctx.ownerToken,params,alive);
    }else if(method==='job.query'){requireKeys(params,'id');owner(true);result=jobs.query(ctx.ownerToken,params.id);
    }else if(method==='job.cancel'){requireKeys(params,'id');owner();result=jobs.cancel(ctx.ownerToken,params.id);
    }else if(method==='inbox.commitConsumption'){
     requireKeys(params,'recordHandle,applicationCommitToken');const value=owner(true);
     if(!token(params.recordHandle)||typeof params.applicationCommitToken!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(params.applicationCommitToken)||inboxBusy)throw Error('Invalid Inbox commit');
     inboxBusy=true;
     try{
      const row=await inbox.store.read(params.recordHandle);if(!row)throw Error('Inbox record unavailable');
      const record=await inbox.decrypt(row);owner(true);if(record.accountSlot!==value.ownerSlot||record.routeId!==value.routeId)throw Error('Inbox owner mismatch');
      const binding=await ownership.read(value.routeId);ownership.matches(binding,value);owner(true);
      if(!['ACTIVE','RETIRED'].includes(binding.state)||binding.ownership.generation!==binding.certificate.generation)throw Error('Inbox binding unavailable');
      if(record.kind==='seen'){
       if(record.applicationCommitToken!==params.applicationCommitToken||record.routeAuthorityDigest!==value.routeAuthorityDigest||record.generation!==binding.ownership.generation)throw Error('Inbox commit conflict');
      }else{
       if(record.kind!=='pending')throw Error('Inbox record unavailable');
       const consumed={kind:'seen',accountSlot:value.ownerSlot,routeId:value.routeId,routeAuthorityDigest:value.routeAuthorityDigest,generation:binding.ownership.generation,seenAt:Date.now(),applicationCommitToken:params.applicationCommitToken};
       const encrypted=await inbox.encrypt(params.recordHandle,consumed);owner(true);
       if(!await inbox.store.cas(params.recordHandle,row.revision,encrypted,{guard:()=>{owner(true);return true;}}))throw Error('Inbox commit conflict');
      }
      result={committed:true,recordHandle:params.recordHandle,applicationCommitToken:params.applicationCommitToken};
     }finally{inboxBusy=false;}
    }else if(method==='inbox.list'){
     requireKeys(params,'limit,after');const value=owner(true);if(inboxBusy)throw Error('Inbox busy');inboxBusy=true;
     try{result=await inbox.list(value.ownerSlot,params.limit,params.after);owner(true);while(result.records.length>1&&new TextEncoder().encode(JSON.stringify(result)).byteLength>450000)result.records.pop();const last=result.records[result.records.length-1];result.next=last?{receivedAt:last.receivedAt,handle:last.handle}:null;}finally{inboxBusy=false;}
    }else throw Error('Unsupported local operation');
   }
   alive();host('localReply',id,JSON.stringify({ok:true,result}));
   if(revoke){report({event:'transport-revoked',ownerGeneration});stop();}
  }catch(_){if(!closed)host('localReply',id,JSON.stringify({ok:false,code:'REQUEST_REJECTED'}));}
 }
 function stop(){if(closed)return;closed=true;ready=false;for(const group of groups.values())if(group.timer)clearTimeout(group.timer);groups.clear();for(const id of [...localSessions.keys()])closeLocal(id);jobs?.close();bootstrap?.close();ownership?.close();local?.close();abort.abort();for(const channel of channels.values())channel.close();channels.clear();peers.clear();void routing?.close();inbox?.close();store?.close();signing?.secretKey.fill(0);signing=null;NativePlatform.close();}
 g.NativeNode=Object.freeze({openLocal,closeLocal,dispatchLocal:data=>{void dispatchLocal(data);},initialize:data=>{void initialize(data).catch(e=>{error('initialize',e);stop();});},connect:peer=>{try{connect(peer);}catch(e){error('connect',e);}},query:index=>{void query(index).catch(e=>error('query',e));},snapshot:()=>report({event:'snapshot',ready,nodeId,peers:routing?.peers.size||0,stats:routing?.stats||{}}),stop});
})(globalThis);
