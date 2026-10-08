'use strict';
(function(global){
 const PROFILE='DMASH_NOTE_FRAGMENTS_V1',SLICE=4096,MAX=16*1024*1024,TTL=86400000,WINDOW=8;
 const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
 const hash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
 const canonical=meta=>JSON.stringify([meta.id,meta.count,meta.size,meta.sha256,meta.mediaType,meta.name,meta.mime,meta.expiresAt]);
 const wire=(id,index)=>'media:'+id+':'+index;
 function validate(meta,now){
  if(!meta||!uuid(meta.id)||!Number.isSafeInteger(meta.size)||meta.size<1||meta.size>MAX||
   !Number.isInteger(meta.count)||meta.count!==Math.ceil(meta.size/SLICE)||!/^[0-9a-f]{64}$/.test(meta.sha256||'')||
   !['voice','video_note','video'].includes(meta.mediaType)||typeof meta.name!=='string'||new TextEncoder().encode(meta.name).length>256||
   !/^(audio|video)\/[a-z0-9.+-]+$/i.test(meta.mime||'')||!Number.isSafeInteger(meta.expiresAt)||meta.expiresAt<=now||meta.expiresAt>now+TTL+60000)throw Error('Invalid recorded-note manifest');
 }
 class AccountRecordedMedia{
  constructor(core,storage,{clock=()=>Date.now()}={}){this.core=core;this.storage=storage;this.clock=clock;this.serial=Promise.resolve();this.flushing=null;this.forgotten=new WeakMap();}
  capture(peerId=null){
   const core=this.core,keys=core.keys,salt=core.blindSalt,slot=core.activeIdentity;
   const current=()=>!core._accountTransitioning&&core.keys===keys&&core.blindSalt===salt&&core.activeIdentity===slot&&!!keys?.sign&&!!salt&&
    (!peerId||!this.forgotten.get(keys)?.has(peerId));
   if(!current()||typeof slot!=='string'||!slot)throw Error('Account unavailable');return {keys,slot,current};
  }
  check(session){if(!session.current())throw Error('Account session changed');}
  exclusive(session,fn){const task=this.serial.catch(()=>{}).then(()=>{this.check(session);return fn();});this.serial=task.catch(()=>{});return task;}
  async alias(session,label){const alias=await this.storage.getAlias(label,'L3');this.check(session);return alias;}
  async read(session,table,label){const alias=await this.alias(session,label),row=await this.storage.getBox(table,alias);this.check(session);return row;}
  async write(session,table,label,row){const alias=await this.alias(session,label);await this.storage.putBox(table,{alias,data:row});this.check(session);}
  async remove(session,table,label){await this.storage.deleteBox(table,await this.alias(session,label));this.check(session);}
  async operations(session){const rows=await this.storage.getAllBoxes('blind_outbox');this.check(session);return rows.filter(row=>row.record==='media_outbound');}
  async noteData(session,operation){const note=global.DmashChatPassword?await global.DmashChatPassword.reveal(this.storage,operation.peerID,operation.content):operation.content;this.check(session);return note;}
  async send(session,peer,body,id=null){
   this.check(session);
   const sent=await this.core.sendMessage(body,false,peer,'media-control',true,null,id,session.current);
   this.check(session);return sent===true;
  }
  async queue(peer,note){
   const session=this.capture(peer);
   if(!/^[0-9a-f]{64}$/.test(peer||'')||!['voice','video_note','video'].includes(note?.type)||typeof note.data!=='string')throw Error('Invalid recorded note');
   const delimiter=note.data.indexOf(';base64,'),mime=note.data.slice(5).split(';')[0];
   if(!note.data.startsWith('data:')||delimiter<0||!/^(audio|video)\/[a-z0-9.+-]+$/i.test(mime))throw Error('Unsupported recorded data');
   const encoded=note.data.slice(delimiter+8);if(!encoded||encoded.length>MAX||!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded))throw Error('Invalid recorded encoding or size');
   if(mime.length+13+encoded.length>MAX)throw Error('Recorded note exceeds size bound');
   const data='data:'+mime+';base64,'+encoded,id=crypto.randomUUID(),meta={id,size:data.length,count:Math.ceil(data.length/SLICE),
    sha256:await hash(data),mediaType:note.type,name:String(note.name||'recorded').slice(0,80),mime,expiresAt:this.clock()+TTL};
   this.check(session);validate(meta,this.clock());
   const content={type:meta.mediaType,name:meta.name,mime,data};
   const protectedNote=global.DmashChatPassword?await global.DmashChatPassword.protect(this.storage,peer,content):content;this.check(session);
   await this.exclusive(session,async()=>{
    const entries=await this.operations(session);
    if(entries.filter(row=>row.status!=='failed').length>=4||entries.filter(row=>row.peerID===peer&&row.status!=='failed').length>=2)throw Error('Recorded-note queue full');
    await this.write(session,'blind_outbox','media-out:'+peer+':'+id,{record:'media_outbound',peerID:peer,meta,content:protectedNote,
     nonce:Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join(''),status:'profile',profileAttempts:0,nextProfileAt:0,profileDeadline:0,acked:[],sentAt:{}});
    if(!await this.storage.hasMessageWireId(peer,id)){this.check(session);await this.storage.saveMessageGamma(peer,content,false,true,'QUEUED',id);this.check(session);}
   });
   if(this.core.activePeerId===peer)await this.core.loadChat?.();else await this.core.renderPeers?.();
   void this.flush().catch(()=>{});return true;
  }
  flush(){
   if(this.flushing)return this.flushing;
   let session;try{session=this.capture();}catch(_){return Promise.resolve();}
   const task=this.runFlush(session);this.flushing=task;return task.finally(()=>{if(this.flushing===task)this.flushing=null;});
  }
  async fail(session,operation,reason){operation.status='failed';operation.failure=reason;operation.content=null;await this.write(session,'blind_outbox','media-out:'+operation.peerID+':'+operation.meta.id,operation);
   await this.storage.markMessageSendFailure?.(operation.peerID,operation.meta.id,reason);this.check(session);
   this.core.refreshMessageTransportState?.(operation.peerID,operation.meta.id,'FAILED');}
  async runFlush(session){
   await this.exclusive(session,()=>this.purge(session));
   const rows=await this.operations(session);
   for(const row of rows){
    this.check(session);if(this.forgotten.get(session.keys)?.has(row.peerID))continue;
    const peerSession=this.capture(row.peerID);
    let work;
    try{work=await this.exclusive(peerSession,async()=>{
     const operation=await this.read(peerSession,'blind_outbox','media-out:'+row.peerID+':'+row.meta.id);if(!operation||operation.status==='failed')return [];
     // Recover a crash between durable SEND intent and its local history row.
     if(!operation.historyCommitted){
      if(!await this.storage.hasMessageWireId(operation.peerID,operation.meta.id)){
       this.check(peerSession);const note=await this.noteData(peerSession,operation);
       await this.storage.saveMessageGamma(operation.peerID,note,false,true,'QUEUED',operation.meta.id);this.check(peerSession);
      }
      operation.historyCommitted=true;await this.write(peerSession,'blind_outbox','media-out:'+operation.peerID+':'+operation.meta.id,operation);
     }
     const now=this.clock();if(operation.meta.expiresAt<=now){await this.fail(peerSession,operation,'expired');return [];}
     if(this.core.accountTransportMode()==='legacy'){await this.fail(peerSession,operation,'transport-unavailable');return [];}
     const secrets=await this.storage.getBox('blind_secrets',await this.storage.getAlias(operation.peerID,'L1'));this.check(peerSession);
     if(!secrets?.staticShared)return [];
     if(operation.status==='profile'){
      if(operation.profileDeadline&&now>=operation.profileDeadline){await this.fail(peerSession,operation,'profile-unavailable');return [];}
      if(operation.nextProfileAt>now)return [];
      if(operation.profileAttempts>=3){await this.fail(peerSession,operation,'profile-unavailable');return [];}
      operation.profileAttempts++;operation.profileDeadline ||= now+120000;operation.nextProfileAt=now+30000;
      await this.write(peerSession,'blind_outbox','media-out:'+operation.peerID+':'+operation.meta.id,operation);
      return [{peer:operation.peerID,body:{type:'voip_media_profile_request',profile:PROFILE,id:operation.meta.id,nonce:operation.nonce,expiresAt:operation.profileDeadline}}];
     }
     const note=await this.noteData(peerSession,operation),pending=[];
     for(let index=0;index<operation.meta.count&&pending.length<WINDOW;index++)if(!operation.acked.includes(index))pending.push(index);
     if(!pending.length)pending.push(operation.meta.count-1); // Recover a lost final receipt.
     const jobs=[];
     for(const index of pending){
      if(operation.sentAt[index]&&now-operation.sentAt[index]<10000)continue;
      operation.sentAt[index]=now;
      jobs.push({peer:operation.peerID,id:wire(operation.meta.id,index),body:{type:'dmash_media_fragment',version:1,nonce:operation.nonce,meta:operation.meta,index,data:note.data.slice(index*SLICE,(index+1)*SLICE)}});
     }
     await this.write(peerSession,'blind_outbox','media-out:'+operation.peerID+':'+operation.meta.id,operation);return jobs;
    });}catch(_){continue;}
    for(const job of work){if(!peerSession.current())return;try{await this.send(peerSession,job.peer,job.body,job.id);}catch(_){break;}}
   }
  }
  async index(session){return await this.read(session,'pairing_material','media-index')||{record:'media_index',entries:[]};}
  async purge(session){
   const ledger=await this.index(session),entry=ledger.entries.find(value=>value.expiresAt<=this.clock());if(!entry)return;
   const label='media-in:'+entry.peerId+':'+entry.id;
   for(let index=0;index<Math.ceil(entry.size/SLICE);index++)await this.remove(session,'pairing_material',label+':'+index);
   await this.remove(session,'pairing_material',label);
   ledger.entries=ledger.entries.filter(value=>value!==entry);await this.write(session,'pairing_material','media-index',ledger);
  }
  async profile(message,peer,current){
   if(!message.type?.startsWith('voip_media_profile_')&&message.type!=='voip_media_complete')return null;
   const session=this.capture(peer);if(!current())return false;
   if(!uuid(message.id)||message.profile!==PROFILE)throw Error('Unsupported recorded-note profile');
   if(message.type==='voip_media_profile_request'){
    if(!/^[0-9a-f]{64}$/.test(message.nonce||'')||!Number.isSafeInteger(message.expiresAt)||message.expiresAt<=this.clock()||message.expiresAt>this.clock()+180000)throw Error('Invalid recorded-note profile challenge');
    const known=await this.storage.getBox('blind_peers',await this.storage.getAlias(peer,'L1'));this.check(session);if(!known||!current())return false;
    let permitted=true;
    await this.exclusive(session,async()=>{
     await this.purge(session);
     const ledger=await this.index(session),previous=ledger.entries.find(entry=>entry.peerId===peer&&entry.id===message.id);
     if(previous){if(previous.nonce!==message.nonce||previous.expiresAt<=this.clock())throw Error('Recorded-note permit context mismatch');return;}
     const active=ledger.entries.filter(entry=>!entry.complete&&entry.expiresAt>this.clock());
     if(active.length>=4||active.filter(entry=>entry.peerId===peer).length>=2||ledger.entries.length>=64){permitted=false;return;}
     ledger.entries.push({peerId:peer,id:message.id,nonce:message.nonce,size:0,expiresAt:this.clock()+TTL,complete:false});
     await this.write(session,'pairing_material','media-index',ledger);
    });
    return this.send(session,peer,{type:'voip_media_profile_response',profile:PROFILE,id:message.id,nonce:message.nonce,expiresAt:message.expiresAt,maxBytes:MAX,supported:permitted});
   }
   return this.exclusive(session,async()=>{
    const operation=await this.read(session,'blind_outbox','media-out:'+peer+':'+message.id);if(!operation)return true;
    if(!current())return false;
    if(message.type==='voip_media_complete'){
     if(operation.status!=='sending'||message.sha256!==operation.meta.sha256)throw Error('Invalid recorded-note completion');
     await this.storage.updateMessageTransportState(peer,message.id,'DELIVERED');this.check(session);
     await this.remove(session,'blind_outbox','media-out:'+peer+':'+message.id);
     this.core.refreshMessageTransportState?.(peer,message.id,'DELIVERED');return true;
    }
    if(message.type!=='voip_media_profile_response'||message.nonce!==operation.nonce||message.expiresAt!==operation.profileDeadline||message.maxBytes!==MAX||typeof message.supported!=='boolean')throw Error('Recorded-note profile response context mismatch');
    if(['sending','failed'].includes(operation.status))return true;
    if(operation.status!=='profile'||message.expiresAt<=this.clock())throw Error('Recorded-note profile response expired');
    if(!message.supported){await this.fail(session,operation,'receiver-refused');return true;}
    operation.status='sending';await this.write(session,'blind_outbox','media-out:'+peer+':'+message.id,operation);return true;
   });
  }
  async receipt(peer,id,state){
   const match=/^media:([0-9a-f-]{36}):(\d{1,4})$/.exec(id||'');
   if(!match){if(!uuid(id))return false;const session=this.capture(peer);return !!await this.read(session,'blind_outbox','media-out:'+peer+':'+id);}
   if(state!=='DELIVERED')return false;
   const session=this.capture(peer);
   return this.exclusive(session,async()=>{
    const operation=await this.read(session,'blind_outbox','media-out:'+peer+':'+match[1]);if(!operation)return true;
    const index=Number(match[2]);if(operation.status!=='sending'||index>=operation.meta.count)throw Error('Invalid recorded-note fragment receipt');
    if(!operation.acked.includes(index)){operation.acked.push(index);await this.write(session,'blind_outbox','media-out:'+peer+':'+match[1],operation);}return true;
   });
  }
  async fragment(body,id,peer,current){
   const session=this.capture(peer);validate(body.meta,this.clock());
   const meta=body.meta;
   if(body.type!=='dmash_media_fragment'||body.version!==1||!Number.isInteger(body.index)||body.index<0||body.index>=meta.count||
    id!==wire(meta.id,body.index)||typeof body.data!=='string'||body.data.length!==Math.min(SLICE,meta.size-body.index*SLICE)||!/^[-A-Za-z0-9+/=;:.,]+$/.test(body.data))throw Error('Invalid recorded-note fragment');
   const partHash=await hash(body.data);this.check(session);if(!current())return false;
   let created=false,note;
   const result=await this.exclusive(session,async()=>{
    const ledger=await this.index(session),label='media-in:'+peer+':'+meta.id;
    const permit=ledger.entries.find(entry=>entry.peerId===peer&&entry.id===meta.id);
    if(!permit||permit.nonce!==body.nonce||permit.expiresAt<=this.clock())throw Error('Unnegotiated recorded-note fragment');
    if(permit.size&&permit.size!==meta.size)throw Error('Conflicting recorded-note allocation');
    if(!permit.size){
     const reserved=ledger.entries.filter(entry=>!entry.complete&&entry.expiresAt>this.clock()).reduce((n,e)=>n+e.size,0);
     if(reserved+meta.size>32*1024*1024)throw Error('Recorded-note assembly byte quota');
     permit.size=meta.size;await this.write(session,'pairing_material','media-index',ledger);
    }
    let assembly=await this.read(session,'pairing_material',label);
    if(assembly&&canonical(assembly.meta)!==canonical(meta))throw Error('Conflicting recorded-note manifest');
    if(!assembly){
     assembly={record:'media_assembly',peerId:peer,meta,hashes:{},complete:false};
    }
    if(assembly.hashes[body.index]&&assembly.hashes[body.index]!==partHash)throw Error('Conflicting recorded-note duplicate');
    if(!assembly.complete){
     await this.write(session,'pairing_material',label+':'+body.index,{record:'media_piece',peerId:peer,id:meta.id,index:body.index,data:body.data});
     assembly.hashes[body.index]=partHash;await this.write(session,'pairing_material',label,assembly);
     if(Object.keys(assembly.hashes).length===meta.count){
      const parts=[];
      for(let index=0;index<meta.count;index++){const part=await this.read(session,'pairing_material',label+':'+index);if(!part||await hash(part.data)!==assembly.hashes[index])throw Error('Recorded-note assembly incomplete');this.check(session);parts.push(part.data);}
      const data=parts.join('');if(data.length!==meta.size||await hash(data)!==meta.sha256)throw Error('Recorded-note digest mismatch');this.check(session);
      if(!data.startsWith('data:'+meta.mime+';base64,'))throw Error('Recorded-note MIME mismatch');
      note={type:meta.mediaType,name:meta.name,mime:meta.mime,data};
      if(!await this.storage.hasMessageWireId(peer,meta.id)){
       this.check(session);if(!current())return null;
       await this.storage.saveMessageGamma(peer,note,true,this.core.activePeerId===peer,null,meta.id);this.check(session);created=true;
      }
      assembly.complete=true;await this.write(session,'pairing_material',label,assembly);
      const entry=ledger.entries.find(entry=>entry.peerId===peer&&entry.id===meta.id);if(entry)entry.complete=true;
      await this.write(session,'pairing_material','media-index',ledger);
      for(let index=0;index<meta.count;index++)await this.remove(session,'pairing_material',label+':'+index);
     }
    }
    return {complete:assembly.complete};
   });
   if(!result||!current())return false;
   if(created){if(this.core.activePeerId===peer)await this.core.loadChat?.();else await this.core.renderPeers?.();}
   const acknowledged=await this.send(session,peer,{type:'dmash_receipt',id,state:'DELIVERED'});
   if(result.complete&&!await this.send(session,peer,{type:'voip_media_complete',profile:PROFILE,id:meta.id,sha256:meta.sha256}))return false;
   return current()&&acknowledged;
  }
  async forgetPeer(peer){
   const session=this.capture();let peers=this.forgotten.get(session.keys);if(!peers){peers=new Set();this.forgotten.set(session.keys,peers);}peers.add(peer);
   await this.exclusive(session,async()=>{const ledger=await this.index(session);ledger.entries=ledger.entries.filter(entry=>entry.peerId!==peer);await this.write(session,'pairing_material','media-index',ledger);});
  }
  allowPeer(peer){if(this.core.keys)this.forgotten.get(this.core.keys)?.delete(peer);}
 }
 AccountRecordedMedia.PROFILE=PROFILE;AccountRecordedMedia.SLICE=SLICE;AccountRecordedMedia.MAX=MAX;
 global.DmashAccountRecordedMedia=AccountRecordedMedia;
 if(typeof module!=='undefined')module.exports=AccountRecordedMedia;
})(typeof window!=='undefined'?window:globalThis);
