'use strict';
(function(global){
 const MAX=16*1024*1024,AUTO=2*1024*1024,QUOTA=128*1024*1024;
 const hex=x=>Array.from(x,b=>b.toString(16).padStart(2,'0')).join(''),id=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
 const encode=x=>new TextEncoder().encode(x),hash=async x=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',x)));
 const b64=x=>{let s='';for(let i=0;i<x.length;i+=8192)s+=String.fromCharCode(...x.subarray(i,i+8192));return btoa(s);};
 const raw=x=>Uint8Array.from(atob(x),c=>c.charCodeAt(0));
 const BASE64_ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
 function recorderMime(value,type){
  if(typeof value!=='string'||!value||value.length>512||/[^\x20-\x7e]/.test(value))throw Error('Формат записи не поддерживается');
  const [essence,...parameters]=value.split(';'),base=essence.trim().toLowerCase();
  const category=type==='voice'?'audio':type==='video_note'?'video':null;
  if(!category||!new RegExp('^'+category+'/[a-z0-9.+-]+$').test(base))throw Error('Формат записи не поддерживается');
  const names=new Set();
  for(const part of parameters){
   const match=/^\s*([a-z][a-z0-9_-]{0,31})\s*=\s*(?:"([a-z0-9.+,_/ -]{1,128})"|([a-z0-9.+_/-]+(?:\s*,\s*[a-z0-9.+_/-]+)*))\s*$/i.exec(part);
   if(!match||names.has(match[1].toLowerCase()))throw Error('Формат записи не поддерживается');
   names.add(match[1].toLowerCase());
  }
  return base;
 }
 function recorderData(value,type,declaredMime){
  if(typeof value!=='string'||!/^data:/i.test(value))throw Error('Формат записи не поддерживается');
  const header=value.slice(0,526),delimiter=header.toLowerCase().lastIndexOf(';base64,');
  if(delimiter<5||delimiter>517)throw Error('Формат записи не поддерживается');
  const mime=recorderMime(value.slice(5,delimiter),type);
  if(declaredMime&&recorderMime(declaredMime,type)!==mime)throw Error('Формат записи не поддерживается');
  const encoded=value.slice(delimiter+8);
  if(encoded.length>Math.ceil(MAX/3)*4)throw Error('Запись превышает 16 МиБ. Разделите её на несколько частей.');
  if(!encoded||!(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)))throw Error('Формат записи не поддерживается');
  let bytes;try{bytes=raw(encoded);}catch(_){throw Error('Формат записи не поддерживается');}
  if(!bytes.length||(encoded.endsWith('==')&&(BASE64_ALPHABET.indexOf(encoded.at(-3))&15)!==0)||(encoded.endsWith('=')&&!encoded.endsWith('==')&&(BASE64_ALPHABET.indexOf(encoded.at(-2))&3)!==0))throw Error('Формат записи не поддерживается');
  if(bytes.length>MAX)throw Error('Запись превышает 16 МиБ. Разделите её на несколько частей.');
  return {mime,encoded,bytes};
 }
 class RecordedNoteTurn {
  constructor(core,storage){this.core=core;this.storage=storage;this.tasks=new Map();this.peerEpochs=new WeakMap();this.serial=Promise.resolve();this.incoming=Promise.resolve();this.flushing=null;global.DeviceRoot?.onLock?.(()=>this.close());}
  capture(peer=null){const c=this.core,s=this.storage,keys=c.keys,salt=c.blindSalt,slot=c.activeIdentity,db=s.db,key=s.masterKey,root=global.DeviceRoot?.state;
   const epoch=this.peerEpochs.get(keys)?.get(peer)?.generation||0;
   const current=()=> (!peer||((this.peerEpochs.get(keys)?.get(peer)?.generation||0)===epoch&&!this.peerEpochs.get(keys)?.get(peer)?.blocked))&&!c._accountTransitioning&&c.keys===keys&&c.blindSalt===salt&&c.activeIdentity===slot&&s.db===db&&s.masterKey===key&&global.DeviceRoot?.state===root&&!!keys?.sign&&!!salt&&!!root;
   const check=()=>{if(!current())throw Error('Аккаунт заблокирован или изменён');};check();
   const session={keys,salt,slot,db,key,current,check},blind=salt.slice(),vault=Object.create(s);vault.db=db;vault.masterKey=key;
   const rawAlias=async(base,level)=>{check();const label=encode(base+level),input=new Uint8Array(label.length+blind.length);input.set(label);input.set(blind,label.length);return this.wait(session,c.fastHash(input));};
   vault.getAlias=async(base,level='L1')=>{
    check();const match=level==='L3'&&/^([0-9a-f]{64})([0-9]+)$/.exec(base);
    if(match){const peer=await vault.getBox('blind_peers',match[1]);if(peer?.chatLock){
     const entropy=peer.chatLock.aliasEntropy;if(!/^[0-9a-f]{64}$/.test(entropy||''))throw Error('Повреждена соль чата');
     return rawAlias(base+':chat:'+entropy,level);
    }}
    return rawAlias(base,level);
   };
   vault.getBox=async(table,alias)=>{check();const row=await this.wait(session,new Promise((resolve,reject)=>{const q=db.transaction(table).objectStore(table).get(alias);q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);}));return row?this.open(session,row.blob):null;};
   vault.putBox=async(table,{alias,data})=>{const blob=await this.crypt(session,data);check();return this.wait(session,new Promise((resolve,reject)=>{const tx=db.transaction(table,'readwrite');tx.objectStore(table).put({alias,blob});tx.oncomplete=resolve;tx.onabort=tx.onerror=()=>reject(tx.error);}));};
   session.vault=vault;return session;}
  async wait(s,p){s.check();const x=await p;s.check();return x;}
  exclusive(s,fn){const p=this.serial.catch(()=>{}).then(()=>{s.check();return fn();});this.serial=p.catch(()=>{});return p;}
  async alias(s,label){return this.wait(s,s.vault.getAlias('turn-note:'+label,'L3'));}
  async crypt(s,value){const iv=crypto.getRandomValues(new Uint8Array(12)),bytes=new Uint8Array(await this.wait(s,crypto.subtle.encrypt({name:'AES-GCM',iv},s.key,encode(JSON.stringify(value))))),packed=new Uint8Array(12+bytes.length);packed.set(iv);packed.set(bytes,12);return b64(packed);}
  async open(s,blob){const bytes=raw(blob);return JSON.parse(new TextDecoder().decode(await this.wait(s,crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(0,12)},s.key,bytes.slice(12)))));}
  async rows(s){const values=await this.wait(s,new Promise((resolve,reject)=>{const tx=s.db.transaction('blind_outbox'),q=tx.objectStore('blind_outbox').getAll();q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);})),out=[];
   for(const row of values){let value;try{value=await this.open(s,row.blob);}catch(e){s.check();continue;}if(value?.record==='turn_note_v1')out.push(value);}return out;}
  async write(s,row){const alias=await this.alias(s,row.id),blob=await this.crypt(s,row);s.check();await this.wait(s,new Promise((resolve,reject)=>{const tx=s.db.transaction('blind_outbox','readwrite');tx.objectStore('blind_outbox').put({alias,blob});tx.oncomplete=resolve;tx.onabort=tx.onerror=()=>reject(tx.error||Error('Не удалось сохранить запись'));}));}
  async row(s,noteId){const alias=await this.alias(s,noteId),stored=await this.wait(s,new Promise((resolve,reject)=>{const tx=s.db.transaction('blind_outbox'),q=tx.objectStore('blind_outbox').get(alias);q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);}));return stored?this.open(s,stored.blob):null;}
  async history(s,peer,note,inbound,noteId){await this.wait(s,this.core.withContactAccountV3(s.slot,async()=>{s.check();if(!await s.vault.hasMessageWireId(peer,noteId)){s.check();await s.vault.saveMessageGamma(peer,note,inbound,this.core.activePeerId===peer,inbound?null:'WAITING',noteId);s.check();}}));}
  async queue(peer,note){const s=this.capture(peer);if(!id(peer)||!['voice','video_note'].includes(note?.type)||typeof note.data!=='string')throw Error('Недействительная запись');
   const {mime,encoded,bytes}=recorderData(note.data,note.type,note.mime);
   const noteId=hex(crypto.getRandomValues(new Uint8Array(32))),content={type:note.type,name:note.type==='voice'?'voice_msg':'circle',mime,data:'data:'+mime+';base64,'+encoded};
   const protectedContent=global.DmashChatPassword?await this.wait(s,global.DmashChatPassword.protect(s.vault,peer,content)):content;
   const row={record:'turn_note_v1',id:noteId,peerID:peer,size:bytes.length,sha256:await hash(bytes),content:protectedContent,status:'waiting',nextAttempt:0,attempts:0,createdAt:Date.now()};s.check();
   await this.exclusive(s,async()=>{const rows=await this.rows(s);if(rows.filter(r=>r.content).reduce((n,r)=>n+r.size,0)+row.size>QUOTA)throw Error('Для сохранённых записей занято 128 МиБ. Дождитесь доставки или освободите локальное место. Существующие записи не удалены.');await this.write(s,row);await this.history(s,peer,content,false,noteId);});
   if(this.core.activePeerId===peer)await this.wait(s,this.core.loadChat());
   for(const saved of await this.rows(s))this.view(saved,saved.status);
   void this.flush();return true;
  }
  async hydrate(peer){const s=this.capture(peer),rows=await this.rows(s);s.check();if(this.core.activePeerId!==peer)return;for(const row of rows)if(row.peerID===peer)this.view(row,row.status);}
  view(row,status,progress){this.core.refreshRecordedNoteState?.(row.peerID,row.id,status,progress);}
  async send(s,peer,payload){return this.wait(s,this.core.sendMessage(payload,false,peer,'turn-note-control',true,null,null,s.current));}
  async state(s,row,status){row.status=status;await this.write(s,row);this.view(row,status);}
  stop(task){if(!task||task.closed)return;task.closed=true;task.controller?.abort();clearTimeout(task.timer);task.signal?.close();void task.session?.close();task.panel?.remove();this.tasks.delete(task.key);}
  close(){clearTimeout(this.wakeTimer);this.wakeTimer=null;this.wakeAt=0;for(const task of this.tasks.values())this.stop(task);}
  forgetPeer(peer){const keys=this.core.keys;if(!keys)return;let epochs=this.peerEpochs.get(keys);if(!epochs){epochs=new Map();this.peerEpochs.set(keys,epochs);}epochs.set(peer,{generation:(epochs.get(peer)?.generation||0)+1,blocked:true});for(const task of this.tasks.values())if(task.peer===peer)this.stop(task);}
  allowPeer(peer){const entry=this.peerEpochs.get(this.core.keys)?.get(peer);if(entry)entry.blocked=false;}
  async cancel(noteId){const s=this.capture();this.stop(this.tasks.get(noteId));await this.exclusive(s,async()=>{const row=await this.row(s,noteId);if(!row||row.status==='delivered')return;this.stop(this.tasks.get(noteId));await this.state(s,row,'cancelled');});}
  async retry(noteId){const s=this.capture();await this.exclusive(s,async()=>{const row=await this.row(s,noteId);if(!row||row.status==='delivered')return;row.nextAttempt=0;await this.state(s,row,'waiting');});void this.flush();}
  armWake(s,at){if(!s.current())return;if(this.wakeTimer&&this.wakeAt<=at)return;clearTimeout(this.wakeTimer);this.wakeAt=at;this.wakeTimer=setTimeout(()=>{this.wakeTimer=null;this.wakeAt=0;if(s.current())void this.flush();},Math.max(100,Math.min(60000,at-Date.now())));}
  flush(){if(this.flushing)return this.flushing;let s;try{s=this.capture();}catch(_){this.close();return Promise.resolve();}const job=this.run(s).catch(()=>{});this.flushing=job;return job.finally(()=>{if(this.flushing===job)this.flushing=null;});}
  async run(s){for(const task of this.tasks.values())if(task.current&&!task.current())this.stop(task);if([...this.tasks.values()].some(t=>t.outbound))return;const rows=await this.rows(s);for(const saved of rows)this.view(saved,saved.status);const pending=rows.filter(r=>!this.peerEpochs.get(s.keys)?.get(r.peerID)?.blocked&&!['delivered','cancelled'].includes(r.status));const row=pending.filter(r=>r.nextAttempt<=Date.now()).sort((a,b)=>a.createdAt-b.createdAt)[0];if(!row){if(pending.length)this.armWake(s,Math.min(...pending.map(r=>r.nextAttempt)));return;}s=this.capture(row.peerID);
   // A reload repairs history from the encrypted sender intent before any network use.
   const note=global.DmashChatPassword?await this.wait(s,global.DmashChatPassword.reveal(s.vault,row.peerID,row.content)):row.content;
   await this.history(s,row.peerID,note,false,row.id);
   const task={key:row.id,peer:row.peerID,outbound:true,controller:new AbortController(),closed:false};this.tasks.set(task.key,task);const current=()=>s.current()&&!task.closed&&this.tasks.get(task.key)===task;task.current=current;
   const deferred=async()=>{if(!current())return;this.stop(task);await this.exclusive(s,async()=>{const latest=await this.row(s,row.id);if(!latest||['delivered','cancelled'].includes(latest.status))return;latest.nextAttempt=Date.now()+Math.min(60000,15000*2**Math.min(latest.attempts,2));await this.state(s,latest,'waiting');this.armWake(s,latest.nextAttempt);});};
   try{
    row.attempts++;row.nextAttempt=Date.now()+30000;await this.state(s,row,'connecting');
    const endpoint=await this.wait(s,global.NodeManager.selectCallService({file:true}));if(!current())return;
    task.signal=await global.DmashCallSignaling.WebSocketSignaling.create(endpoint,{signal:task.controller.signal});if(!current()){task.signal.close();this.stop(task);return;}
    const file=new File([raw(note.data.split(';base64,')[1])],note.name,{type:note.mime});
    const manifest=await this.wait(s,global.DmashFileChannel.describe(file,task.signal.invitation.call_id));if(!current())return;
    task.session=global.DmashFileSession.create({signaling:task.signal,manifest,file,onProgress:(done,total)=>{if(current()){clearTimeout(task.timer);task.timer=setTimeout(()=>{void deferred();},60000);this.view(row,'sending',Math.floor(100*done/total));}},onComplete:()=>{if(current())void this.delivered(s,row).then(()=>{this.stop(task);void this.flush();}).catch(()=>this.stop(task));},onError:()=>{void deferred();}});
    task.session.onclose=()=>{if(!task.session.finished)void deferred();};
    await this.wait(s,task.session.startOffer(manifest.id));if(!current())return;
    task.timer=setTimeout(()=>{void deferred();},30000);
    const payload={type:'voip_note_request',version:1,note_id:row.id,media_type:note.type,manifest,invitation:task.signal.invitation};
    if(!await this.send(s,row.peerID,payload))throw Error('Приглашение пока не доставлено');if(current())this.view(row,'waiting');
   }catch(_){await deferred();}
  }
  async delivered(s,row){await this.exclusive(s,async()=>{const latest=await this.row(s,row.id);if(!latest)return;await this.wait(s,this.core.withContactAccountV3(s.slot,()=>s.vault.updateMessageTransportState(row.peerID,row.id,'DELIVERED')));latest.content=null;await this.state(s,latest,'delivered');this.core.refreshMessageTransportState?.(row.peerID,row.id,'DELIVERED');});void this.flush();}
  receive(message,peer,current){const task=this.incoming.catch(()=>{}).then(()=>this.consume(message,peer,current));this.incoming=task.catch(()=>{});return task;}
  async consume(message,peer,current){if(!['voip_note_request','voip_note_complete'].includes(message?.type))return null;const s=this.capture(peer);if(!current()||!id(peer)||!id(message.note_id))return false;
   if(message.type==='voip_note_complete'){const row=await this.row(s,message.note_id);if(!row||row.peerID!==peer||row.sha256!==message.sha256)return false;await this.delivered(s,row);this.stop(this.tasks.get(row.id));return true;}
   const {manifest,invitation}=message;global.DmashFileChannel.validate(manifest);
   if(Object.keys(manifest).sort().join(',')!=='chunk_bytes,id,key,mime,name,nonce,sha256,size,version')throw Error('Неизвестный формат записи');
   if(message.version!==1||!['voice','video_note'].includes(message.media_type)||manifest.size>MAX||!manifest.mime.startsWith(message.media_type==='voice'?'audio/':'video/')||invitation?.call_id!==manifest.id||!Number.isInteger(invitation.expires_at)||invitation.expires_at*1000<=Date.now()||invitation.expires_at*1000>Date.now()+3600000)throw Error('Недействительное приглашение записи');
   global.DmashCallSignaling.validEndpoint(invitation.signaling?.wss_endpoint);if(!/^[A-Za-z0-9_-]{43}$/.test(invitation.signaling?.session_id||'')||!/^[A-Za-z0-9_-]{43}$/.test(invitation.signaling?.one_time_key||''))throw Error('Недействительный канал записи');
   const known=await this.wait(s,s.vault.getBox('blind_peers',await this.wait(s,s.vault.getAlias(peer,'L1'))));if(!known||!current())return false;
   // Only a prior authenticated note with the same content may answer a retry.
   const receiveAlias=await this.alias(s,'received:'+peer+':'+message.note_id);
   const previous=await this.wait(s,new Promise((resolve,reject)=>{const q=s.db.transaction('pairing_material').objectStore('pairing_material').get(receiveAlias);q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);}));
   if(previous){const saved=await this.open(s,previous.blob);if(saved.record!=='turn_note_received_v1'||(saved.peerId!==undefined&&saved.peerId!==peer)||(saved.noteId!==undefined&&saved.noteId!==message.note_id)||saved.sha256!==manifest.sha256||saved.size!==manifest.size||saved.mediaType!==message.media_type||saved.mime!==manifest.mime)throw Error('Запись с таким номером уже существует');if(saved.status==='committed')return this.send(s,peer,{type:'voip_note_complete',note_id:message.note_id,sha256:manifest.sha256});}
   const key='in:'+peer+':'+message.note_id;if(this.tasks.has(key))return true;
   if([...this.tasks.values()].filter(t=>!t.outbound).length>=2)return false;
   const approvedEndpoint=await this.wait(s,global.NodeManager.selectCallService({file:true}));
   if(global.DmashCallSignaling.validEndpoint(approvedEndpoint)!==global.DmashCallSignaling.validEndpoint(invitation.signaling.wss_endpoint))throw Error('Сервер передачи записи не совпадает с подключённым S-TURN');
   if(!previous){
    const reservation=await this.crypt(s,{record:'turn_note_received_v1',peerId:peer,noteId:message.note_id,status:'receiving',sha256:manifest.sha256,size:manifest.size,mediaType:message.media_type,mime:manifest.mime});
    await this.wait(s,new Promise((resolve,reject)=>{const tx=s.db.transaction('pairing_material','readwrite');tx.objectStore('pairing_material').put({alias:receiveAlias,blob:reservation});tx.oncomplete=resolve;tx.onerror=tx.onabort=()=>reject(tx.error);}));
   }
   const task={key,peer,controller:new AbortController(),closed:false};this.tasks.set(key,task);const valid=()=>s.current()&&current()&&!task.closed;task.current=valid;
   const accept=async()=>{if(!valid())return;task.panel?.remove();task.panel=null;try{
    task.signal=new global.DmashCallSignaling.WebSocketSignaling({endpoint:invitation.signaling.wss_endpoint,sessionId:invitation.signaling.session_id,ticket:invitation.signaling.one_time_key,signal:task.controller.signal});
    task.session=global.DmashFileSession.create({signaling:task.signal,manifest,onCommit:async blob=>{
     if(!valid())throw Error('Приём отменён');const bytes=new Uint8Array(await this.wait(s,blob.arrayBuffer()));if(!valid())throw Error('Приём отменён');
     const note={type:message.media_type,name:message.media_type==='voice'?'voice_msg':'circle',mime:manifest.mime,data:'data:'+manifest.mime+';base64,'+b64(bytes)};
     await this.history(s,peer,note,true,message.note_id);if(!valid())throw Error('Приём отменён');
     const encrypted=await this.crypt(s,{record:'turn_note_received_v1',peerId:peer,noteId:message.note_id,status:'committed',sha256:manifest.sha256,size:manifest.size,mediaType:message.media_type,mime:manifest.mime});s.check();
     await this.wait(s,new Promise((resolve,reject)=>{const tx=s.db.transaction('pairing_material','readwrite');tx.objectStore('pairing_material').put({alias:receiveAlias,blob:encrypted});tx.oncomplete=resolve;tx.onerror=tx.onabort=()=>reject(tx.error);}));
    },onComplete:()=>{if(valid()){if(this.core.activePeerId===peer)void this.core.loadChat();else void this.core.renderPeers();}clearTimeout(task.timer);task.timer=setTimeout(()=>this.stop(task),2000);},onError:()=>this.stop(task)});
    task.session.onclose=()=>this.stop(task);task.timer=setTimeout(()=>this.stop(task),90000);await this.wait(s,task.session.accept(manifest.id));
   }catch(_){this.stop(task);}};
   if(manifest.size<=AUTO){void accept();return true;}
   const panel=document.createElement('section'),label=document.createElement('span'),yes=document.createElement('button'),no=document.createElement('button');panel.className='dmash-file-transfer';label.textContent='Входящая запись '+Math.ceil(manifest.size/1024)+' КиБ';yes.textContent='Принять';no.textContent='Отклонить';yes.onclick=()=>{yes.disabled=true;void accept();};no.onclick=()=>this.stop(task);panel.append(label,yes,no);document.body.append(panel);task.panel=panel;task.timer=setTimeout(()=>this.stop(task),90000);return true;
  }
 }
 global.DmashRecordedNoteTurn=RecordedNoteTurn;
})(typeof window!=='undefined'?window:globalThis);
