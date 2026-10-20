'use strict';
(function(g){
 // Pure mapping only. The caller must commit authenticated CONTROL durably
 // before dispatch; this module does not confer receipt or Node authority.
 const fail=()=>{throw Error('NODE_MEDIA_CONTROL_INVALID');};
 function create({schema=g.DmashAccountMediaControlV4,verifyService,clock=()=>Math.floor(Date.now()/1000)}){
  if(typeof verifyService!=='function'||!schema?.validate)fail();
  async function pin(service,options){if(await verifyService(Object.freeze({...service}),options)!==true)throw Error('NODE_MEDIA_SERVICE_UNTRUSTED');}
  const blob=m=>({mime:m.mime,name:m.name,size:m.size,sha256:m.sha256,chunkBytes:m.chunk_bytes,key:m.key,nonce:m.nonce});
  async function invite(message,service){
   let kind,transferId,transportId,media,invitation;
   if(message?.type==='voip_note_request'){
    if(message.version!==1||!['voice','video_note'].includes(message.media_type))fail();kind=message.media_type==='voice'?'voice':'circle';transferId=message.note_id;transportId=message.manifest?.id;media=blob(message.manifest||{});invitation=message.invitation;
   }else if(message?.type==='voip_call_request'){
    kind='call';invitation=message.request;transferId=transportId=invitation?.call_id;media={audio:true,video:invitation?.media_capabilities?.video===true};
   }else if(message?.type==='voip_file_request'){
    kind='file';const r=message.request;let m;try{m=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(r.encrypted_metadata),x=>x.charCodeAt(0))));}catch(_){fail();}
    if(r.version!==2)throw Error('NODE_FILE_V2_REQUIRED');transferId=r.file_id;transportId=r.session_id;if(m.id!==transportId||m.size!==r.size_bytes||m.chunk_bytes!==r.chunk_bytes||m.sha256!==r.sha256||r.resumable!==false)fail();media=blob(m);invitation={call_id:transportId,expires_at:r.expires_at,signaling:r.signaling};
   }else fail();
   if(invitation?.call_id!==transportId||invitation.expires_at>clock()+3600||invitation.signaling?.wss_endpoint!==service?.wssEndpoint)fail();
   const payload=schema.validate('INVITE',{version:1,transferId,transportId,kind,expiresAt:invitation.expires_at,service,signaling:{sessionId:invitation.signaling.session_id,ticket:invitation.signaling.one_time_key},media},{now:clock()});await pin(payload.service,{file:kind!=='call'});return payload;
  }
  async function incoming(type,payload,{validationTime=clock()}={}){const p=schema.validate(type,payload,{now:validationTime});if(type==='COMMIT_ACK')return p.kind==='file'?{type:'voip_file_complete',file_id:p.transferId,sha256:p.sha256}:{type:'voip_note_complete',note_id:p.transferId,sha256:p.sha256};if(type==='DECLINE'&&p.kind==='file')return {type:'voip_file_reject',file_id:p.transferId,sha256:p.sha256,reason:p.reason,...(p.reason==='RECEIVER_BUSY'?{session_id:p.transportId}:{})};if(type!=='INVITE')return p;await pin(p.service,{file:p.kind!=='call'});
   const invitation={version:2,call_id:p.transportId,expires_at:p.expiresAt,signaling:{wss_endpoint:p.service.wssEndpoint,session_id:p.signaling.sessionId,one_time_key:p.signaling.ticket}};
   if(p.kind==='call')return {type:'voip_call_request',request:{...invitation,caller_display_name:'D-MASH',ringtone:null,media_capabilities:p.media}};
   const m=p.media,manifest={version:1,id:p.transportId,name:m.name,mime:m.mime,size:m.size,chunk_bytes:m.chunkBytes,sha256:m.sha256,key:m.key,nonce:m.nonce};
   if(p.kind==='file'){const bytes=new TextEncoder().encode(JSON.stringify(manifest));return {type:'voip_file_request',request:{version:2,file_id:p.transferId,session_id:p.transportId,expires_at:p.expiresAt,signaling:invitation.signaling,encrypted_metadata:btoa(String.fromCharCode(...bytes)),size_bytes:m.size,chunk_bytes:m.chunkBytes,sha256:m.sha256,resumable:false}};}
   return {type:'voip_note_request',version:1,note_id:p.transferId,media_type:p.kind==='voice'?'voice':'video_note',manifest,invitation};
  }
  function outcome(message,record){
   if(!record||!['voice','circle','file'].includes(record.kind))fail();const id=record.kind==='file'?message?.file_id:message?.note_id;if(id!==record.transferId||message.sha256!==record.sha256)fail();
   if(!Number.isSafeInteger(record.expiresAt)||record.expiresAt<=clock()||record.expiresAt>clock()+300)throw Error('NODE_MEDIA_OUTCOME_EXPIRY');
   const base={version:1,transferId:record.transferId,kind:record.kind,expiresAt:record.expiresAt};
   if(message.type==='voip_file_reject'&&record.kind==='file'&&message.reason==='RECEIVER_BUSY'&&(message.session_id!==record.transportId||!/^[0-9a-f]{64}$/.test(record.transportId||'')))fail();
   if(message.type==='voip_file_reject'&&record.kind==='file')return {type:'DECLINE',payload:schema.validate('DECLINE',{...base,sha256:record.sha256,reason:message.reason,...(message.reason==='RECEIVER_BUSY'?{transportId:record.transportId}:{})},{now:clock()})};
   if(message.type!==(record.kind==='file'?'voip_file_complete':'voip_note_complete'))fail();
   return {type:'COMMIT_ACK',payload:schema.validate('COMMIT_ACK',{...base,sha256:record.sha256,size:record.size},{now:clock()})};
  }
  return Object.freeze({invite,incoming,outcome});
 }
 g.DmashAccountMediaBridgeV4=Object.freeze({create});if(typeof module!=='undefined')module.exports=g.DmashAccountMediaBridgeV4;
})(globalThis);
