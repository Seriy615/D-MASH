'use strict';
const assert=require('node:assert/strict');
require('../js/file_channel.js');require('../js/call_signaling.js');require('../js/recorded_note_turn.js');
(async()=>{
 const rows=new Map(),peer='a'.repeat(64),noteId='b'.repeat(64),sent=[];
 global.DeviceRoot={state:{},onLock(){}};
 const core={keys:{sign:{}},blindSalt:new Uint8Array(32).fill(1),activeIdentity:'synthetic',fastHash:async bytes=>Buffer.from(await crypto.subtle.digest('SHA-256',bytes)).toString('hex'),sendMessage:async body=>{sent.push(body);return true;}};
 const storage={masterKey:await crypto.subtle.importKey('raw',new Uint8Array(32).fill(2),'AES-GCM',false,['encrypt','decrypt']),db:{transaction(){return {objectStore(){return {get(alias){const request={};queueMicrotask(()=>{request.result=rows.get(alias);request.onsuccess();});return request;}};}};}}};
 const runtime=new DmashRecordedNoteTurn(core,storage),session=runtime.capture(peer);
 const known=await session.vault.getAlias(peer,'L1');rows.set(known,{blob:await runtime.crypt(session,{id:peer})});
 const manifest=await DmashFileChannel.describe(new File(['abc'],'voice_msg',{type:'audio/webm'}),'c'.repeat(64));
 const message={type:'voip_note_request',version:1,note_id:noteId,media_type:'voice',manifest,invitation:{call_id:manifest.id,expires_at:Math.floor(Date.now()/1000)+60,signaling:{wss_endpoint:'wss://stage-api-ems.d-mash.ru/signal/v1',session_id:'a'.repeat(43),one_time_key:'b'.repeat(43)}}};
 const alias=await runtime.alias(session,'received:'+peer+':'+noteId);
 for(const status of ['receiving','committed']){
  const blob=await runtime.crypt(session,{record:'turn_note_received_v1',status,sha256:manifest.sha256,size:manifest.size,mediaType:'voice',mime:'audio/webm'});rows.set(alias,{blob});
  await assert.rejects(runtime.receive({...message,manifest:{...manifest,mime:'audio/ogg'}},peer,()=>true),/Запись с таким номером уже существует/);
  assert.equal(rows.get(alias).blob,blob,'MIME substitution must not rewrite an encrypted reservation');assert.equal(sent.length,0);
 }
 assert.equal(await runtime.receive(message,peer,()=>true),true);assert.equal(sent.length,1);assert.equal(sent[0].type,'voip_note_complete');assert.equal(sent[0].sha256,manifest.sha256);
 console.log('PASS real AES reservation: pending/committed MIME substitution refused unchanged, original MIME retry returns metadata receipt');
})().catch(e=>{console.error(e);process.exitCode=1;});
