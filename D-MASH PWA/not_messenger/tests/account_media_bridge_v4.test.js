'use strict';
const assert=require('node:assert/strict'),schema=require('../js/account_media_control_v4.js'),bridge=require('../js/account_media_bridge_v4.js');
(async()=>{
 const service={nodeId:'a'.repeat(64),wssEndpoint:'wss://example.test/signal'},api=bridge.create({schema,clock:()=>100,verifyService:s=>s.nodeId===service.nodeId&&s.wssEndpoint===service.wssEndpoint});
 const manifest={version:1,id:'b'.repeat(64),name:'voice.webm',mime:'audio/webm;codecs=opus',size:10,chunk_bytes:32768,sha256:'c'.repeat(64),key:Buffer.alloc(32,1).toString('base64'),nonce:Buffer.alloc(8,2).toString('base64')};
 const message={type:'voip_note_request',version:1,note_id:'d'.repeat(64),media_type:'voice',manifest,invitation:{version:2,call_id:manifest.id,expires_at:200,signaling:{wss_endpoint:service.wssEndpoint,session_id:'e'.repeat(43),one_time_key:'f'.repeat(43)}}};
 const p=await api.invite(message,service);assert.notEqual(p.transferId,p.transportId);assert.deepEqual(await api.incoming('INVITE',p),message);
 await assert.rejects(()=>api.invite(message,{...service,nodeId:'f'.repeat(64)}),/UNTRUSTED/);
 await assert.rejects(()=>api.incoming('INVITE',{...p,service:{...service,nodeId:'f'.repeat(64)}}),/UNTRUSTED/);
 await assert.rejects(()=>api.invite({...message,invitation:{...message.invitation,call_id:'e'.repeat(64)}},service));
 const call={type:'voip_call_request',request:{...message.invitation,media_capabilities:{audio:true,video:true}}};assert.equal((await api.incoming('INVITE',await api.invite(call,service))).request.media_capabilities.video,true);
 const file={type:'voip_file_request',request:{version:2,file_id:'9'.repeat(64),session_id:manifest.id,expires_at:200,signaling:message.invitation.signaling,encrypted_metadata:Buffer.from(JSON.stringify(manifest)).toString('base64'),size_bytes:manifest.size,chunk_bytes:manifest.chunk_bytes,sha256:manifest.sha256,resumable:false}};
 const filePayload=await api.invite(file,service);assert.equal(filePayload.transferId,file.request.file_id);assert.deepEqual(await api.incoming('INVITE',filePayload),file);await assert.rejects(()=>api.invite({...file,request:{...file.request,version:1}},service),/V2_REQUIRED/);
 const record={expiresAt:400,kind:'file',transferId:file.request.file_id,sha256:manifest.sha256,size:manifest.size},complete={type:'voip_file_complete',file_id:record.transferId,sha256:record.sha256},ack=api.outcome(complete,record);assert.equal(ack.type,'COMMIT_ACK');assert.deepEqual(await api.incoming(ack.type,ack.payload),complete);
 const rejected={type:'voip_file_reject',file_id:record.transferId,sha256:record.sha256,reason:'RECEIVER_STORAGE_FULL'},decline=api.outcome(rejected,record);assert.deepEqual(await api.incoming(decline.type,decline.payload),rejected);assert.throws(()=>api.outcome({...complete,sha256:'f'.repeat(64)},record));assert.throws(()=>api.outcome({...rejected,reason:'unbounded raw error'},record));
 const busyRecord={...record,transportId:manifest.id},busy={...rejected,reason:'RECEIVER_BUSY',session_id:manifest.id},busyWire=api.outcome(busy,busyRecord);assert.deepEqual(await api.incoming(busyWire.type,busyWire.payload),busy);assert.throws(()=>api.outcome({...busy,session_id:'0'.repeat(64)},busyRecord));assert.throws(()=>api.outcome(busy,record));const missing={...busyWire.payload};delete missing.transportId;assert.throws(()=>schema.validate('DECLINE',missing,{now:100}));
 console.log('PASS strict S-TURN mapping, distinct logical/transport IDs, key preservation and trusted service denial; inactive');
})().catch(e=>{console.error(e);process.exitCode=1;});
