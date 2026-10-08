'use strict';
const assert=require('node:assert/strict');const {createCore}=require('./fixtures/core_vm.cjs');
(async()=>{const {core,ctx,storage}=await createCore();const peer='a'.repeat(64);let alerts=[],queued=0,network=0;core.activePeerId=peer;core.customAlert=(...x)=>alerts.push(x);core.getAccountTransportRoute=async()=>{network++;return null;};
 assert.equal(await core.sendMessage({type:'voice',data:'data:audio/webm;base64,YQ=='},false,peer),false);assert.equal(network,0,'missing S-TURN runtime cannot silently put media in Mesh');assert.equal(alerts.length,1);
 ctx.DmashRecordedNoteTurn=class{async queue(p,n){assert.equal(p,peer);assert.equal(n.type,'voice');queued++;return true;}};
 assert.equal(await core.sendMessage({type:'voice',data:'data:audio/webm;base64,YQ=='},false,peer),true);assert.equal(queued,1);assert.equal(network,0);
 ctx.NodeManager={connectedConnections:()=>[{}]};const legacy={record:'media_outbound',content:{data:'LEGACY_BYTES'}},turn={record:'turn_note_v1',content:{data:'TURN_BYTES'}},text={alias:'ordinary',content:'ordinary text',peerID:peer};storage.getAllBoxes=async()=>[legacy,turn,text];let sent=[],deleted=[];storage.deleteBox=async(table,alias)=>deleted.push(alias);core.sendMessage=async content=>{sent.push(content);return true;};await core.flushOutboundQueue();assert.deepEqual(sent,['ordinary text']);assert.deepEqual(deleted,['ordinary'],'generic outbox cannot resend/delete typed media intent');
 console.log('PASS new notes require S-TURN runtime, no Mesh media fallback; generic outbox preserves both typed media stores');
})().catch(e=>{console.error(e);process.exitCode=1;});
