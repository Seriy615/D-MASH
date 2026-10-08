'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
require('../js/chat_password.js');
require('../js/recorded_note_turn.js');

(async()=>{
 const peer='a'.repeat(64),noteId='b'.repeat(64),entropy='c'.repeat(64),policy={aliasEntropy:entropy};
 let locked=true,saves=0,savedAlias=null,known=false;
 const salt=new Uint8Array(32);
 const rawAlias=async(base,level='L1')=>crypto.createHash('sha256').update(base+level).update(salt).digest('hex');
 const peerAlias=await rawAlias(peer,'L1');
 const storage={db:{},masterKey:{},getAlias:rawAlias,getBox:async(table,alias)=>table==='blind_peers'&&alias===peerAlias?{chatLock:locked?policy:null}:null,
  putBox:async()=>{},deleteBox:async()=>{},hasMessageWireId:async()=>known,
  saveMessageGamma:async function(){savedAlias=await DmashChatPassword.location(this,peerAlias+'1','L3',locked?policy:null);known=true;saves++;}};
 DmashChatPassword.install(storage);
 const core={keys:{sign:{}},blindSalt:salt,activeIdentity:'synthetic',fastHash:async bytes=>crypto.createHash('sha256').update(bytes).digest('hex'),withContactAccountV3:async(_,work)=>work()};
 global.DeviceRoot={state:{},onLock(){}};
 const runtime=new DmashRecordedNoteTurn(core,storage);
 for(const lock of [true,false]){
  locked=lock;known=false;const session=runtime.capture(peer);
  session.vault.getBox=async(table,alias)=>storage.getBox(table,alias);
  const expected=await storage.getAlias(peerAlias+'1','L3');
  assert.equal(await session.vault.getAlias(peerAlias+'1','L3'),expected,'Captured vault must use the same locked L3 address');
  await runtime.history(session,peer,{type:'voice'},false,noteId);
  assert.equal(savedAlias,expected,'History save must resolve the guarded snapshot alias');
  await runtime.history(session,peer,{type:'voice'},false,noteId);
  assert.equal(saves,lock?1:2,'Retry must not duplicate recorded-note history');
 }
 await assert.rejects(DmashChatPassword.location(Object.create(storage),peerAlias,'L2',null),/Chat alias source unavailable/);
 console.log('PASS captured voice history uses normal/locked chat aliases; retry idempotent; unregistered proxy rejected');
})().catch(error=>{console.error(error);process.exitCode=1;});
