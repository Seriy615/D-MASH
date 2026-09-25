'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
const discovery=require('../js/route_discovery_v4.js');
require('../js/recipient_payload_v4.js');
const Runtime=require('../js/node_routing_v4.js');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
(async()=>{
 let wall=Date.now()/1000;const runtime=new Runtime(new Uint8Array(32),{clock:()=>wall});
 const sent=[],sink={sendOperation:async value=>sent.push({at:performance.now(),value}),close(){}};
 runtime.peers.set('peer',sink);
 const packet={type:'DATA',version:4,label:'ab'.repeat(32),offer:'cd'.repeat(32),payload:'opaque',expires_at:Math.floor(wall)+100};
 const until=async count=>{for(let i=0;i<200&&sent.length<count;i++)await sleep(10);assert.equal(sent.length,count);};
 try{
  const start=performance.now();runtime.enqueue('peer',packet);await sleep(100);runtime.enqueue('peer',packet);
  wall-=3600;await until(1);assert(sent[0].at-start>=450);assert.equal(sent[0].value.packets.length,2);
  const restart=performance.now();runtime.enqueue('peer',packet);await until(2);
  assert(sent[1].at-restart>=450);assert.equal(sent[1].value.packets.length,1);
  const stale={peer:'peer',label:packet.label,channel:{},expires_at:packet.expires_at};
  assert.throws(()=>runtime.send(stale,'opaque',async()=>{}),/replaced/);
  assert.equal(runtime.labels.size,0);
 }finally{await runtime.close();}
 const owner=nacl.sign.keyPair(),sign=nacl.sign.keyPair(),box=nacl.box.keyPair(),recipient=nacl.box.keyPair();
 const now=Math.floor(Date.now()/1000),short=new Runtime(new Uint8Array(32));short.peers.set('peer',sink);
 const cert=discovery.issueCertificate(owner,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+20});
 const binding=short.bindLocal(cert,sign,box,async()=>{}),query=discovery.createQuery(cert,{now});
 try{
  await short.answerBinding('peer',{box:query.blob,return_label:'ab'.repeat(32),expires_at:now+180},binding);
  const packet=short.queues.get('peer')[0].packet;assert.equal(packet.expires_at,now+20);
  assert.equal([...short.labels.values()][0].expires,now+20);
 }finally{await short.close();query.state.replyPrivate.fill(0);for(const pair of [owner,sign,box,recipient])pair.secretKey.fill(0);}
 let mono=1000;const budget=new Runtime(new Uint8Array(32),{monotonic:()=>mono}),frames=[];
 try{
  assert.equal(budget.injectCoverOnce(),false);
  assert.throws(()=>budget.startCover({minimum:14}));budget.startCover();assert(budget.coverTimer);budget.stopCover();assert.equal(budget.coverTimer,null);
  budget.startCover();
  for(const peer of ['left','right']){
   budget.peers.set(peer,{sendOperation:async value=>frames.push({peer,value}),close(){}});
   budget.label('incoming',[peer,'ab'.repeat(32)],Date.now()/1000+120);
  }
  const drain=async count=>{for(let i=0;i<500&&frames.length<count;i++)await sleep(10);assert.equal(frames.length,count);};
  for(let i=0;i<4;i++){
   assert(budget.injectCoverOnce(1024));assert.equal(budget.injectCoverOnce(1024),false);await drain(i+1);
   assert.deepEqual(Object.keys(frames[i].value.packets[0]).sort(),['expires_at','label','offer','payload','type','version']);
  }
  assert.equal(frames.filter(row=>row.peer==='left').length,2);assert.equal(frames.filter(row=>row.peer==='right').length,2);
  assert.equal(budget.injectCoverOnce(),false);mono+=59.9;assert.equal(budget.injectCoverOnce(),false);
  mono+=.2;assert(budget.injectCoverOnce(16384));await drain(5);assert.equal(budget.injectCoverOnce(256),false);
 }finally{await budget.close();assert.equal(budget.coverTimer,null);assert.throws(()=>budget.startCover());}
 console.log('PASS first-arrival 500 ms windows, wall-clock correction and stale session route refusal');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
