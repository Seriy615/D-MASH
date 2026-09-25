'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
const discovery=require('../js/route_discovery_v4.js');
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
 console.log('PASS first-arrival 500 ms windows, wall-clock correction and stale session route refusal');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
