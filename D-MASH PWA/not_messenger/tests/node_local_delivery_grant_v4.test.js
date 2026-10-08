'use strict';
const assert=require('node:assert/strict');
const LocalDelivery=require('../js/node_local_delivery_v4.js');

(async()=>{
 const now=Math.floor(Date.now()/1000),channel={},ownerA='a1'.repeat(32),ownerB='b2'.repeat(32);
 const runtime={clock:()=>now,peers:new Map([['relay',channel]]),discover:async()=>({peer:'relay',channel,label:'relay-label',expires_at:now+180})};
 const local=new LocalDelivery(runtime,{check(){}});
 const certificate={route_id:'cc'.repeat(32)};
 const first=await local.discover(certificate,{ownerToken:ownerA});
 assert.equal(local.routes.size,1);
 assert.throws(()=>local.releaseGrant(first.handle,ownerB),/Discovery owner mismatch/);
 assert.equal(local.routes.size,1);
 assert.equal(local.releaseGrant(first.handle,ownerA),true);
 assert.equal(local.releaseGrant(first.handle,ownerA),false);

 // A 15-second refresh over a 180-second route life can otherwise consume
 // twelve local handles per peer. Releasing the superseded handle keeps the
 // bounded 128-slot map proportional to active peers, not retry attempts.
 const active=[];
 for(let peer=0;peer<32;peer++)active.push(await local.discover(certificate,{ownerToken:ownerA}));
 for(let retry=0;retry<16;retry++)for(let peer=0;peer<32;peer++){
  const next=await local.discover(certificate,{ownerToken:ownerA});
  assert.equal(local.releaseGrant(active[peer].handle,ownerA),true);
  active[peer]=next;
  assert.equal(local.routes.size,32);
 }
 const foreign=await local.discover(certificate,{ownerToken:ownerB});
 assert.equal(local.releaseOwnerGrants(ownerA),32);
 assert.equal(local.routes.size,1);
 assert.equal(local.routes.has(foreign.handle),true);
 assert.equal(local.releaseOwnerGrants(ownerB),1);
 assert.equal(local.routes.size,0);
 const saturated=[];for(let i=0;i<128;i++)saturated.push(await local.discover(certificate,{ownerToken:ownerA}));
 await assert.rejects(local.discover(certificate,{ownerToken:ownerA}),/Local discovery quota/);
 assert.equal(local.releaseGrant(saturated[0].handle,ownerA),true);
 await local.discover(certificate,{ownerToken:ownerA});
 assert.equal(local.routes.size,128);
 assert.equal(local.releaseOwnerGrants(ownerA),128);
 local.close();
 console.log('PASS managed discovery grant release: owner isolation, 32-peer/16-refresh bound, 128-slot saturation recovery, owner cleanup');
})().catch(error=>{console.error(error);process.exitCode=1;});
