'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {createCore,nacl}=require('./fixtures/core_vm.cjs');
(async()=>{
 const [a,b]=await Promise.all([createCore({kyber:true}),createCore({kyber:true})]);
 for(const name of ['route_discovery_v4.js','account_node_inbox_v4.js','account_node_transport_v4.js'])
  vm.runInContext(fs.readFileSync(require.resolve('../js/'+name),'utf8'),a.ctx);
 a.core.activeIdentity='slot-A';a.core.blindSalt=nacl.randomBytes(32);
 const owner=nacl.sign.keyPair(),discovery=nacl.sign.keyPair(),box=nacl.box.keyPair(),recipient=nacl.box.keyPair();
 const now=Math.floor(Date.now()/1000),certificate=a.ctx.DmashRouteDiscoveryV4.issueCertificate(owner,discovery.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600});
 const reply='d'.repeat(64),calls=[];
 const host={closed:false,inboxList:async()=>({records:[]}),acknowledgeInbox:async()=>true,
  discover:async cert=>{calls.push({type:'discover',certificate:cert});return {handle:'a'.repeat(64),expiresAt:now+600};},
  submit:async(handle,payload,route)=>{calls.push({type:'submit',handle,payload,route});return {queued:true};}};
 a.ctx.NodeManager={transportMode:'legacy',getMeshRoute(){throw Error('v3 fallback');},startProbe(){throw Error('v3 fallback');},submitEnvelope(){throw Error('v3 fallback');}};
 const transport=a.core.attachNodeTransportV4(host);
 await transport.configurePeer(b.core.keys.pub_hex,certificate,reply);
 await a.storage.putBox('blind_peers',{alias:b.core.keys.pub_hex,data:{curvePub:a.core.bytesToHex(b.core.keys.box.publicKey),kyberPub:a.core.bytesToHex(b.core.keys.kyber.publicKey)}});
 assert.equal(await a.core.sendMessage('init',true,b.core.keys.pub_hex),true,'real initial Account packet reaches local v4 submit');
 const submission=calls.find(call=>call.type==='submit'),envelope=JSON.parse(submission.payload);
 assert.equal(submission.route,reply);assert.equal(submission.handle,'a'.repeat(64));
 assert.equal(nacl.sign.detached.verify(Buffer.from(envelope.ciphertext,'hex'),Buffer.from(envelope.sender_proof,'hex'),a.core.keys.sign.publicKey),true);
 assert.equal(JSON.stringify(calls.filter(call=>call.type==='discover')).includes(b.core.keys.pub_hex),false,'peer identity remains local to Account mapping');
 assert.equal(JSON.stringify(calls.filter(call=>call.type==='discover')).includes('slot-A'),false,'Account slot never enters discovery');
 assert.equal((await a.storage.getBox('pairing_material','node-route-v4:'+reply)).peerId,b.core.keys.pub_hex);
 await assert.rejects(transport.configurePeer('c'.repeat(64),certificate,reply),/another peer/,'local inbound ownership cannot be reassigned silently');
 let route=await transport.getRoute(b.core.keys.pub_hex);route.grant=null;
 let release;host.discover=()=>new Promise(resolve=>release=resolve);
 const preparation=transport.prepare(route);a.core.blindSalt=nacl.randomBytes(32);release({handle:'b'.repeat(64),expiresAt:now+600});
 await assert.rejects(preparation,/session changed/,'changed Account generation cancels late route grants');
 host.discover=async()=>({handle:'b'.repeat(64),expiresAt:now+600});
 route=await transport.getRoute(b.core.keys.pub_hex);
 host.submit=async()=>{throw Error('route unavailable');};
 await assert.rejects(transport.submit(route,envelope),/route unavailable/);assert.equal(route.grant,null,'failed send invalidates stale local grant');
 transport.close();await assert.rejects(transport.getRoute(b.core.keys.pub_hex),/unavailable/);
 console.log('PASS real Account initial crypto to explicit local v4 adapter: no v3 fallback, opaque payload, local peer mapping, route ownership, late-grant cancellation and failed-submit invalidation');
})().catch(error=>{console.error(error);process.exitCode=1;});
