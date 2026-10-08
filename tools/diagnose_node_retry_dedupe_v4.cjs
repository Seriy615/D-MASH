'use strict';
// Routing retry regression; admitted-operation adapters, not socket acceptance.
const assert=require('node:assert/strict'),path=require('node:path'),base=path.join(__dirname,'../D-MASH PWA/not_messenger/js/');global.nacl=require(base+'vendor/nacl-fast.min.js');const discovery=require(base+'route_discovery_v4.js');require(base+'probe_primitives_v4.js');const Runtime=require(base+'node_routing_v4.js'),sleep=ms=>new Promise(r=>setTimeout(r,ms));
class Channel{
 constructor(){this.items=[];this.wait=[];this.closed=false;this.drop=null;}
 requireAuthorized(){if(this.closed)throw Error('closed');}
 async sendOperation(value){this.requireAuthorized();const packets=value.packets.filter(packet=>{if(this.drop===packet.payload){this.drop=null;return false;}return true;});if(packets.length)this.other.put({...value,packets});}
 put(value){if(this.wait.length)this.wait.shift()(value);else this.items.push(value);}
 async receiveOperation(){const value=this.items.length?this.items.shift():await new Promise(r=>this.wait.push(r));if(value===null)throw Error('closed');return value;}
 close(){if(this.closed)return;this.closed=true;this.put(null);this.other.put(null);}
}
async function connect(left,leftName,right,rightName){const a=new Channel(),b=new Channel();a.other=b;b.other=a;await left.addPeer(rightName,a);await right.addPeer(leftName,b);return [a,b];}
(async()=>{
 const nodes=[1,2,3].map(n=>new Runtime(new Uint8Array(32).fill(n))),[a,hub,c]=nodes;await connect(a,'a',hub,'hub');const [outgoing]=await connect(hub,'hub',c,'c');
 const owner=nacl.sign.keyPair(),sign=nacl.sign.keyPair(),box=nacl.box.keyPair(),recipient=nacl.box.keyPair(),now=Math.floor(Date.now()/1000),cert=discovery.issueCertificate(owner,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:now+3600}),received=[];
 c.bindLocal(cert,sign,box,async(_,packet)=>received.push(packet.payload));const discard=async()=>{};
 try{
  const first=await a.discover(cert),opaque=discovery.seal(recipient.publicKey,{control:'unchanged retry fixture'});outgoing.drop=opaque;a.send(first,opaque,discard);await sleep(1300);assert.equal(received.length,0,'initial fault');
  const forwarded=hub.stats.forwarded;a.send(first,opaque,discard);await sleep(800);assert.equal(hub.stats.forwarded,forwarded,'same grant suppression');
  const second=await a.discover(cert);assert.notEqual(second.label,first.label);a.send(second,opaque,discard);await sleep(3000);
  assert(received[0]===opaque,'Fresh certified route must retry identical recipient ciphertext after downstream loss');
  console.log('PASS fresh-hop-grant retry delivers exact ciphertext; same-grant duplicate suppressed; no Account metadata');
 }finally{await Promise.all(nodes.map(node=>node.close()));for(const key of [owner,sign,box,recipient])key.secretKey.fill(0);}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
