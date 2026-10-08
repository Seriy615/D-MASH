'use strict';
// NOT IMPLEMENTED: intentionally RED N3 design diagnostics. No runtime activation/network/storage edits.
const assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto');
const nacl=require('../D-MASH PWA/not_messenger/js/vendor/nacl-fast.min.js');
global.nacl=nacl;
global.DmashRouteDiscoveryV4=require('../D-MASH PWA/not_messenger/js/route_discovery_v4.js');
const Transport=require('../D-MASH PWA/not_messenger/js/account_node_transport_v4.js');
const hex=x=>Buffer.from(x).toString('hex');
function fixture(){
 const rows=new Map(),keys={sign:nacl.sign.keyPair()},core={keys,blindSalt:nacl.randomBytes(32),activeIdentity:'synthetic-account',_accountTransitioning:false};
 const host={closed:false,discover:async()=>{throw Error('Network must not run in contract regression');},submit:async()=>{throw Error('Network must not run in contract regression');}};
 const storage={getAlias:async x=>x,getBox:async(_,alias)=>structuredClone(rows.get(alias)||null),putBox:async(_,{alias,data})=>{rows.set(alias,structuredClone(data));}};
 return {rows,keys,core,storage,adapter:new Transport(host,core,storage)};
}
function cert(authority=nacl.sign.keyPair(),generation=1){const now=Math.floor(Date.now()/1000);return global.DmashRouteDiscoveryV4.issueCertificate(authority,nacl.sign.keyPair().publicKey,nacl.box.keyPair().publicKey,nacl.box.keyPair().publicKey,{generation,issuedAt:now,expiresAt:now+3600});}
(async()=>{
 const modulePath=require.resolve('../D-MASH PWA/not_messenger/js/account_node_transport_v4.js');
 const report={kind:'UNIT proposed N3 contract; NOT IMPLEMENTED; expected RED against current adapter',node:process.version,moduleSha256:crypto.createHash('sha256').update(fs.readFileSync(modulePath)).digest('hex'),cases:[]};
 const run=async(id,fn)=>{try{await fn();report.cases.push({id,status:'PASS'});}catch(e){report.cases.push({id,status:'FAIL',reason:e.message});}};
 await run('N3-CERT-ACCOUNT-AUTH',async()=>{const f=fixture(),peer=hex(nacl.sign.keyPair().publicKey),attackerCert=cert();let rejected=false;try{await f.adapter.configurePeer(peer,attackerCert,'a'.repeat(64));}catch(_){rejected=true;}assert(rejected,'configurePeer accepted an unrelated self-signed route certificate without any Account signature/bundle');assert.equal(f.rows.size,0,'Rejected association must not persist a mapping');});
 await run('N3-MAPPING-ATOMIC',async()=>{const f=fixture(),peer=hex(nacl.sign.keyPair().publicKey);let writes=0;f.storage.putBox=async(_,{alias,data})=>{if(++writes===2)throw Error('Injected second durable write failure');f.rows.set(alias,structuredClone(data));};await assert.rejects(f.adapter.configurePeer(peer,cert(),'b'.repeat(64)),/Injected/);assert.equal(f.rows.size,0,'Failed outbound write left an inbound map published without its outbound/journal commit');});
 await run('N3-GENERATION-ROLLBACK',async()=>{const f=fixture(),peer=hex(nacl.sign.keyPair().publicKey),authority=nacl.sign.keyPair(),newer=cert(authority,2),older=cert(authority,1);await f.adapter.configurePeer(peer,newer,'c'.repeat(64));let rejected=false;try{await f.adapter.configurePeer(peer,older,'c'.repeat(64));}catch(_){rejected=true;}assert(rejected,'Older self-consistent certificate overwrote newer peer mapping');const row=f.rows.get('node-peer-v4:'+peer);assert.equal(row.certificate.generation,2);});
 console.log(JSON.stringify(report,null,2));process.exitCode=report.cases.some(x=>x.status==='FAIL')?1:0;
})().catch(e=>{console.error(e.message);process.exitCode=1;});
