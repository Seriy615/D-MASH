'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');require('../js/route_discovery_v4.js');
const api=require('../js/node_store_profile_v4.js');
for(const row of require('./fixtures/node_store_profile_v4_signed.json')){
 const e=row.envelope,opts={now:100,expected:row.expected};
 assert.equal(Buffer.from(api.bodyBytes(e.kind,e.body)).toString('hex'),row.bytes);
 assert.deepEqual(api.verify(e,opts),e.body);
 assert.deepEqual(api.sign(e.kind,e.body,nacl.sign.keyPair.fromSeed(Buffer.from(row.seed,'hex')).secretKey),e);
 assert.throws(()=>api.verify(e,{...opts,now:200}));
 assert.throws(()=>api.verify({...e,body:{...e.body,extra:1}},opts));
 assert.throws(()=>api.verify({...e,signature:Buffer.alloc(64).toString('base64')},opts));
 assert.throws(()=>api.parse(' '+DmashSecureSession.canonical(e),opts));
 assert.throws(()=>api.verify(e,{...opts,expected:{issuer:'ff'.repeat(32)}}));
 for(const field of ['version','expires_at'])assert.throws(()=>api.verify({...e,body:{...e.body,[field]:true}},opts));
 const lowR=Buffer.from(e.signature,'base64');lowR.fill(0,0,32);assert.throws(()=>api.verify({...e,signature:lowR.toString('base64')},opts));
 const highS=Buffer.from(e.signature,'base64');let L=(1n<<252n)+27742317777372353535851937790883648493n;for(let i=32;i<64;i++){highS[i]=Number(L&255n);L>>=8n;}assert.throws(()=>api.verify({...e,signature:highS.toString('base64')},opts));
 if(row.expected.transcript_hash)assert.throws(()=>api.verify(e,{...opts,expected:{...row.expected,transcript_hash:'ee'.repeat(32)}}));
 const bad={...e.body,version:-0};assert.throws(()=>api.bodyBytes(e.kind,bad));
}
assert.equal(api.negotiate({profiles:[api.PROFILE],required_profiles:[api.PROFILE]}),api.PROFILE);
for(const p of [{},{profiles:[api.PROFILE],required_profiles:['UNKNOWN']},{profiles:[api.PROFILE,api.PROFILE],required_profiles:[api.PROFILE]}])assert.throws(()=>api.negotiate(p));
console.log('node_store_profile_v4 Python/JS signed vectors PASS');
