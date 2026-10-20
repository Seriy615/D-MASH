'use strict';
const assert=require('node:assert/strict');global.nacl=require('../js/vendor/nacl-fast.min.js');require('../js/secure_session.js');require('../js/route_discovery_v4.js');const api=require('../js/node_service_descriptor_v4.js'),row=require('./fixtures/node_service_descriptor_v4.json'),e=row.envelope,b=e.body,opts={now:101,...Object.fromEntries(['issuer','holder','transcript_hash','challenge','signaling_wss'].map(k=>[k,b[k]]))};
assert.equal(Buffer.from(api.bodyBytes(b)).toString('hex'),row.bytes);assert.deepEqual(api.verify(e,opts),b);
for(const k of ['issuer','holder','transcript_hash','challenge','signaling_wss'])assert.throws(()=>api.verify(e,{...opts,[k]:'wrong'}));
assert.throws(()=>api.verify(e,{...opts,now:125}));assert.throws(()=>api.verify({...e,body:{...b,can_relay_blob:false}},opts));assert.throws(()=>api.verify({...e,signature:'00'.repeat(64)},opts));assert.throws(()=>api.verify({...e,body:{...b,extra:true}},opts));
console.log('PASS Python-signed JS service descriptor bytes/signature/context/expiry/capability mutation');
