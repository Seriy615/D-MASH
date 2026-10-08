'use strict';
const assert=require('node:assert/strict'),codec=require('../js/account_media_control_v4.js');
const base={version:1,transferId:'a'.repeat(64),kind:'voice',expiresAt:200};
const invite={...base,transportId:'d'.repeat(64),service:{nodeId:'b'.repeat(64),wssEndpoint:'wss://example.test/signal'},signaling:{sessionId:'a'.repeat(43),ticket:'b'.repeat(43)},media:{mime:'audio/webm;codecs=opus',name:'voice.webm',size:1234,sha256:'c'.repeat(64),chunkBytes:32768,key:Buffer.alloc(32).toString('base64'),nonce:Buffer.alloc(8).toString('base64')}};
const check=(type,v)=>codec.validate(type,v,{now:100});
assert.deepEqual(check('INVITE',invite),invite);assert.deepEqual(check('ACCEPT',base),base);
for(const mutation of [v=>v.bytes='secret',v=>v.service.wssEndpoint='ws://example.test/',v=>v.service.wssEndpoint='wss://user:secret@example.test/',v=>v.media.size=0,v=>v.media.chunkBytes=65536,v=>v.media.mime='video/webm',v=>v.signaling.sdp='secret',v=>v.expiresAt=99]){const v=structuredClone(invite);mutation(v);assert.throws(()=>check('INVITE',v));}
assert.throws(()=>check('COMMIT_ACK',{...base,kind:'call',size:1,sha256:'c'.repeat(64)}));
assert.throws(()=>check('UNKNOWN',base));
assert.throws(()=>check('ACCEPT',{...base,extra:undefined}));
assert.throws(()=>check('ACCEPT',{...base,get extra(){throw Error('must not invoke getter');}}));
assert.deepEqual(check('COMMIT_ACK',{...base,size:1234,sha256:'c'.repeat(64)}).size,1234);
console.log('PASS strict media control schema; inactive, no crypto/transport claim');
