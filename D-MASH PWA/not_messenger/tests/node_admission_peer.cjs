'use strict';
const fs=require('node:fs');
global.DmashBlake3=require('../js/vendor/blake3.min.js');
require('../js/node_identity.js');
const api=require('../js/node_admission_v4.js');
(async()=>{
 const value=JSON.parse(fs.readFileSync(0,'utf8'));
 value.session.transcriptHash=new Uint8Array(value.session.transcriptHash);
 try{console.log(JSON.stringify({proof:await api.passwordProof(new Uint8Array(value.key),value.challenge,value.session,{now:value.now})}));}
 catch(_){console.log(JSON.stringify({rejected:true}));}
})().catch(()=>{process.exitCode=1;});
