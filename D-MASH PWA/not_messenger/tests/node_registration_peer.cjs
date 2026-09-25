'use strict';
require('../js/resource_pow.js');
const api = require('../js/node_registration_v4.js');
let input=''; process.stdin.on('data',chunk=>input+=chunk); process.stdin.on('end',()=>{
 console.log(JSON.stringify(JSON.parse(input).map(({session,request,difficulty,now,expectedDnss}) => {
 session.transcriptHash = new Uint8Array(Buffer.from(session.transcriptHash,'hex'));
 return api.verifyRegistration(session,request,difficulty,{now,expectedDnss});
 })));
});
