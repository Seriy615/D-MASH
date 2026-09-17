'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
const {Initiator, canonical, b64, SUITE} = require('../js/secure_session.js');
const node = nacl.sign.keyPair();
const nodeId = Buffer.from(node.publicKey).toString('hex');
async function handshake(delta, corrupt = false) {
    const initiator = new Initiator(nacl.sign.keyPair());
    const hello = initiator.initiate();
    const challenge = {type:'CHALLENGE', protocol:'DMP-C', version:3, suite:SUITE,
        role:'NODE', peer_role:'DEVICE', public_key:nodeId,
        ephemeral:b64(nacl.box.keyPair().publicKey), nonce:b64(nacl.randomBytes(32)), expires_at:1000+delta};
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.concat([
        Buffer.from('D-MASH|DMP-C|3|HANDSHAKE\0'), Buffer.from(canonical([hello, challenge]))])));
    const signature = nacl.sign.detached(Buffer.concat([Buffer.from('D-MASH|DMP-C|3|RESPONDER\0'),hash]),node.secretKey);
    if(corrupt) signature[0]^=1;
    return initiator.finish({...challenge,signature:b64(signature)},nodeId,1000);
}
(async()=>{
    for(const delta of [1,15,16,20]) (await handshake(delta)).session.close();
    for(const delta of [0,-1,21]) await assert.rejects(handshake(delta),/Invalid challenge/);
    await assert.rejects(handshake(16,true),/signature/i);
    console.log('signed challenge clock tolerance and strict expiry/signature checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
