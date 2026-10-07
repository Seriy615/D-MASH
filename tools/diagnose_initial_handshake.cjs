'use strict';
// Real bundled NaCl + Kyber WASM, with controllable in-memory storage/network.
// This diagnostic exits nonzero until H1-H3 are fixed. It is deliberately kept
// separate from release suites; no mocked cryptographic success is accepted.
const assert = require('node:assert/strict');
const {createCore, nacl} = require('../D-MASH PWA/not_messenger/tests/fixtures/core_vm.cjs');
const hex = bytes => Buffer.from(bytes).toString('hex');
async function pair() {
    const [a, b] = await Promise.all([createCore({kyber: true}), createCore({kyber: true})]);
    for (const [local, peer] of [[a, b], [b, a]]) {
        local.outgoing = [];
        await local.storage.putBox('blind_peers', {alias: peer.core.keys.pub_hex, data: {
            id: peer.core.keys.pub_hex, curvePub: hex(peer.core.keys.box.publicKey),
            kyberPub: hex(peer.core.keys.kyber.publicKey),
        }});
        local.ctx.NodeManager = {transportMode: 'mesh',
            getMeshRoute: () => ({routeLocator: 'fixture-out', backRouteLocator: 'fixture-in'}),
            startProbe: async () => ({}),
            submitEnvelope: async (_, envelope) => {local.outgoing.push(envelope); return {state: 'NODE_ACCEPTED'};}};
    }
    return [a, b];
}
async function deliver(local, peer, ciphertext) {
    const bytes = peer.core.hexToBytes(ciphertext);
    const proof = nacl.sign.detached(bytes, peer.core.keys.sign.secretKey);
    assert(nacl.sign.detached.verify(bytes, proof, peer.core.keys.sign.publicKey));
    return local.core.decrypt(ciphertext, peer.core.keys.pub_hex, true);
}
const state = (local, peer) => local.storage.getBox('blind_secrets', peer.core.keys.pub_hex);
const scenarios = {
    H1: async () => {
        const [a, b] = await pair();
        const [ai, bi] = await Promise.all([a.core.encrypt('init', b.core.keys.pub_hex, true), b.core.encrypt('init', a.core.keys.pub_hex, true)]);
        await Promise.all([deliver(b, a, ai), deliver(a, b, bi)]);
        await deliver(b, a, a.outgoing[0].ciphertext);
        await deliver(a, b, b.outgoing[0].ciphertext);
        assert.equal((await state(a, b)).staticShared === (await state(b, a)).staticShared, true,
            'crossed initial proposals must converge to one confirmed secret');
    },
    H2: async () => {
        const [a, b] = await pair();
        await deliver(b, a, await a.core.encrypt('init', b.core.keys.pub_hex, true));
        await deliver(a, b, b.outgoing.shift().ciphertext);
        a.rows.delete('blind_secrets' + b.core.keys.pub_hex);
        await deliver(b, a, await a.core.encrypt('recovery', b.core.keys.pub_hex, true));
        assert(b.outgoing.length > 0, 'authenticated recovery must respond when the peer lost its state');
    },
    H3: async () => {
        const [a, b] = await pair();
        await deliver(b, a, await a.core.encrypt('init', b.core.keys.pub_hex, true));
        // Accept at Node, then drop before remote Account receipt.
        const pendingBefore = (await state(b, a)).pendingKyberFinal;
        b.outgoing.length = 0;
        assert(pendingBefore, 'Node acceptance must retain the final before peer confirmation');
        const repeatedInit = await a.core.encrypt('init', b.core.keys.pub_hex, true);
        assert.equal(repeatedInit, await a.core.encrypt('init', b.core.keys.pub_hex, true),
            'an initial retry must reuse one attempt id and packet');
        await deliver(b, a, repeatedInit);
        const retransmitted = b.outgoing.shift();
        assert(retransmitted, 'duplicate init retransmits the stored final');
        assert.equal(hex(a.core.hexToBytes(retransmitted.ciphertext).slice(1, 1089)), pendingBefore.capsule,
            'retransmission reuses the exact persisted Kyber capsule');
        for (const side of [a, b]) {
            side.core.activeIdentity = side === a ? 'slot-A' : 'slot-B';
            side.core.blindSalt = new Uint8Array(32).fill(7);
            side.ctx.window.argon2 = {argon2id: 2,
                async hash({pass, salt}) {return {hash: new Uint8Array(await crypto.subtle.digest('SHA-256',
                    new TextEncoder().encode(pass+'|'+hex(salt)) ))};}};
        }
        const localRoute='d'.repeat(64);
        a.core.activePeerId=b.core.keys.pub_hex;
        let historyWrites=0;
        a.storage.saveMessageGamma=async()=>{historyWrites++;return 1;};
        await a.storage.putBox('pairing_material',{alias:'node-route-v4:'+localRoute,data:{peerId:b.core.keys.pub_hex}});
        const finalEnvelope={version:1,ciphertext:retransmitted.ciphertext,
            sender_proof:hex(nacl.sign.detached(Buffer.from(retransmitted.ciphertext,'hex'),b.core.keys.sign.secretKey))};
        assert.equal(await a.core.receiveAccountNodeRecordV4({routeId:localRoute,accountSlot:'slot-A',payload:JSON.stringify(finalEnvelope)},'slot-A'),true,
            'the real Account receive path sends confirmation only after decrypting/persisting final');
        // Drop the first confirmation after local receipt. A repeated final
        // must regenerate confirmation from the persisted accepted capsule.
        a.outgoing.length=0;
        assert.equal(await a.core.receiveAccountNodeRecordV4({routeId:localRoute,accountSlot:'slot-A',payload:JSON.stringify(finalEnvelope)},'slot-A'),true);
        const confirmation=a.outgoing.at(-1);
        assert(confirmation&&confirmation.ciphertext!==retransmitted.ciphertext,'Account confirmation travels as a separately signed packet');
        assert.equal(historyWrites,0,'handshake confirmations never enter chat history');
        a.ctx.NodeManager.submitEnvelope=async()=>{throw Error('offline');};
        assert.equal(await a.core.receiveAccountNodeRecordV4({routeId:localRoute,accountSlot:'slot-A',payload:JSON.stringify(finalEnvelope)},'slot-A'),false,
            'failed confirmation send retains the final Inbox record for retry');
        assert.equal(historyWrites,0,'failed confirmations never enter queued user history');
        assert.equal([...a.rows.keys()].some(key=>key.startsWith('blind_outbox')),false,
            'the retained Inbox final owns confirmation retries');
        assert.match(await deliver(b,a,confirmation.ciphertext),/pqc_confirm/,
            'remote confirmation is encrypted under the shared Account secret');
        assert.equal((await state(b,a)).pendingKyberFinal,undefined,
            'only authenticated remote Account confirmation retires the final');
        const before=(await state(a,b)).staticShared;
        const unknown={...finalEnvelope,ciphertext:'03'+'00'.repeat(1088)+finalEnvelope.ciphertext.slice(2178)};
        unknown.sender_proof=hex(nacl.sign.detached(Buffer.from(unknown.ciphertext,'hex'),b.core.keys.sign.secretKey));
        a.outgoing.length=0;
        await a.core.receiveAccountNodeRecordV4({routeId:localRoute,accountSlot:'slot-A',payload:JSON.stringify(unknown)},'slot-A');
        assert.equal(a.outgoing.length,0,'a different capsule cannot solicit confirmation for the accepted attempt');
        assert.equal((await state(a,b)).staticShared,before,'duplicate finals cannot replace the established secret');
    },
};
(async () => {
    let failures = 0;
    for (const [id, run] of Object.entries(scenarios)) {
        try { await run(); console.log('PASS', id); }
        catch (error) { failures++; console.log('FAIL', id, error.message.split('\n')[0]); }
    }
    process.exitCode = failures ? 1 : 0;
})().catch(error => {console.error(error.message); process.exitCode = 1;});
