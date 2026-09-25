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
        b.outgoing.length = 0;
        assert((await state(b, a)).pendingKyberFinal,
            'Node acceptance must not retire a final before peer confirmation');
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
