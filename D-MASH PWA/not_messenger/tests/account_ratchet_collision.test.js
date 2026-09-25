'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
const {createCore, nacl} = require('./fixtures/core_vm.cjs');
const hex = bytes => Buffer.from(bytes).toString('hex');
async function scenario(order) {
    const nodes = await Promise.all([createCore(), createCore()]);
    const root = hex(nacl.randomBytes(32)), queue = [];
    for (let i = 0; i < 2; i++) {
        const local = nodes[i], peer = nodes[1-i];
        for (const file of ['account_ratchet.js', 'account_ratchet_runtime.js']) {
            vm.runInContext(fs.readFileSync(require.resolve('../js/' + file), 'utf8'), local.ctx);
        }
        local.runtime = local.ctx.DmashAccountRatchetRuntime;
        local.core.activePeerId = peer.core.keys.pub_hex;
        local.core.customAlert = () => {};
        await local.storage.putBox('blind_secrets', {alias: peer.core.keys.pub_hex,
            data: {staticShared: root, ratchetRoot: root, ratchetEpoch: 1}});
        local.core.sendMessage = async (message, force, pid, queued, suppress, override) => {
            const secrets = await local.storage.getBox('blind_secrets', pid);
            queue.push({sender:i, ciphertext: await local.runtime.encryptPacket(local.core, message, pid, {...secrets, ...override})});
            return true;
        };
    }
    await Promise.all(nodes.map(n => n.runtime.initHandshake(n.core)));
    const proposals = queue.splice(0);
    for (const index of order) queue.push(proposals.find(packet => packet.sender === index));
    let count = 0;
    while (queue.length) {
        assert(++count < 12, 'collision cannot produce an unbounded reply loop');
        const {sender, ciphertext} = queue.shift(), target = nodes[1-sender], peer = nodes[sender];
        const secrets = await target.storage.getBox('blind_secrets', peer.core.keys.pub_hex);
        const plaintext = await target.runtime.decryptPacket(target.core, target.core.hexToBytes(ciphertext), peer.core.keys.pub_hex, secrets);
        assert(plaintext, 'every reordered control decrypts under retained current/previous epoch');
        const message = JSON.parse(plaintext);
        const handler = message.type === 'ratchet_update' ? 'handleUpdate' : 'handleAck';
        assert.equal(await target.runtime[handler](target.core, message, peer.core.keys.pub_hex), true);
    }
    const states = await Promise.all(nodes.map((n,i) => n.storage.getBox('blind_secrets', nodes[1-i].core.keys.pub_hex)));
    assert.equal(states[0].ratchetRoot === states[1].ratchetRoot, true, 'concurrent updates agree on one root');
    for (const state of states) { assert.equal(state.ratchetEpoch, 2); assert.equal(state.ratchetPending, null); }
    const ciphertext = await nodes[0].runtime.encryptPacket(nodes[0].core, 'after collision', nodes[1].core.keys.pub_hex, states[0]);
    assert.equal(await nodes[1].runtime.decryptPacket(nodes[1].core, nodes[1].core.hexToBytes(ciphertext), nodes[0].core.keys.pub_hex, states[1]), 'after collision');
}
(async () => {
    await scenario([0,1]); await scenario([1,0]);
    console.log('Concurrent ratchet proposals converge with either delivery order');
})().catch(error => {console.error(error.message); process.exitCode = 1;});
