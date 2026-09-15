const assert = require('node:assert/strict');
global.window = global;
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/account_ratchet.js');
require('../js/account_ratchet_runtime.js');
const runtime = DmashAccountRatchetRuntime, ratchet = DmashAccountRatchet;
const hex = bytes => Buffer.from(bytes).toString('hex');
const unhex = value => new Uint8Array(Buffer.from(value, 'hex'));
function account() {
    const sign = nacl.sign.keyPair();
    return {keys: {sign, pub_hex: hex(sign.publicKey)}, bytesToHex: hex, hexToBytes: unhex};
}
(async () => {
    const sender = account(), receiver = account(), root = nacl.randomBytes(32);
    const senderState = new ratchet.RatchetState({root, epoch: 1});
    const update = await senderState.proposeUpdate();
    let stored = {staticShared: hex(root), ratchetRoot: hex(root), ratchetEpoch: 1};
    global.DMashStorage = {
        getAlias: async () => 'blind-fixture',
        getBox: async () => structuredClone(stored),
        putBox: async (table, row) => { stored = structuredClone(row.data); }
    };
    const acknowledgements = [];
    receiver.sendMessage = async (message, force, pid, queued, suppress, override) => {
        acknowledgements.push(await runtime.encryptPacket(receiver, message, pid, {...stored, ...override}));
        return true;
    };
    const control = {type: 'ratchet_update', suite: 'CLASSICAL_ROOT_V1', update: ratchet.updateToPayload(update)};
    await runtime.handleUpdate(receiver, control, sender.keys.pub_hex);
    assert.equal(stored.ratchetEpoch, 2);
    // Lose the first ACK. Reloaded storage must recognize a repeated update
    // and encrypt the replacement ACK under the sender's unchanged epoch.
    await runtime.handleUpdate(receiver, control, sender.keys.pub_hex);
    assert.equal(stored.ratchetEpoch, 2);
    assert.equal(acknowledgements.length, 2);
    for (const packet of acknowledgements) {
        const opened = await runtime.decryptPacket(sender, unhex(packet), receiver.keys.pub_hex,
            {ratchetRoot: hex(root), ratchetEpoch: 1});
        assert(opened, 'both original and retried ACK decrypt before sender advances');
        assert.deepEqual(JSON.parse(opened).ack, ratchet.updateToAck(update));
    }
    console.log('Ratchet lost ACK retry preserves originating epoch and root');
})().catch(error => {console.error(error); process.exitCode = 1;});
