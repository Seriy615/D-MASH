const assert = require('node:assert/strict');
require('../js/account_ratchet.js');
const Ratchet = DmashAccountRatchet;
const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
(async () => {
    const root = Uint8Array.from({length: Ratchet.ROOT_BYTES}, (_, index) => index);
    const messageId = Uint8Array.from({length: Ratchet.MESSAGE_ID_BYTES}, (_, index) => 0xa0 + index);
    const first = await Ratchet.deriveMessageKey(root, 'A_TO_B', 7, messageId);
    assert.equal(first.length, 32);
    assert.equal(hex(first), hex(await Ratchet.deriveMessageKey(root, 'A_TO_B', 7, messageId)));
    assert.notDeepEqual(first, await Ratchet.deriveMessageKey(root, 'B_TO_A', 7, messageId));
    assert.notDeepEqual(first, await Ratchet.deriveMessageKey(root, 'A_TO_B', 8, messageId));
    assert.notDeepEqual(first, await Ratchet.deriveMessageKey(root, 'A_TO_B', 7,
        Uint8Array.from(messageId, value => value ^ 1)));

    const entropy = Uint8Array.from({length: 32}, (_, index) => 0x55 ^ index);
    const next = await Ratchet.deriveEpochRoot(root, 8, entropy);
    assert.notDeepEqual(root, next);
    assert.deepEqual(next, await Ratchet.deriveEpochRoot(root, 8, entropy));
    assert.notDeepEqual(next, await Ratchet.deriveEpochRoot(root, 9, entropy));
    assert.notDeepEqual(next, await Ratchet.deriveEpochRoot(root, 8, Uint8Array.from(entropy, value => value ^ 1)));

    assert.equal(Ratchet.classifyEpoch(7, 6), 'stale');
    assert.equal(Ratchet.classifyEpoch(7, 7), 'current');
    assert.equal(Ratchet.classifyEpoch(7, 71), 'advance');
    assert.equal(Ratchet.classifyEpoch(7, 72), 'too_far');
    assert.equal(Ratchet.randomMessageId().length, Ratchet.MESSAGE_ID_BYTES);
    assert.throws(() => Ratchet.classifyEpoch(0, 1, -1), /Invalid epoch window/);
    await assert.rejects(Ratchet.deriveMessageKey(root, 'A\0B', 0, messageId), /Invalid ratchet direction/);
    await assert.rejects(Ratchet.deriveMessageKey(root, 'A_TO_B', 0, new Uint8Array(1)), /Invalid message id/);
    console.log('account_ratchet.test.js: per-message derivation, fresh entropy and epoch bounds passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
