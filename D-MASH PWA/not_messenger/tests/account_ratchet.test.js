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
    const pqSecret = Uint8Array.from({length: 32}, (_, index) => 0xf0 ^ index);
    const hybrid = await Ratchet.deriveHybridEntropy(entropy, pqSecret);
    assert.notDeepEqual(hybrid, entropy);

    assert.equal(Ratchet.classifyEpoch(7, 6), 'stale');
    assert.equal(Ratchet.classifyEpoch(7, 7), 'current');
    assert.equal(Ratchet.classifyEpoch(7, 71), 'advance');
    assert.equal(Ratchet.classifyEpoch(7, 72), 'too_far');
    assert.equal(Ratchet.randomMessageId().length, Ratchet.MESSAGE_ID_BYTES);
    assert.throws(() => Ratchet.classifyEpoch(0, 1, -1), /Invalid epoch window/);
    await assert.rejects(Ratchet.deriveMessageKey(root, 'A\0B', 0, messageId), /Invalid ratchet direction/);
    await assert.rejects(Ratchet.deriveMessageKey(root, 'A_TO_B', 0, new Uint8Array(1)), /Invalid message id/);

    const sender = new Ratchet.RatchetState({root}), receiver = new Ratchet.RatchetState({root});
    const update = await sender.proposeUpdate();
    assert.deepEqual(update, await sender.proposeUpdate(), 'lost update is safely repeatable');
    const payload = Ratchet.updateToPayload(update);
    assert.deepEqual(Ratchet.updateToPayload(Ratchet.payloadToUpdate(payload)), payload);
    assert.deepEqual(Ratchet.updateToAck(update), {version:1,from_epoch:0,epoch:1,update_id:payload.update_id});
    const pqPayload = Ratchet.updateToPqcPayload(update, entropy, new Uint8Array(1088).fill(7));
    const pqUpdate = await Ratchet.pqcPayloadToUpdate(pqPayload, pqSecret);
    assert.deepEqual(pqUpdate.update_id, update.update_id);
    assert.deepEqual(pqUpdate.entropy, hybrid);
    assert.equal(sender.epoch, 0, 'sender waits for authenticated ACK');
    assert.equal(await receiver.applyUpdate(update), 'advanced');
    assert.equal(await receiver.applyUpdate(update), 'duplicate');
    assert.equal(sender.acknowledge(update), true);
    assert.equal(sender.epoch, receiver.epoch);
    assert.deepEqual(await sender.messageKey('A_TO_B', messageId), await receiver.messageKey('A_TO_B', messageId));
    assert.equal(sender.acknowledge(update), false, 'ACK cannot be replayed');
    const restored = new Ratchet.RatchetState({root, epoch: 0});
    await restored.restorePending(Ratchet.payloadToUpdate(payload));
    assert.equal(restored.acknowledge(Ratchet.ackToUpdate(Ratchet.updateToAck(update), update.entropy)), true);
    assert.equal(restored.epoch, 1);
    assert.throws(() => Ratchet.payloadToUpdate({...payload, entropy:'00'}), /Invalid ratchet entropy/);
    await assert.rejects(receiver.applyUpdate({version:1,from_epoch:receiver.epoch + 64,epoch:receiver.epoch + 65,
        entropy:new Uint8Array(32),update_id:new Uint8Array(16)}), /epoch jump exceeds bound/);
    await assert.rejects(receiver.applyUpdate({version:1,from_epoch:receiver.epoch - 1,epoch:receiver.epoch,
        entropy:new Uint8Array(32),update_id:new Uint8Array(16)}), /Conflicting ratchet update/);
    console.log('account_ratchet.test.js: per-message derivation, fresh entropy and epoch bounds passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
