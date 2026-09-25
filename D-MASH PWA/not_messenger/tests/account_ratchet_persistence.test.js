'use strict';
const assert = require('node:assert/strict');
global.window = global;
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/account_ratchet.js');
require('../js/account_ratchet_runtime.js');
const runtime = DmashAccountRatchetRuntime, ratchet = DmashAccountRatchet;
const hex = bytes => Buffer.from(bytes).toString('hex');
const unhex = value => new Uint8Array(Buffer.from(value, 'hex'));
(async () => {
    const root = nacl.randomBytes(32), sign = nacl.sign.keyPair(), peer = nacl.sign.keyPair();
    const pid = hex(peer.publicKey);
    const core = {keys: {sign, pub_hex: hex(sign.publicKey)}, bytesToHex: hex, hexToBytes: unhex};
    const initial = {staticShared: hex(root), ratchetRoot: hex(root), ratchetEpoch: 1};
    let stored = structuredClone(initial), failWrite = false, sends = 0;
    global.DMashStorage = {
        getAlias: async () => 'test-alias', getBox: async () => structuredClone(stored),
        putBox: async (_, row) => { if (failWrite) throw Error('persist failed'); stored = structuredClone(row.data); }
    };
    const update = await new ratchet.RatchetState({root, epoch: 1}).proposeUpdate();
    const message = {type: 'ratchet_update', suite: 'CLASSICAL_ROOT_V2', update: ratchet.updateToPayload(update)};
    await assert.rejects(runtime.handleUpdate(core, {...message, suite: 'CLASSICAL_ROOT_V1'}, pid), /version incompatible/);
    assert.equal(stored.ratchetEpoch, 1, 'legacy control cannot silently enter v2 collision policy');
    core.sendMessage = async (_, force, target, queued, suppress, override) => {
        sends++;
        assert.equal(stored.ratchetEpoch, 2, 'new root must persist before an ACK can reach the peer');
        assert(stored.ratchetPendingAck, 'ACK intent must be durable before send');
        assert.equal(target, pid);
        assert.equal(override.ratchetRoot, hex(root));
        assert.equal(override.ratchetEpoch, 1);
        return false;
    };
    assert.equal(await runtime.handleUpdate(core, message, pid), false, 'send=false cannot consume inbound update');
    assert(stored.ratchetPendingAck);
    assert.equal(stored.ratchetEpoch, 2);
    const nextRoot = stored.ratchetRoot;
    core.sendMessage = async () => { sends++; return true; };
    assert.equal(await runtime.handleUpdate(core, message, pid), true, 'retry after reload resends durable ACK');
    assert.equal(stored.ratchetRoot, nextRoot);
    assert.equal(stored.ratchetPendingAck, null);
    assert.equal(sends, 2);
    stored = structuredClone(initial); failWrite = true;
    await assert.rejects(runtime.handleUpdate(core, message, pid), /persist failed/);
    assert.equal(sends, 2, 'failed persistence must never emit an ACK');
    console.log('Ratchet durable root/ACK ordering and failed-send retry passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
