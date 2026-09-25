'use strict';
const assert = require('node:assert/strict');
const {createCore} = require('./fixtures/core_vm.cjs');
(async () => {
    const {core} = await createCore();
    const a = 'aa'.repeat(32), b = 'bb'.repeat(32), wrong = 'cc'.repeat(32);
    core.activePeerId = wrong;
    const calls = [];
    core.sendMessage = async (message, force, pid) => { calls.push({force, pid}); return true; };
    await core.sendEmergencyHandshake(a);
    await core.sendEmergencyHandshake(b);
    assert.deepEqual(calls, [{force: 'SOS', pid: a}, {force: 'SOS', pid: b}], 'recovery targets requested peers independently of active chat');
    assert.equal(await core.sendEmergencyHandshake(a), false, 'same peer is throttled');
    assert.equal(await core.sendEmergencyHandshake(null), false, 'missing peer never defaults to active chat');
    assert.equal(calls.length, 2);
    core.keys = {...core.keys};
    assert.equal(await core.sendEmergencyHandshake(a), true, 'new Account key generation has independent retries');
    console.log('Emergency handshake explicit peer and per-Account retry isolation passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
