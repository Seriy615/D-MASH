"use strict";
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
const Envelope = require('../js/device_envelope.js');
const { DeviceInbox } = require('../js/device_inbox.js');

class MemoryStore {
    constructor() { this.rows = new Map(); }
    async all() { return structuredClone([...this.rows.values()]); }
    async get(key) { return structuredClone(this.rows.get(key) || null); }
    async write(record, onlyIfAbsent) {
        if (onlyIfAbsent && this.rows.has(record.key)) return false;
        this.rows.set(record.key, structuredClone(record)); return true;
    }
}
(async () => {
    let root = crypto.getRandomValues(new Uint8Array(32)), active = 'Account A';
    const recipient = nacl.box.keyPair(), store = new MemoryStore(), accounts = [], events = [];
    let failAccount = false;
    const inbox = new DeviceInbox({ store, getRoot: () => root, getActiveAccount: () => active,
        onAccount: async (envelope, slot) => {
            if (failAccount) throw new Error('Vault write failed');
            accounts.push({ slot, payload: envelope.account_payload }); return true;
        },
        onDevice: async envelope => { events.push(envelope.type); return true; }
    });
    await inbox.registerRoute('route-B', { scope: 'ACCOUNT', accountSlot: 'Account B' });
    await inbox.registerRoute('public-device-route', { scope: 'DEVICE' });
    const packet = Envelope.create('route-B', 'MSG', 'opaque Account B ciphertext');
    const ciphertext = Envelope.seal(recipient.publicKey, packet);
    await assert.rejects(inbox.receive(ciphertext, recipient.secretKey, 'another-route'), /Route mismatch/);
    assert.equal(await inbox.receive(ciphertext, recipient.secretKey), 'DEVICE_STORED');
    assert.equal(active, 'Account A', 'arrival must never switch the active Account');
    assert.deepEqual(accounts, [], 'locked Account payload must not enter the active Account');
    const persisted = JSON.stringify(await store.all());
    for (const secret of ['route-B', 'Account B', packet.account_payload, packet.packet_id]) assert.equal(persisted.includes(secret), false);
    for (const row of await store.all()) {
        const local = await inbox._open(row);
        assert.equal(JSON.stringify(local).includes('route-B'), false, 'even decrypted Account route records retain only blind aliases');
    }
    assert.equal(await inbox.receive(ciphertext, recipient.secretKey), 'DUPLICATE');
    active = 'Account B';
    assert.deepEqual(await inbox.drain('Account B'), ['PROCESSED']);
    assert.deepEqual(accounts, [{ slot: 'Account B', payload: packet.account_payload }]);
    assert.equal(await inbox.receive(ciphertext, recipient.secretKey), 'DUPLICATE');
    assert.deepEqual(await inbox.drain('Account B'), []);

    active = null;
    const event = Envelope.create('public-device-route', 'CONN_REQUEST', 'opaque contact bootstrap');
    assert.equal(await inbox.receive(Envelope.seal(recipient.publicKey, event), recipient.secretKey), 'PROCESSED');
    assert.deepEqual(events, ['CONN_REQUEST'], 'Device event works before Account login');

    active = 'Account B'; failAccount = true;
    const retry = Envelope.create('route-B', 'MSG', 'second opaque payload');
    await assert.rejects(inbox.receive(Envelope.seal(recipient.publicKey, retry), recipient.secretKey), /Vault write failed/);
    failAccount = false;
    assert.deepEqual(await inbox.drain('Account B'), ['PROCESSED'], 'callback failure retains pending payload');
    assert.equal(accounts.length, 2);
    const unknown = Envelope.create('restored-route', 'MSG', 'waiting for route restoration');
    assert.equal(await inbox.receive(Envelope.seal(recipient.publicKey, unknown), recipient.secretKey), 'DEVICE_STORED');
    assert.deepEqual(await inbox.drain('Account B'), []);
    await inbox.registerRoute('restored-route', { scope: 'ACCOUNT', accountSlot: 'Account B' });
    assert.deepEqual(await inbox.drain('Account B'), ['PROCESSED']);
    assert.equal(accounts.length, 3);
    const staged = Envelope.create('route-B', 'MSG', 'staged after Node drain');
    await inbox.stageTransport('node-test', [{delivery_id: 'one', ciphertext: Envelope.seal(recipient.publicKey, staged)},
        {delivery_id: 'bad', ciphertext: 'unopenable-box'}]);
    const transportResults = await inbox.drainTransport(value => inbox.receive(value, recipient.secretKey));
    assert.deepEqual(transportResults, ['PROCESSED', 'DEVICE_STORED']);
    assert.equal(accounts.length, 4);
    assert.deepEqual(await inbox.drainTransport(value => inbox.receive(value, recipient.secretKey)), ['DEVICE_STORED'], 'only the unopenable raw box remains for retry');
    assert.equal(await inbox.canPull(), true);
    root = null;
    await assert.rejects(inbox.drain('Account B'), /Device locked/);
    root = crypto.getRandomValues(new Uint8Array(32));
    await assert.rejects(inbox.drain('Account B'), /operation|decrypt/i, 'different DeviceRoot cannot open Inbox');
    console.log('Multi-account Device Inbox acceptance: all assertions passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
