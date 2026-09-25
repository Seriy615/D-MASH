"use strict";
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
const Envelope = require('../js/device_envelope.js');
const { DeviceInbox } = require('../js/device_inbox.js');

class Store {
    constructor() { this.rows = new Map(); }
    async all() { return structuredClone([...this.rows.values()]); }
    async get(key) { return structuredClone(this.rows.get(key) || null); }
    async write(row, absent) {
        if (absent && this.rows.has(row.key)) return false;
        this.rows.set(row.key, structuredClone(row)); return true;
    }
}

async function fixture() {
    let root = crypto.getRandomValues(new Uint8Array(32)), active = null;
    const store = new Store(), recipient = nacl.box.keyPair(), handled = [];
    const inbox = new DeviceInbox({store, getRoot: () => root,
        getActiveAccount: () => active,
        onAccount: async envelope => { handled.push(envelope.account_payload); return true; }});
    await inbox.registerRoute('test-route', {scope: 'ACCOUNT', accountSlot: 'test-account'});
    const seal = payload => Envelope.seal(recipient.publicKey, Envelope.create('test-route', 'MSG', payload));
    return {inbox, store, recipient, handled, seal,
        unlock: () => { active = 'test-account'; }, lock: () => { root = null; }};
}

(async () => {
    // A real authenticated pending row fails at the Account callback before a
    // second valid row. Failed payload must remain encrypted and retryable.
    const f = await fixture();
    await f.inbox.receive(f.seal('bad-first'), f.recipient.secretKey);
    await f.inbox.receive(f.seal('valid-next'), f.recipient.secretKey);
    f.unlock();
    const account = f.inbox.onAccount;
    f.inbox.onAccount = async envelope => {
        if (envelope.account_payload === 'bad-first') throw Error('temporary vault failure');
        return account(envelope);
    };
    assert.deepEqual(await f.inbox.drain('test-account'), ['DEVICE_STORED', 'PROCESSED']);
    assert.deepEqual(f.handled, ['valid-next']);
    f.inbox.onAccount = account;
    assert.deepEqual(await f.inbox.drain('test-account'), ['PROCESSED']);
    assert.deepEqual(f.handled, ['valid-next', 'bad-first']);

    // Tamper actual AES-GCM storage, not the decrypt implementation. A bad
    // first storage row also must not abort the transport staging drain.
    for (const transport of [false, true]) {
        const g = await fixture();
        await g.inbox.stageTransport('test-node', [{delivery_id: 'corrupt', ciphertext: g.seal('corrupt')}]);
        const rows = await g.store.all(), corrupt = rows[rows.length - 1];
        const bytes = DmashSecureSession.unb64(corrupt.ciphertext); bytes[0] ^= 1;
        corrupt.ciphertext = DmashSecureSession.b64(bytes);
        g.store.rows = new Map([[corrupt.key, corrupt], ...rows.slice(0, -1).map(row => [row.key, row])]);
        if (transport) await g.inbox.stageTransport('test-node', [{delivery_id: 'good', ciphertext: g.seal('good')}]);
        else await g.inbox.receive(g.seal('good'), g.recipient.secretKey);
        g.unlock();
        const results = transport
            ? await g.inbox.drainTransport(value => g.inbox.receive(value, g.recipient.secretKey))
            : await g.inbox.drain('test-account');
        assert.deepEqual(results, ['DEVICE_STORED', 'PROCESSED']);
        assert.deepEqual(g.handled, ['good']);
        assert.deepEqual(await g.store.get(corrupt.key), corrupt, 'corrupt ciphertext is retained for recovery');
    }

    // A lock inside a callback must propagate, not become a record retry.
    for (const transport of [false, true]) {
      for (const throws of [false, true]) {
        const g = await fixture();
        if (transport) await g.inbox.stageTransport('test-node', [
            {delivery_id: 'one', ciphertext: g.seal('one')}, {delivery_id: 'two', ciphertext: g.seal('two')}]);
        else {
            await g.inbox.receive(g.seal('one'), g.recipient.secretKey);
            await g.inbox.receive(g.seal('two'), g.recipient.secretKey);
        }
        g.unlock();
        let calls = 0;
        g.inbox.onAccount = async () => {
            calls++; g.lock();
            if (throws) throw Error('callback stopped');
            return true;
        };
        await assert.rejects(transport
            ? g.inbox.drainTransport(value => g.inbox.receive(value, g.recipient.secretKey))
            : g.inbox.drain('test-account'), /locked|changed/);
        assert.equal(calls, 1);
      }
    }
    console.log('Inbox per-record isolation: all assertions passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
