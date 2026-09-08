'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
const nacl = require('../js/vendor/nacl-fast.min.js');
global.nacl = nacl;
require('../js/secure_session.js');
const Envelope = require('../js/device_envelope.js');
const {DeviceInbox} = require('../js/device_inbox.js');
class Store {
    constructor() { this.rows = new Map(); }
    async all() {return structuredClone([...this.rows.values()]);}
    async get(key) {return structuredClone(this.rows.get(key) || null);}
    async write(record, absent) {if (absent && this.rows.has(record.key)) return false; this.rows.set(record.key, structuredClone(record)); return true;}
}
(async () => {
    const writes = [], receipts = [], messages = new Set();
    const storage = {getItem: () => null, setItem() {}, removeItem() {}};
    const vault = {hasMessageWireId: async (_, id) => messages.has(id),
        getAlias: async value => value,
        getBox: async () => ({peerId}),
        saveMessageGamma: async (peer, body, incoming, read, state, id) => {writes.push({peer, body}); messages.add(id); return writes.length;},
        updateMessageTransportState: async () => {}};
    const context = {console: {...console, error() {}}, Promise, Array, Map, Set, Object, Uint8Array, TextEncoder,
        window: {location: {}, addEventListener() {}, nacl}, document: {getElementById: () => null},
        localStorage: storage, sessionStorage: storage, crypto, URL, Storage: vault};
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(require.resolve('../js/core_engine.js'), 'utf8'), context);
    const core = context.window.Core;
    core.activeIdentity = 'A'; core.blindSalt = new Uint8Array(32); core.keys = {sign: nacl.sign.keyPair()};
    core.renderPeers = async () => {}; core.sendMessage = async message => receipts.push(message);
    const peer = nacl.sign.keyPair(), peerId = Buffer.from(peer.publicKey).toString('hex');
    let decrypts = 0;
    core.decrypt = async () => {decrypts++; return JSON.stringify({type: 'dmash_message', id: 'wire-one', body: 'Account B content'});};
    const root = nacl.randomBytes(32), recipient = nacl.box.keyPair();
    const inbox = new DeviceInbox({store: new Store(), getRoot: () => root,
        getActiveAccount: () => core._accountTransitioning ? null : core.activeIdentity,
        onAccount: (envelope, slot) => core.receiveAccountDeviceEnvelopeV3(envelope, slot)});
    context.window.NodeManager = {deviceInboxV3: () => inbox};
    await inbox.registerRoute('private-B', {scope: 'ACCOUNT', accountSlot: 'B'});
    const payload = {ciphertext: '001122', sender_proof: Buffer.from(nacl.sign.detached(Buffer.from('001122', 'hex'), peer.secretKey)).toString('hex')};
    const envelope = Envelope.create('private-B', 'MSG', JSON.stringify(payload));
    const localEnvelope = {...envelope, route_alias: await inbox.routeAlias('private-B')};
    delete localEnvelope.route_id;
    const ciphertext = Envelope.seal(recipient.publicKey, envelope);
    assert.equal(await inbox.receive(ciphertext, recipient.secretKey, 'private-B'), 'DEVICE_STORED');
    assert.equal(core.activeIdentity, 'A'); assert.equal(decrypts, 0); assert.equal(writes.length, 0);
    core.activeIdentity = 'B';
    assert.deepEqual(await inbox.drain(), ['PROCESSED']);
    assert.equal(writes.length, 1); assert.equal(receipts[0].state, 'DELIVERED');
    assert.equal(await inbox.receive(ciphertext, recipient.secretKey), 'DUPLICATE');
    const tampered = {...payload, sender_proof: '00'.repeat(64)};
    await assert.rejects(core.receiveAccountDeviceEnvelopeV3({...localEnvelope, account_payload: JSON.stringify(tampered)}, 'B'), /sender proof/);
    assert.equal(decrypts, 1);
    let releaseDecrypt;
    let entered;
    const decryptionStarted = new Promise(resolve => {entered = resolve;});
    core.decrypt = () => new Promise(resolve => {releaseDecrypt = resolve; entered();});
    const receiving = core.receiveAccountDeviceEnvelopeV3(localEnvelope, 'B');
    await decryptionStarted;
    let bootFinished = false;
    const boot = core.boot('C', 'test-only').then(() => {bootFinished = true;});
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(bootFinished, false, 'Account key replacement waits for current Inbox handling');
    assert.equal(await core.receiveAccountDeviceEnvelopeV3(localEnvelope, 'B'), false, 'new handling pauses during Account transition');
    releaseDecrypt(JSON.stringify({type: 'dmash_message', id: 'wire-one', body: 'duplicate'}));
    await receiving; await boot;
    assert.equal(writes.length, 1);
    console.log('Core / Device Inbox multi-account routing, sender proof and Account transition tests passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
