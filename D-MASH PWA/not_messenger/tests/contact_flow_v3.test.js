'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
require('../js/device_routes.js');
require('../js/contact_payloads.js');
const Envelope = require('../js/device_envelope.js');
const Bootstrap = require('../js/contact_bootstrap_v3.js');
const Flow = require('../js/contact_flow_v3.js');
const {DeviceInbox} = require('../js/device_inbox.js');
const b64url = value => Buffer.from(value).toString('base64url');
class Store {
    constructor() {this.rows = new Map();}
    async all() {return structuredClone([...this.rows.values()]);}
    async get(key) {return structuredClone(this.rows.get(key) || null);}
    async write(record, absent) {if (absent && this.rows.has(record.key)) return false; this.rows.set(record.key, structuredClone(record)); return true;}
}
function device(slot) {
    const route = nacl.sign.keyPair(), box = nacl.box.keyPair(), account = nacl.sign.keyPair(), root = nacl.randomBytes(32);
    const now = Math.floor(Date.now() / 1000);
    const certificate = {version: 1, routeId: b64url(route.publicKey), signingPublicKey: b64url(route.publicKey), boxPublicKey: b64url(box.publicKey), issuedAt: now};
    certificate.signature = b64url(nacl.sign.detached(DeviceRoutes.certificateTranscript(certificate), route.secretKey));
    const bundle = Buffer.concat([Buffer.from(account.publicKey), Buffer.from(nacl.box.keyPair().publicKey), Buffer.from(nacl.randomBytes(1184))]).toString('hex');
    const store = new DeviceInbox({store: new Store(), getRoot: () => root});
    const self = {certificate, box, bundle, store, slot, active: slot, sent: [], imported: [], failSend: false};
    self.options = {store, activeAccount: () => self.active,
        makeBootstrap: async options => Bootstrap.create({version: 3, phase: options.phase, request_id: options.request.request_id,
            recipient_route_id: options.peerCertificate.routeId, route_certificate: certificate,
            account_bundle: bundle, contribution: (slot === 'A' ? '11' : '22').repeat(32), display_name: options.displayName,
            created_at: now, expires_at: now + 3600, accept_hash: options.acceptHash}, account, route),
        importPeer: async (body, expectedSlot) => {assert.equal(expectedSlot, self.active); self.imported.push(body.account_bundle);},
        send: async (recipient, message) => {
            if (self.failSend) throw Error('simulated socket failure');
            const publicKey = Buffer.from(recipient.boxPublicKey, 'base64url');
            self.sent.push(Envelope.seal(publicKey, Envelope.create(recipient.routeId, 'CONN_ACCEPT', JSON.stringify(message))));
        }};
    self.flow = new Flow(self.options);
    return self;
}
(async () => {
    const a = device('A'), b = device('B');
    const request = {type: 'CONTACT_REQUEST_V1', version: 1, request_id: b64url(nacl.randomBytes(32)),
        reply_route_certificate: a.certificate, sender_display_name: 'Alice', intro_message: '',
        bootstrap_encryption_public: a.certificate.boxPublicKey, protocol_capabilities: ['CONTACT_BOOTSTRAP_V3', 'DMP_C_V3']};
    await assert.rejects(b.flow.accept({...request, protocol_capabilities: ['CONTACT_ACCEPT_V1', 'DMP_C_V2']}, b.certificate, 'Bob'), /обновить/);
    await a.flow.recordOutgoing(request, b.certificate);
    a.active = 'Other';
    await assert.rejects(a.flow.recordOutgoing(request, b.certificate, 'A'), /выбранный Account/);
    a.active = 'A';
    b.failSend = true;
    await assert.rejects(b.flow.accept(request, b.certificate, 'Bob'), /socket failure/);
    const prepared = (await b.flow.read(request.request_id)).accept;
    b.flow = new Flow(b.options); b.failSend = false;
    await assert.rejects(b.flow.accept({...request, sender_display_name: 'Changed'}, b.certificate, 'Bob'), /context changed/);
    await assert.rejects(b.flow.accept(request, a.certificate, 'Bob'), /context changed/);
    assert.equal(b.sent.length, 0, 'changed request context must not resend a prepared Accept');
    await b.flow.accept(request, b.certificate, 'Bob');
    assert.deepEqual((await b.flow.read(request.request_id)).accept, prepared, 'retry sends exactly the persisted signed Accept');
    const acceptEnvelope = Envelope.open(a.box.secretKey, b.sent[0]);
    a.active = 'Different Account';
    await a.flow.receive(a.certificate.routeId, JSON.parse(acceptEnvelope.account_payload));
    await a.flow.resume(); assert.equal(a.imported.length, 0);
    a.active = 'A'; await a.flow.resume();
    assert.deepEqual(a.imported, [b.bundle]);
    assert.equal((await a.flow.read(request.request_id)).status, 'established');
    const confirmEnvelope = Envelope.open(b.box.secretKey, a.sent[0]);
    b.active = null;
    await b.flow.receive(b.certificate.routeId, JSON.parse(confirmEnvelope.account_payload));
    await b.flow.resume(); assert.equal(b.imported.length, 0);
    b.active = 'B'; await b.flow.resume();
    assert.deepEqual(b.imported, [a.bundle]);
    await b.flow.receive(b.certificate.routeId, JSON.parse(confirmEnvelope.account_payload));
    await b.flow.resume(); assert.equal(b.imported.length, 1, 'duplicate Confirm is idempotent');
    const sentCount = b.sent.length;
    assert.equal(await b.flow.accept(request, b.certificate, 'Bob'), 'established');
    assert.equal(b.sent.length, sentCount, 'repeated acceptance must not regress an established contact');
    const conflict = structuredClone(prepared); conflict.body.contribution = '33'.repeat(32);
    await assert.rejects(a.flow.receive(a.certificate.routeId, conflict), /signature/);
    for (const endpoint of [a, b]) {
        assert.equal(JSON.stringify(await endpoint.store.store.all()).includes(endpoint.bundle), false);
        for (const frame of endpoint.sent) assert.equal(Buffer.from(frame, 'base64').toString().includes(endpoint.bundle), false);
    }
    console.log('Encrypted Contact Accept/Confirm, restart retry and locked Account flow passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
