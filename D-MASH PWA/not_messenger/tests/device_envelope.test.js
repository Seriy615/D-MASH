"use strict";
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
const Envelope = require('../js/device_envelope.js');
const recipient = nacl.box.keyPair(), other = nacl.box.keyPair();
for (const type of ['MSG', 'ACK', 'DELIVERED', 'READ', 'CONN_REQUEST', 'CONN_ACCEPT', 'CALL_REQUEST', 'CALL_CANCEL', 'KEY_UPDATE', 'FILE_SESSION_REQUEST', 'DEVICE_EVENT', 'FUTURE_EVENT_V8']) {
    const envelope = Envelope.create('private-local-route', type, 'opaque Account ciphertext', { slot_hint: 'encrypted metadata' });
    const ciphertext = Envelope.seal(recipient.publicKey, envelope);
    const visible = Buffer.from(ciphertext, 'base64').toString();
    for (const secret of [type, envelope.route_id, envelope.account_payload, envelope.packet_id]) assert.equal(visible.includes(secret), false);
    assert.deepEqual(Envelope.open(recipient.secretKey, ciphertext), envelope);
    assert.throws(() => Envelope.open(other.secretKey, ciphertext));
    const corrupt = JSON.parse(visible);
    const bytes = Buffer.from(corrupt.c, 'base64'); bytes[0] ^= 1; corrupt.c = bytes.toString('base64');
    assert.throws(() => Envelope.open(recipient.secretKey, Buffer.from(DmashSecureSession.canonical(corrupt)).toString('base64')));
}
assert.throws(() => Envelope.create('route', 'MSG', 'a'.repeat(40 * 1024)));
assert.throws(() => Envelope.validate({ ...Envelope.create('route', 'MSG', 'cipher'), version: 2 }));
assert.notEqual(Envelope.create('route', 'MSG', '').packet_id, Envelope.create('route', 'MSG', '').packet_id);
console.log('Device envelope real-crypto acceptance: all assertions passed');
