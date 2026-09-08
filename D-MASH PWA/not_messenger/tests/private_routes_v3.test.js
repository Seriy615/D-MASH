'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
const Envelope = require('../js/device_envelope.js');
const Routes = require('../js/private_routes_v3.js');
(async () => {
    const a = Buffer.from(nacl.randomBytes(32)).toString('hex'), b = Buffer.from(nacl.randomBytes(32)).toString('hex');
    const alice = await Routes.pair(a, b), bob = await Routes.pair(b, a), next = await Routes.pair(a, b, 2);
    assert.equal(alice.routeLocator, bob.backRouteLocator);
    assert.equal(alice.backRouteLocator, bob.routeLocator);
    assert.notEqual(alice.routeLocator, alice.backRouteLocator);
    assert.notEqual(alice.routeLocator, next.routeLocator);
    const prefix = Buffer.from('D-MASH|PRIVATE-LOCATOR|V3\0');
    const {createHash} = require('node:crypto');
    assert.equal(createHash('sha256').update(prefix).update(alice.incoming.signing.publicKey).digest('hex'), alice.backRouteLocator);
    const envelope = Envelope.create(alice.routeLocator, 'MSG', 'opaque Account ciphertext');
    const ciphertext = Envelope.seal(alice.outgoing.box.publicKey, envelope);
    assert.deepEqual(Envelope.open(bob.incoming.box.secretKey, ciphertext), envelope);
    assert.throws(() => Envelope.open(alice.incoming.box.secretKey, ciphertext));
    assert.throws(() => Envelope.open(next.outgoing.box.secretKey, ciphertext));
    await assert.rejects(Routes.pair(a, a));
    for (const pair of [alice, bob, next]) {
        pair.close();
        assert.ok(pair.incoming.signing.secretKey.every(byte => byte === 0));
        assert.ok(pair.outgoing.box.secretKey.every(byte => byte === 0));
    }
    console.log('Private route directional capability and Device box tests passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
