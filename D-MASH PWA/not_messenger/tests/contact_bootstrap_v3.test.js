'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
require('../js/device_routes.js');
const Bootstrap = require('../js/contact_bootstrap_v3.js');
const b64url = value => Buffer.from(value).toString('base64url');
function identity() {
    const signing = nacl.sign.keyPair(), box = nacl.box.keyPair();
    const certificate = {version: 1, routeId: b64url(signing.publicKey), signingPublicKey: b64url(signing.publicKey), boxPublicKey: b64url(box.publicKey), issuedAt: 1000};
    certificate.signature = b64url(nacl.sign.detached(DeviceRoutes.certificateTranscript(certificate), signing.secretKey));
    return {signing, certificate};
}
(async () => {
    const a = identity(), b = identity(), account = nacl.sign.keyPair();
    // Public bundle layout fixture: Ed25519 + X25519 + 1184-byte legacy KEM public bytes.
    const bundle = Buffer.concat([Buffer.from(account.publicKey), Buffer.from(nacl.box.keyPair().publicKey), Buffer.from(nacl.randomBytes(1184))]).toString('hex');
    const body = {version: 3, phase: 'ACCEPT', request_id: b64url(nacl.randomBytes(32)), recipient_route_id: a.certificate.routeId,
        route_certificate: b.certificate, account_bundle: bundle, contribution: Buffer.from(nacl.randomBytes(32)).toString('hex'),
        display_name: 'Contact B', created_at: 1000, expires_at: 2000, accept_hash: null};
    const message = Bootstrap.create(body, account, b.signing, 1000);
    const context = {requestId: body.request_id, recipientRouteId: a.certificate.routeId, senderRouteId: b.certificate.routeId, phase: 'ACCEPT', now: 1000};
    assert.deepEqual(Bootstrap.verify(message, context), body);
    for (const change of [{requestId: b64url(nacl.randomBytes(32))}, {recipientRouteId: b.certificate.routeId}, {senderRouteId: a.certificate.routeId}, {phase: 'CONFIRM'}, {now: 2000}]) assert.throws(() => Bootstrap.verify(message, {...context, ...change}));
    const changed = structuredClone(message); changed.body.contribution = '00'.repeat(32);
    assert.throws(() => Bootstrap.verify(changed, context), /signature/);
    assert.throws(() => Bootstrap.create(body, account, a.signing, 1000), /key mismatch/);
    const hash = await Bootstrap.digest(message);
    const confirmBody = {...body, phase: 'CONFIRM', recipient_route_id: b.certificate.routeId, route_certificate: a.certificate, accept_hash: hash};
    const confirm = Bootstrap.create(confirmBody, account, a.signing, 1000);
    const confirmContext = {...context, phase: 'CONFIRM', recipientRouteId: b.certificate.routeId, senderRouteId: a.certificate.routeId, acceptHash: hash};
    assert.equal(Bootstrap.verify(confirm, confirmContext).accept_hash, hash);
    assert.throws(() => Bootstrap.verify(confirm, {...confirmContext, acceptHash: '00'.repeat(32)}));
    console.log('Contact bootstrap Account/Route dual signatures and transcript binding passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
