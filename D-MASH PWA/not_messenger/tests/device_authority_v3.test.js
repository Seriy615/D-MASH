'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
const Authority = require('../js/device_authority_v3.js');
(async () => {
    const saved = new Map(), calls = [], work = [];
    let registered = false;
    const client = { nodeId: 'aa'.repeat(32), transportPublicKey: 'bb'.repeat(32), resourcePowDifficulty: 22,
        session: { transcriptHash: new Uint8Array(32).fill(3) },
        request: async (op, payload, rid) => {
            calls.push({op, payload: structuredClone(payload), rid});
            if (op === 'REGISTER_DNSS' && !registered && !payload.pow) throw Error('DNSS_NOT_REGISTERED');
            if (op === 'REGISTER_DNSS') registered = true;
            return {type: op + '_RESULT'};
        }
    };
    const options = { deviceRoot: { deviceMaterial: async (name, create) => {
        if (!saved.has(name)) saved.set(name, create()); return saved.get(name);
    } }, mine: async args => { work.push(args); return {testProof: args.activationType}; } };
    const authority = new Authority(client, options);
    await Promise.all([authority.bind(), authority.bind()]);
    assert.equal(work.length, 1, 'simultaneous bind shares one work task');
    const original = Buffer.from(authority.dnss).toString('hex');
    authority.close();
    const reconnect = new Authority(client, options);
    await reconnect.bind();
    assert.equal(Buffer.from(reconnect.dnss).toString('hex'), original);
    assert.equal(work.length, 1, 'reconnect must not mine while registration survives');
    registered = false;
    const restart = new Authority(client, options);
    await restart.bind();
    assert.equal(Buffer.from(restart.dnss).toString('hex'), original);
    assert.equal(work.length, 2, 'Node restart repeats work for the same DNSS');
    const signing = nacl.sign.keyPair();
    const route = {kind: 'PRIVATE', routeId: 'private-locator', signing, generation: 1, expiresAt: 2000};
    await restart.route('REGISTER_ROUTE', route);
    const call = calls.at(-1), auth = call.payload.authorization;
    assert.equal('entry_grant' in call.payload, false);
    assert.equal(work.at(-1).activationType, 'PRIVATE_ROUTE');
    const transcript = session => new TextEncoder().encode('D-MASH|ROUTE-AUTH|V3\0' + DmashSecureSession.canonical({
        node_id: client.nodeId, session, dnss: original, operation: call.op, request_id: call.rid,
        kind: auth.kind, route_id: auth.route_id, public_key: auth.public_key,
        generation: auth.generation, expires_at: auth.expires_at
    }));
    assert.ok(nacl.sign.detached.verify(transcript('03'.repeat(32)), DmashSecureSession.unb64(auth.signature), signing.publicKey));
    assert.equal(nacl.sign.detached.verify(transcript('04'.repeat(32)), DmashSecureSession.unb64(auth.signature), signing.publicKey), false);
    await restart.route('START_PROBE', route, {route_locator: 'destination'});
    assert.equal(calls.at(-1).payload.back_route_locator, route.routeId);
    assert.notEqual(calls.at(-1).rid, call.rid);
    client.resourcePowDifficulty = 256;
    await assert.rejects(restart.work('DNSS', restart.dnss), /policy/);
    console.log('Device v3 authority lifecycle and cryptographic proof tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
