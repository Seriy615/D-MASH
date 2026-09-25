'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
const {Initiator, Session} = require('../js/secure_session.js');
const signing = nacl.sign.keyPair();
for (const version of [true, '4', 0, 5]) assert.throws(() => new Initiator(signing, 'NODE', version), /version/i);
assert.throws(() => new Initiator(signing, 'DEVICE', 4), /role/i);
assert.throws(() => new Session(nacl.randomBytes(32), nacl.randomBytes(32), nacl.randomBytes(32), {version:4}), /role/i);
for (const version of [3, 4]) {
    const initiator = new Initiator(signing, 'NODE', version);
    const hello = initiator.initiate();
    assert.equal(hello.role, 'NODE'); assert.equal(hello.version, version);
    initiator.close();
    assert(!initiator.private.some(Boolean));
    const a = nacl.randomBytes(32), b = nacl.randomBytes(32), hash = nacl.randomBytes(32);
    const options = {version, localRole:'NODE', peerRole:'NODE'};
    const sender = new Session(a, b, hash, options), receiver = new Session(b, a, hash, options);
    const frame = sender.seal({type:'PING'});
    assert.equal(frame.version, version);
    assert.deepEqual(receiver.open(frame), {type:'PING'});
    assert.throws(() => receiver.open(frame), /record/i);
    assert(receiver.closed);
    const other = new Session(b, a, hash, {...options, version:version === 3 ? 4 : 3});
    assert.throws(() => other.open(frame), /record/i);
    assert(other.closed);
}
console.log('Explicit secure-session profiles reject old roles, unknown versions and cross-version records');
