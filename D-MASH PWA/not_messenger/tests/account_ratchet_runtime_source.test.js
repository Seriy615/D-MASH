const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const jsDir = path.join(__dirname, '..', 'js');
const coreSource = fs.readFileSync(path.join(jsDir, 'core_engine.js'), 'utf8');
const runtimeSource = fs.readFileSync(path.join(jsDir, 'account_ratchet_runtime.js'), 'utf8');

assert.match(runtimeSource, /DmashAccountRatchetRuntime/);
assert.match(runtimeSource, /HYBRID_MLKEM768_V2/);
assert.match(runtimeSource, /ratchetRoot/);
assert.match(coreSource, /return window\.DmashAccountRatchetRuntime\.encryptPacket/);
assert.match(coreSource, /return window\.DmashAccountRatchetRuntime\.handleUpdate/);
assert.match(coreSource, /ratchetOverride/);
assert.doesNotMatch(coreSource, /const PACKET_DOMAIN/);

global.window = global;
require(path.join(jsDir, 'account_ratchet_runtime.js'));
assert.equal(typeof global.DmashAccountRatchetRuntime.initHandshake, 'function');
assert.equal(typeof global.DmashAccountRatchetRuntime.encryptPacket, 'function');
console.log('account_ratchet_runtime_source.test.js: ratchet orchestration is split from Core');
