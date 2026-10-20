'use strict';
// Native test exports only a synthetic encrypted candidate; reopen it through
// the actual shipped WASM and existing JS DeviceRoot, not a second fake KDF.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const repo = path.resolve(__dirname, '../../..');
const input = process.argv[2];
const service = process.argv[3] === '--service';
if (!input) throw Error('Usage: node reopen_native_wrap.cjs SYNTHETIC_NATIVE_OUTPUT');
const context = { WebAssembly, TextEncoder, TextDecoder, Uint8Array, Int8Array,
  Uint16Array, Int16Array, Uint32Array, Int32Array, Float32Array, Float64Array,
  ArrayBuffer, Promise, Math, Date, console, atob, btoa, setTimeout, clearTimeout };
context.window = context; context.self = context; vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(repo, 'D-MASH PWA/not_messenger/js/vendor/argon2-bundled.min.js'), 'utf8'), context);
global.argon2 = context.argon2;
global.nacl = require(path.join(repo, 'D-MASH PWA/not_messenger/js/vendor/nacl-fast.min.js'));
const { DeviceRoot } = require(path.join(repo, 'D-MASH PWA/not_messenger/js/device_root.js'));
(async () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'compatibility.json'), 'utf8'));
  const candidate = JSON.parse(fs.readFileSync(input, 'utf8'));
  let root, identity;
  try {
    root = await DeviceRoot._decryptRoot(candidate, service ? 'synthetic-next-master' : 'synthetic-only-next-master');
    identity = await DeviceRoot.deviceIdentity(root);
    assert.equal(identity.deviceId, fixture.deviceId);
    assert.deepEqual(candidate.materials, fixture.records.modern_id.materials);
    if (service) {
      assert.ok(candidate.credentialRevision > fixture.records.modern_id.credentialRevision);
      assert.equal(candidate.credentials.legacyCleanup, 'complete');
      const verifier = candidate.credentials.wipe;
      const prehash = require('node:crypto').createHash('sha256').update('synthetic-wipe').digest('hex');
      const derived = await context.argon2.hash({ pass: prehash,
        salt: 'dmash/local-wipe/v1|' + verifier.salt,
        type: 2, time: 3, mem: 65536, parallelism: 1, hashLen: 32, version: 19 });
      assert.equal(Buffer.from(derived.hash).toString('base64'), verifier.digest);
      derived.hash.fill(0);
    } else assert.equal(candidate.credentialRevision, fixture.records.modern_id.credentialRevision);
    console.log('PASS actual JS/WASM opens native v2 rewrap; same DeviceID and encrypted materials');
  } finally {
    root?.fill(0); identity?.signing.secretKey.fill(0); identity?.agreement.secretKey.fill(0);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
