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
const fresh = process.argv[3] === '--fresh';
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
    if (fresh) {
      const {webcrypto,createHmac}=require('node:crypto');
      root=await DeviceRoot._decryptRoot(candidate.record,'synthetic-fresh-master');
      identity=await DeviceRoot.deviceIdentity(root);assert.equal(identity.deviceId,candidate.deviceId);
      assert.equal(candidate.record.credentials.wipeDisabledReason,'not-configured');
      const name='account-registry-v1',slot=candidate.record.materials[name];
      const raw=await DeviceRoot.derive(root,'dmash/device-mlkem-seed-root',1,name);
      const key=await webcrypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);raw.fill(0);
      const registry=new Uint8Array(await webcrypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(slot.iv,'base64'),additionalData:Buffer.from('dmash/device-material/v1|'+name)},key,Buffer.from(slot.ciphertext,'base64')));
      try {
        assert.equal(createHmac('sha256',registry).update(candidate.account.id).digest('base64'),candidate.registryRow.alias);
        const encrypted=Buffer.from(candidate.registryRow.blob,'base64'),regKey=await webcrypto.subtle.importKey('raw',registry,'AES-GCM',false,['decrypt']);
        const plain=new Uint8Array(await webcrypto.subtle.decrypt({name:'AES-GCM',iv:encrypted.subarray(0,12),additionalData:Buffer.from('dmash/account-registry/v1')},regKey,encrypted.subarray(12)));
        try {assert.deepEqual(JSON.parse(new TextDecoder().decode(plain)),candidate.account);}finally{plain.fill(0);}
      } finally {registry.fill(0);}
      console.log('PASS actual JS/WASM opens fresh native Root and authenticates native registry alias/blob; same DeviceID');return;
    }
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
