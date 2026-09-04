#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { webcrypto } = require("node:crypto");
if (!global.crypto) Object.defineProperty(global, "crypto", { value: webcrypto, configurable: true });
global.btoa = (value) => Buffer.from(value, "binary").toString("base64");
global.atob = (value) => Buffer.from(value, "base64").toString("binary");
// Argon2 is intentionally stubbed only for persistence-flow tests.  HKDF test
// vectors below use native WebCrypto and the production KDF implementation.
global.argon2 = { argon2id: 2, hash: async ({ pass, salt }) => ({ hash: new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`test-wrap|${pass}|${salt}`))) }) };
global.nacl = {
  sign: { keyPair: { fromSeed: (seed) => ({ publicKey: new Uint8Array(seed.map((v) => v ^ 0xa5)), secretKey: new Uint8Array([...seed, ...seed]) }) }, detached: Object.assign(
    (message, secretKey) => new Uint8Array([...message].map((v, i) => v ^ secretKey[i % secretKey.length])),
    { verify: (message, signature, publicKey) => signature.length === message.length && [...signature].every((v, i) => v === (message[i] ^ (publicKey[i % publicKey.length] ^ 0xa5))) }
  ) },
  box: { keyPair: { fromSecretKey: (seed) => ({ publicKey: new Uint8Array(seed.map((v) => v ^ 0x5a)), secretKey: new Uint8Array(32) }) } }
};
const { DeviceRoot, DeviceRootError } = require("../js/device_root.js");

class MemoryStore {
  constructor(record = null, legacy = false) { this.records = new Map(record ? [["root", record]] : []); this.indexedDb = { databases: async () => (legacy ? [{ name: "dm_gamma_vault" }] : []) }; this.failPut = false; this.failAt = 0; this.puts = 0; }
  get record() { return this.records.get("root") || null; }
  async get(id = "root") { return this.records.get(id) || null; }
  async put(record) { this.puts++; if (this.failPut || this.puts === this.failAt) throw new DeviceRootError("STORAGE_WRITE_FAILED", "write failed"); this.records.set(record.id, structuredClone(record)); }
}
const hex = (bytes) => Buffer.from(bytes).toString("hex");

(async () => {
  const root = Uint8Array.from([...Array(32).keys()]);
  // Independently cross-checked RFC 5869/HKDF-SHA-256 derivation using the
  // canonical info encoding documented in DEVICE_ROOT_ARCHITECTURE.md.
  const vector = await DeviceRoot.derive(root, DeviceRoot.domains.storage, 1, "account:alpha");
  assert.equal(hex(vector), "9ea96294abd4d5642d68e43357e2c098100c759d237a71c7226bb5cb79d160ef", "deterministic DeviceRoot vector");
  assert.notEqual(hex(vector), hex(await DeviceRoot.derive(root, DeviceRoot.domains.routing, 1, "account:alpha")));
  assert.notEqual(hex(vector), hex(await DeviceRoot.derive(root, DeviceRoot.domains.storage, 2, "account:alpha")));
  assert.notEqual(hex(vector), hex(await DeviceRoot.derive(root, DeviceRoot.domains.storage, 1, "account:beta")));

  const first = new MemoryStore(); DeviceRoot.setStoreForTests(first);
  const created = await DeviceRoot.unlock("correct horse battery staple");
  assert.equal(created.root.length, 32); assert.equal(created.created, true);
  const firstId = created.identity.deviceId; const firstRoot = new Uint8Array(created.root); const stored = structuredClone(first.record);
  assert.equal(JSON.stringify(stored).includes(hex(created.root)), false, "root must not be plaintext persisted");
  assert.equal(stored.wrap, "argon2id-aes-256-gcm-v1", "new records explicitly identify their Argon2id/AES-GCM wrapping scheme");
  assert.equal(Buffer.from(stored.wrapSalt, "base64").length, 16, "wrapping salt is 128 bits");
  assert.equal(Buffer.from(stored.iv, "base64").length, 12, "AES-GCM wrapping IV is 96 bits");
  assert.equal(Buffer.from(stored.wrappedRoot, "base64").length, 48, "wrapped root contains a 256-bit root and GCM tag");
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(stored));
  const reloaded = await DeviceRoot.unlock("correct horse battery staple");
  assert.equal(reloaded.identity.deviceId, firstId, "identity persists across reload/restart");
  assert.deepEqual([...reloaded.root], [...firstRoot]);

  // A distinct installation gets independent CSPRNG root/DeviceID.
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore());
  const secondInstall = await DeviceRoot.unlock("correct horse battery staple");
  assert.notDeepEqual([...secondInstall.root], [...firstRoot]);
  assert.notEqual(secondInstall.identity.deviceId, firstId);

  // Explicit legacy migration happens only after a supplied unlocked Account
  // key. It preserves that Account public identity and is idempotent.
  const legacyStore = new MemoryStore(null, true); DeviceRoot.lock(); DeviceRoot.setStoreForTests(legacyStore);
  const accountSeed = Uint8Array.from({ length: 32 }, (_, i) => 200 + i);
  const account = global.nacl.sign.keyPair.fromSeed(accountSeed);
  const accountPublicKey = hex(account.publicKey);
  const migrated = await DeviceRoot.migrateLegacy("pin", accountPublicKey, account.secretKey);
  const migratedId = migrated.identity.deviceId; const migratedRecord = structuredClone(legacyStore.record);
  assert.equal(migrated.record.migration.state, "complete");
  assert.equal(migrated.record.migration.binding.account_public_key, accountPublicKey);
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(migratedRecord, true));
  const resumed = await DeviceRoot.migrateLegacy("pin", accountPublicKey, account.secretKey);
  assert.equal(resumed.identity.deviceId, migratedId, "migration retry cannot create another device");
  const nodeA = await DeviceRoot.transportIdentity("aa".repeat(32));
  const nodeB = await DeviceRoot.transportIdentity("bb".repeat(32));
  assert.notDeepEqual([...nodeA.signing.publicKey], [...nodeB.signing.publicKey], "node contexts must be unlinkable");

  // Interrupted after root persistence but before complete commit: restart
  // resumes exactly that root/device, rather than making a second identity.
  const interrupted = new MemoryStore(null, true); interrupted.failAt = 3;
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(interrupted);
  await assert.rejects(() => DeviceRoot.migrateLegacy("pin", accountPublicKey, account.secretKey), (error) => error.code === "STORAGE_WRITE_FAILED");
  const interruptedRootRecord = structuredClone(interrupted.record);
  interrupted.failAt = 0; DeviceRoot.lock(); DeviceRoot.setStoreForTests(interrupted);
  const recovered = await DeviceRoot.migrateLegacy("pin", accountPublicKey, account.secretKey);
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(interruptedRootRecord, true));
  const sameRecovered = await DeviceRoot.migrateLegacy("pin", accountPublicKey, account.secretKey);
  assert.equal(recovered.identity.deviceId, sameRecovered.identity.deviceId, "interruption recovery must reuse persisted root");

  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(stored));
  await assert.rejects(() => DeviceRoot.unlock("wrong pin"), (error) => error.code === "UNLOCK_FAILED");
  const malformed = structuredClone(stored); malformed.iv = "not base64";
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(malformed));
  await assert.rejects(() => DeviceRoot.unlock("correct horse battery staple"), (error) => error.code === "UNLOCK_FAILED", "malformed wrapping fields fail closed");
  const unknownWrap = structuredClone(stored); unknownWrap.wrap = "sha256-verifier-v1";
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(unknownWrap));
  await assert.rejects(() => DeviceRoot.unlock("correct horse battery staple"), (error) => error.code === "UNLOCK_FAILED", "legacy SHA verifier scheme is not accepted");
  const originalArgon2 = global.argon2;
  global.argon2 = { argon2id: 2, hash: async () => ({ hash: new Uint8Array(31) }) };
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore());
  await assert.rejects(() => DeviceRoot.unlock("pin"), (error) => error.code === "ARGON2_FAILED", "invalid Argon2 output cannot create a DeviceRoot");
  global.argon2 = originalArgon2;
  DeviceRoot.setStoreForTests(new MemoryStore(null, true));
  const legacy = await DeviceRoot.bootstrap("pin");
  assert.equal(legacy.legacy, true); assert.equal(legacy.migrationRequired, true);
  const failed = new MemoryStore(); failed.failPut = true; DeviceRoot.setStoreForTests(failed);
  await assert.rejects(() => DeviceRoot.unlock("pin"), (error) => error.code === "STORAGE_WRITE_FAILED");
  assert.equal(failed.record, null, "failed persistence cannot create a usable identity");

  // WebAuthn PRF is deliberately a platform-only, user-verified alternative
  // wrapping path.  These mocks use only Node's built-in WebCrypto.
  const originalSecureContext = global.isSecureContext;
  Object.defineProperty(global, "isSecureContext", { value: true, configurable: true });
  const webauthnRoot = Uint8Array.from({ length: 32 }, (_, i) => 31 - i);
  const prfOutput = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const credentialId = Uint8Array.from([1, 2, 3, 4]);
  const prfCredential = (output = prfOutput) => ({
    rawId: credentialId.buffer.slice(0),
    getClientExtensionResults: () => ({ prf: { results: { first: output.buffer.slice(output.byteOffset, output.byteOffset + output.byteLength) } } })
  });
  const installWebAuthn = ({ assertion = prfCredential(), create = prfCredential() } = {}) => {
    const calls = { create: [], get: [] };
    Object.defineProperty(global, "navigator", { value: { credentials: {
      create: async (options) => { calls.create.push(options); return create; },
      get: async (options) => { calls.get.push(options); return assertion; }
    } }, configurable: true });
    return calls;
  };
  const webauthnRecord = { id: "root", version: 1, materials: {} };
  const webauthnStore = new MemoryStore(webauthnRecord);
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(webauthnStore);
  DeviceRoot.state = { root: new Uint8Array(webauthnRoot), record: webauthnRecord, identity: null, created: false };
  const calls = installWebAuthn();
  const enrolled = await DeviceRoot.enrollWebAuthnPrf();
  assert.deepEqual(enrolled, { enrolled: true }, "a platform PRF credential enrolls successfully");
  assert.equal(calls.create[0].publicKey.authenticatorSelection.authenticatorAttachment, "platform");
  assert.equal(calls.create[0].publicKey.authenticatorSelection.userVerification, "required");
  assert.equal(calls.get[0].publicKey.userVerification, "required");
  assert.equal(calls.get[0].publicKey.extensions.prf.eval.first.length, 32);
  assert.equal(webauthnStore.record.biometricWrap.wrap, "webauthn-prf-aes-256-gcm-v1");

  // A fresh lock can recover precisely the enrolled root with the PRF alone.
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(structuredClone(webauthnStore.record)));
  installWebAuthn();
  const biometricUnlocked = await DeviceRoot.unlockWithWebAuthnPrf();
  assert.deepEqual([...biometricUnlocked.root], [...webauthnRoot], "correct PRF unlocks the enrolled root");

  // No PRF result, a wrong result, and corrupt metadata all fail closed; none
  // may invoke the calculator-PIN unlock path or create/replace a record.
  const enrolledRecord = structuredClone(webauthnStore.record);
  for (const [label, record, assertion] of [
    ["missing PRF", enrolledRecord, { rawId: credentialId.buffer.slice(0), getClientExtensionResults: () => ({}) }],
    ["invalid PRF length", enrolledRecord, prfCredential(new Uint8Array(31))],
    ["wrong PRF", enrolledRecord, prfCredential(new Uint8Array(32).fill(99))],
    ["corrupt metadata", { ...enrolledRecord, biometricWrap: { ...enrolledRecord.biometricWrap, iv: "not-base64" } }, prfCredential()]
  ]) {
    const store = new MemoryStore(structuredClone(record));
    DeviceRoot.lock(); DeviceRoot.setStoreForTests(store); installWebAuthn({ assertion });
    let pinFallback = false;
    const originalUnlock = DeviceRoot.unlock;
    DeviceRoot.unlock = async () => { pinFallback = true; };
    await assert.rejects(() => DeviceRoot.unlockWithWebAuthnPrf(), (error) => error.code === "WEBAUTHN_UNLOCK_FAILED", `${label} must fail closed`);
    DeviceRoot.unlock = originalUnlock;
    assert.equal(pinFallback, false, `${label} must not fall back to PIN`);
    assert.deepEqual(store.record, record, `${label} must not alter stored data`);
  }

  // Required WebAuthn APIs are secure-context-only. This assertion currently
  // exposes whether production rejects an otherwise functional insecure API.
  Object.defineProperty(global, "isSecureContext", { value: false, configurable: true });
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore({ id: "root", version: 1, materials: {} }));
  DeviceRoot.state = { root: new Uint8Array(webauthnRoot), record: { id: "root", version: 1, materials: {} }, identity: null, created: false };
  installWebAuthn();
  await assert.rejects(() => DeviceRoot.enrollWebAuthnPrf(), (error) => error.code === "WEBAUTHN_UNAVAILABLE", "WebAuthn must be rejected outside a secure context");
  Object.defineProperty(global, "isSecureContext", { value: originalSecureContext, configurable: true });

  // AUTH serializes only a node-scoped public key/nonces/signature, never root
  // records or Account key material. The transportIdentity API is permitted:
  // it derives locally and returns a scoped signing key, not DeviceRoot bytes.
  const nodeManager = fs.readFileSync(require.resolve("../js/node_manager.js"), "utf8");
  const authSend = nodeManager.slice(nodeManager.indexOf("type: 'AUTH'"), nodeManager.indexOf("}));", nodeManager.indexOf("type: 'AUTH'")));
  assert.equal(/wrappedRoot|wrapSalt|activeIdentity|Core\.keys|passphrase|\.root\b/.test(authSend), false, "AUTH frame must not serialize root or Account material");

  console.log("DeviceRoot acceptance: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
