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
  sign: { keyPair: { fromSeed: (seed) => ({ publicKey: new Uint8Array(seed.map((v) => v ^ 0xa5)), secretKey: new Uint8Array(64) }) } },
  box: { keyPair: { fromSecretKey: (seed) => ({ publicKey: new Uint8Array(seed.map((v) => v ^ 0x5a)), secretKey: new Uint8Array(32) }) } }
};
const { DeviceRoot, DeviceRootError } = require("../js/device_root.js");

class MemoryStore {
  constructor(record = null, legacy = false) { this.record = record; this.indexedDb = { databases: async () => (legacy ? [{ name: "dm_gamma_vault" }] : []) }; this.failPut = false; }
  async get() { return this.record; }
  async put(record) { if (this.failPut) throw new DeviceRootError("STORAGE_WRITE_FAILED", "write failed"); this.record = structuredClone(record); }
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
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(stored));
  const reloaded = await DeviceRoot.unlock("correct horse battery staple");
  assert.equal(reloaded.identity.deviceId, firstId, "identity persists across reload/restart");
  assert.deepEqual([...reloaded.root], [...firstRoot]);

  // A distinct installation gets independent CSPRNG root/DeviceID.
  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore());
  const secondInstall = await DeviceRoot.unlock("correct horse battery staple");
  assert.notDeepEqual([...secondInstall.root], [...firstRoot]);
  assert.notEqual(secondInstall.identity.deviceId, firstId);

  DeviceRoot.lock(); DeviceRoot.setStoreForTests(new MemoryStore(stored));
  await assert.rejects(() => DeviceRoot.unlock("wrong pin"), (error) => error.code === "UNLOCK_FAILED");
  DeviceRoot.setStoreForTests(new MemoryStore(null, true));
  const legacy = await DeviceRoot.bootstrap("pin");
  assert.equal(legacy.legacy, true); assert.equal(legacy.migrationRequired, true);
  const failed = new MemoryStore(); failed.failPut = true; DeviceRoot.setStoreForTests(failed);
  await assert.rejects(() => DeviceRoot.unlock("pin"), (error) => error.code === "STORAGE_WRITE_FAILED");
  assert.equal(failed.record, null, "failed persistence cannot create a usable identity");

  // Network and QR implementations cannot obtain the root/record API.
  for (const filename of ["../js/node_manager.js", "../js/core_engine.js"]) {
    const source = fs.readFileSync(require.resolve(filename), "utf8");
    assert.equal(/wrappedRoot|wrapSalt|\.root\b/.test(source.replace(/window\.DeviceRoot\.bootstrap\([^)]*\)/g, "")), false, `${filename} must not serialize root material`);
  }

  console.log("DeviceRoot acceptance: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
