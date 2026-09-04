#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
if (!global.crypto) Object.defineProperty(global, "crypto", { value: webcrypto, configurable: true });
global.btoa = (value) => Buffer.from(value, "binary").toString("base64");
global.atob = (value) => Buffer.from(value, "base64").toString("binary");
const { QuickNameRegistry, QuickNameRegistryError, MATERIAL_NAME, STORAGE_KEY } = require("../js/quick_name_registry.js");

class MemoryStorage {
  constructor() { this.values = new Map(); }
  getItem(key) { return this.values.get(key) || null; }
  setItem(key, value) { this.values.set(key, value); }
}
class FakeDeviceRoot {
  constructor() { this.materials = new Map(); this.calls = []; }
  async deviceMaterial(name, create) {
    this.calls.push(name);
    if (!this.materials.has(name)) this.materials.set(name, new Uint8Array(await create()));
    return new Uint8Array(this.materials.get(name));
  }
}
(async () => {
  const storage = new MemoryStorage(), deviceRoot = new FakeDeviceRoot();
  let clock = 1000, sequence = 0;
  const registry = new QuickNameRegistry({ storage, deviceRoot, now: () => ++clock, idFactory: () => `qn_test_${++sequence}` });
  assert.deepEqual(await registry.list(), []);
  const alice = await registry.add({ name: "  Alice   Home ", value: " alice-id ", makeDefault: true });
  const bob = await registry.add({ name: "Bob", value: "bob-id" });
  assert.equal(alice.name, "Alice Home"); assert.equal(alice.value, "alice-id");
  assert.deepEqual(await registry.getDefault(), alice);
  const encrypted = storage.getItem(STORAGE_KEY);
  assert.ok(encrypted && !encrypted.includes("Alice Home") && !encrypted.includes("alice-id"), "plaintext cannot persist");
  assert.deepEqual(deviceRoot.calls, [MATERIAL_NAME, MATERIAL_NAME], "all saves derive protected DeviceRoot material");

  await assert.rejects(() => registry.add({ name: "alice home", value: "different" }), (error) => error instanceof QuickNameRegistryError && error.code === "DUPLICATE_NAME");
  await assert.rejects(() => registry.add({ name: "\u0000", value: "x" }), (error) => error.code === "INVALID_NAME");
  await assert.rejects(() => registry.add({ name: "valid", value: " " }), (error) => error.code === "INVALID_VALUE");
  const edited = await registry.edit(bob.id, { name: "Robert", value: "robert-id" });
  assert.equal(edited.name, "Robert"); assert.equal(edited.value, "robert-id");
  await assert.rejects(() => registry.edit(bob.id, {}), (error) => error.code === "NO_CHANGES");
  assert.deepEqual((await registry.move(bob.id, 0)).map(entry => entry.id), [bob.id, alice.id]);
  await assert.rejects(() => registry.move(bob.id, 2), (error) => error.code === "INVALID_ORDER");

  await registry.markRecent(alice.id); await registry.markRecent(bob.id);
  assert.deepEqual((await registry.recent()).map(entry => entry.id), [bob.id, alice.id]);
  await registry.setDefault(bob.id); assert.equal((await registry.getDefault()).id, bob.id);
  assert.equal((await registry.remove(bob.id)).id, bob.id);
  assert.equal((await registry.getDefault()).id, alice.id, "deleting default chooses first surviving entry");
  await registry.remove(alice.id); assert.equal(await registry.getDefault(), null);

  const restarted = new QuickNameRegistry({ storage, deviceRoot });
  assert.deepEqual(await restarted.list(), [], "encrypted state survives reload");
  storage.setItem(STORAGE_KEY, JSON.stringify({ version: 1, iv: "AAAAAAAAAAAAAAAA", ciphertext: "AAAA" }));
  const corrupt = new QuickNameRegistry({ storage, deviceRoot });
  await assert.rejects(() => corrupt.load(), (error) => error.code === "STORAGE_CORRUPT");
  console.log("Quick Name registry: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
