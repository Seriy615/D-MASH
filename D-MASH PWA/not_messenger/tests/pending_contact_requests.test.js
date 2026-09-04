#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
if (!global.crypto) Object.defineProperty(global, "crypto", { value: webcrypto, configurable: true });
global.btoa = (value) => Buffer.from(value, "binary").toString("base64");
global.atob = (value) => Buffer.from(value, "base64").toString("binary");
const { PendingContactRequestStore, PendingContactRequestError, MATERIAL_NAME, STORAGE_KEY, STATUSES } = require("../js/pending_contact_requests.js");

class MemoryStorage {
  constructor() { this.values = new Map(); }
  getItem(key) { return this.values.get(key) || null; }
  setItem(key, value) { this.values.set(key, String(value)); }
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
  let clock = 100, sequence = 0;
  const store = new PendingContactRequestStore({ storage, deviceRoot, now: () => ++clock, idFactory: () => `request_${++sequence}` });
  assert.deepEqual(await store.list(), []);
  const pending = await store.add({
    displayName: "  Ada   Lovelace ", intro: " Hello from Ada ", replyRoute: "reply-route", receivedRoute: "received-route",
    bootstrap: { protocol: "contact-v1", endpoint: "https://example.test/bootstrap", options: { retry: true } }, receivedAt: 7
  });
  assert.deepEqual(pending, {
    id: "request_1", displayName: "Ada Lovelace", intro: "Hello from Ada", replyRoute: "reply-route", receivedRoute: "received-route",
    bootstrap: { protocol: "contact-v1", endpoint: "https://example.test/bootstrap", options: { retry: true } }, status: STATUSES.PENDING, receivedAt: 7, updatedAt: 101
  });
  assert.deepEqual(await store.list(), [pending]);
  assert.deepEqual(await store.read(pending.id), pending);
  assert.equal(await store.read("missing"), null);
  const encrypted = storage.getItem(STORAGE_KEY);
  for (const secret of ["Ada Lovelace", "Hello from Ada", "reply-route", "received-route", "contact-v1"]) assert.equal(encrypted.includes(secret), false, "request fields must not persist in plaintext");
  assert.deepEqual(deviceRoot.calls, [MATERIAL_NAME], "writes derive DeviceRoot-bound material");

  const accepted = await store.accept(pending.id);
  assert.equal(accepted.status, STATUSES.ACCEPTED);
  await assert.rejects(() => store.reject(pending.id), error => error instanceof PendingContactRequestError && error.code === "ALREADY_RESOLVED");
  const rejected = await store.add({ displayName: "Bob", intro: null, replyRoute: "reply-2", receivedRoute: "received-2", bootstrap: { version: 1 } });
  assert.equal((await store.reject(rejected.id)).status, STATUSES.REJECTED);
  await assert.rejects(() => store.accept("missing"), error => error.code === "NOT_FOUND");
  await assert.rejects(() => store.add({ displayName: "Mallory", replyRoute: "r", receivedRoute: "in", bootstrap: { accountId: "forbidden" } }), error => error.code === "ACCOUNT_IDENTITY_FORBIDDEN");

  const restarted = new PendingContactRequestStore({ storage, deviceRoot });
  assert.equal((await restarted.read(pending.id)).status, STATUSES.ACCEPTED, "encrypted data survives restart");
  storage.setItem(STORAGE_KEY, JSON.stringify({ version: 1, iv: "AAAAAAAAAAAAAAAA", ciphertext: "AAAA" }));
  await assert.rejects(() => new PendingContactRequestStore({ storage, deviceRoot }).load(), error => error.code === "STORAGE_CORRUPT");
  console.log("Pending contact request store: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
