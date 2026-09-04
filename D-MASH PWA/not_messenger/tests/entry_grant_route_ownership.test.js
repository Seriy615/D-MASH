#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
if (!global.crypto) Object.defineProperty(global, "crypto", { value: webcrypto, configurable: true });
global.btoa = (value) => Buffer.from(value, "binary").toString("base64");
global.atob = (value) => Buffer.from(value, "base64").toString("binary");
global.nacl = require("../js/vendor/nacl-fast.min.js");
global.CustomEvent = class CustomEvent { constructor(type, init) { this.type = type; this.detail = init?.detail; } };
global.dispatchEvent = () => {};

class MemoryStorage {
  constructor() { this.data = new Map(); }
  getItem(key) { return this.data.get(key) || null; }
  setItem(key, value) { this.data.set(key, String(value)); }
}

class EncryptedDeviceMaterial {
  constructor() { this.records = new Map(); this.keyBytes = crypto.getRandomValues(new Uint8Array(32)); }
  async deviceMaterial(name, create) {
    const key = await crypto.subtle.importKey("raw", this.keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
    const present = this.records.get(name);
    if (present) {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: present.iv, additionalData: new TextEncoder().encode(name) }, key, present.ciphertext);
      return new Uint8Array(plain);
    }
    const plain = new Uint8Array(await create());
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(name) }, key, plain);
    this.records.set(name, { iv, ciphertext: new Uint8Array(ciphertext) });
    return plain;
  }
}

global.DeviceRoot = new EncryptedDeviceMaterial();
const { DeviceRoutes } = require("../js/device_routes.js");

(async () => {
  const storage = new MemoryStorage();
  DeviceRoutes.setStorageForTests(storage);

  const route = await DeviceRoutes.issue({ type: "public-contact", allowedAccounts: [], issuedAt: 100 });
  const nodeId = "11".repeat(32);
  const grant = await DeviceRoutes.issueEntryGrant(route.routeId, nodeId, {
    generation: 3,
    createdAt: 1000,
    expiresAt: 2000,
  });

  assert.equal(grant.v, "EntryGrantV1");
  assert.equal(grant.route_id, route.routeId, "RouteID stays the Route signing public key");
  assert.equal(grant.route_public_key, route.routeId, "new grants bind compatibility key to RouteSignPublic");
  assert.equal(grant.node_id, nodeId, "Entry Node is a signed target, not the signer");
  assert.equal(DeviceRoutes.verifyEntryGrant(grant, nodeId, 1500), true, "Route-owned grant self-verifies");
  assert.equal(DeviceRoutes.verifyEntryGrant(grant, "22".repeat(32), 1500), false, "grant is NodeID-bound");
  assert.equal(DeviceRoutes.verifyEntryGrant(grant, nodeId, 2000), false, "grant expires exactly at expires_at");

  const changedNode = { ...grant, node_id: "22".repeat(32) };
  const changedGeneration = { ...grant, generation: 4 };
  const changedCreated = { ...grant, created_at: 1001 };
  const changedExpiry = { ...grant, expires_at: 2001 };
  for (const tampered of [changedNode, changedGeneration, changedCreated, changedExpiry]) {
    assert.equal(DeviceRoutes.verifyEntryGrant(tampered, tampered.node_id, 1500), false, "signed EntryGrant metadata is tamper-evident");
  }

  const serialized = JSON.stringify(grant);
  for (const forbidden of ["AccountID", "account_id", "username", "display_name", "DeviceRoot"]) {
    assert.equal(serialized.includes(forbidden), false, `wire grant excludes ${forbidden}`);
  }

  const index = storage.getItem("dmash/routes/v1/index");
  assert.equal(/signingSecretKey|boxSecretKey/.test(index), false, "EntryGrant issuance does not expose route private keys in public storage");

  console.log("Route-owned EntryGrant JS acceptance: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
