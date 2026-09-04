#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
if (!global.crypto) Object.defineProperty(global, "crypto", { value: webcrypto, configurable: true });
global.btoa = (value) => Buffer.from(value, "binary").toString("base64");
global.atob = (value) => Buffer.from(value, "base64").toString("binary");
global.nacl = require("../js/vendor/nacl-fast.min.js");

class MemoryStorage {
  constructor() { this.data = new Map(); }
  getItem(key) { return this.data.get(key) || null; }
  setItem(key, value) { this.data.set(key, String(value)); }
}

// This DeviceRoot-shaped test double stores every material as AES-GCM ciphertext
// and exposes its backing store so the test can prove route secrets do not land
// in the public local index.
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
const { DeviceRoutes, RouteError } = require("../js/device_routes.js");

(async () => {
  const storage = new MemoryStorage();
  DeviceRoutes.setStorageForTests(storage);

  const first = await DeviceRoutes.issue({ type: "direct-message", allowedAccounts: ["bob", "alice", "bob"], issuedAt: 100 });
  assert.equal(first.routeId, first.certificate.signingPublicKey, "RouteID is exactly the signing public key");
  assert.equal(first.routeId.length, 43, "RouteID encodes a 32-byte Ed25519 public key");
  assert.equal(DeviceRoutes.verifyCertificate(first.certificate), true, "canonical RouteCertificateV1 self-signature verifies");
  assert.deepEqual(Object.keys(first).sort(), ["certificate", "routeId"], "public API emits no local policy");
  assert.equal(JSON.stringify(first.certificate).includes("allowedAccounts"), false, "certificate excludes local allowedAccounts");
  assert.equal(JSON.stringify(first.certificate).includes("direct-message"), false, "certificate excludes local type");

  const indexAfterFirst = storage.getItem("dmash/routes/v1/index");
  assert.equal(/signingSecretKey|boxSecretKey/.test(indexAfterFirst), false, "local route index contains no private material");
  assert.equal(global.DeviceRoot.records.size, 1, "private route material is passed to DeviceRoot deviceMaterial");
  for (const record of global.DeviceRoot.records.values()) {
    assert.equal(Buffer.from(record.ciphertext).includes(Buffer.from(first.routeId)), false, "encrypted-at-rest route material is not plaintext public-index data");
  }
  const resolvedFirst = DeviceRoutes.resolve(first.routeId);
  assert.deepEqual([...resolvedFirst.allowedAccounts], ["alice", "bob"], "policy remains local and is canonicalized");
  assert.equal(resolvedFirst.type, "direct-message");

  const second = await DeviceRoutes.issue({ type: "relay", allowedAccounts: ["carol"], issuedAt: 101 });
  const third = await DeviceRoutes.issue({ type: "relay", allowedAccounts: [], issuedAt: 102 });
  assert.equal(DeviceRoutes.current().routeId, third.routeId, "latest route is current");
  assert.equal(DeviceRoutes.resolve(second.routeId).routeId, second.routeId, "only immediate predecessor is accepted as fallback");
  assert.equal(DeviceRoutes.resolve(first.routeId), null, "reissue fallback is bounded to current plus previous");
  const index = JSON.parse(storage.getItem("dmash/routes/v1/index"));
  assert.ok(index.current && index.previous);
  assert.equal(Object.keys(index).filter((key) => /^previous/.test(key)).length, 1, "index has only one previous slot");

  const tampered = structuredClone(third.certificate); tampered.issuedAt++;
  assert.equal(DeviceRoutes.verifyCertificate(tampered), false, "certificate transcript is signature-bound");
  await assert.rejects(() => DeviceRoutes.issue({ type: "", allowedAccounts: [] }), (error) => error instanceof RouteError && error.code === "INVALID_TYPE");

  console.log("Device routes acceptance: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
