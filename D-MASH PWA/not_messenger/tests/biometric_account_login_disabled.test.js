#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const root = require.resolve("../js/core_engine.js");
const source = fs.readFileSync(root, "utf8");
const uiSource = fs.readFileSync(require.resolve("../js/ui_logic.js"), "utf8");

// Account records must not regain the former biometric key/credential storage
// fields. DeviceRoot's installation-level WebAuthn data is intentionally out of
// scope: it is not an account auto-login path.
for (const token of ["bio_key", "cred_id"]) {
  assert.equal(source.includes(token), false, `Core has no legacy account storage field: ${token}`);
}
assert.equal(uiSource.includes("Core.biometricLogin("), false, "UI never invokes retired biometric account login");

const alerts = [];
const context = {
  window: { crypto: webcrypto, addEventListener() {} }, crypto: webcrypto,
  document: { getElementById() { return null; } }, localStorage: { getItem() { return null; } },
  sessionStorage: {}, URL: { revokeObjectURL() {} }, console, setInterval() { return 1; }, clearInterval() {},
  TextEncoder, Uint8Array, Array, Map, Object, Math, Date, JSON, Promise,
};
vm.runInNewContext(source, context, { filename: "core_engine.js" });
const Core = context.window.Core;
Core.customAlert = (...args) => alerts.push(args);

(async () => {
  let bootCalls = 0;
  Core.boot = async () => { bootCalls += 1; };

  // Removed methods are preferred; retained compatibility methods must never
  // auto-login an account or create account biometric credentials.
  for (const method of ["biometricLogin", "setupBiometrics"]) {
    if (typeof Core[method] !== "undefined") {
      assert.equal(await Core[method]("alice"), false, `${method} fails closed`);
    }
    assert.equal(typeof Core[method], "undefined", `legacy account ${method} is absent`);
  }
  assert.equal(await Core.lazyLogin("alice"), false, "legacy account auto-login fails closed");
  assert.equal(bootCalls, 0, "no account biometric or auto-login path boots an account");

  context.window.DeviceRoot = { state: null, async enrollWebAuthnPrf() { throw new Error("must not enroll while locked"); } };
  assert.equal(await Core.setupDeviceBiometrics(), false, "device enrollment fails closed while locked");
  const state = {}; let enrolled = 0;
  context.window.DeviceRoot = { state, async enrollWebAuthnPrf() { enrolled += 1; } };
  Core.deviceState = state;
  assert.equal(await Core.setupDeviceBiometrics(), true, "unlocked enrollment is DeviceRoot-only");
  assert.equal(enrolled, 1, "biometric trigger calls only DeviceRoot PRF enrollment");
  assert.equal(alerts.length, 2, "device enrollment reports both outcomes");
  console.log("Biometric account-login remediation: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
