#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const context = {
  window: {
    crypto: webcrypto,
    DeviceRoot: {
      enrollCalls: 0,
      async enrollWebAuthnPrf() { this.enrollCalls += 1; return { enrolled: true }; },
    },
    addEventListener() {},
  },
  document: { getElementById() { return null; }, querySelector() { return null; } },
  localStorage: {
    getItem() { throw new Error("account biometric code must not read localStorage"); },
    setItem() { throw new Error("account biometric code must not write localStorage"); },
  },
  sessionStorage: {}, crypto: webcrypto, TextEncoder, TextDecoder,
  Uint8Array, Array, Map, Object, Math, Date, JSON, Promise, console,
  setTimeout, clearTimeout,
};
vm.runInNewContext(fs.readFileSync(require.resolve("../js/core_engine.js"), "utf8"), context, { filename: "core_engine.js" });
const Core = context.window.Core;
Core.customAlert = (...args) => { context.alertArgs = args; };

(async () => {
  let bootCalls = 0;
  Core.boot = async () => { bootCalls += 1; };

  // Account biometric login/setup was removed. If a compatibility method is
  // reintroduced, it must explicitly fail closed and must not boot an account.
  for (const method of ["biometricLogin", "setupBiometrics"]) {
    if (typeof Core[method] !== "undefined") {
      assert.equal(await Core[method]("alice"), false, `${method} fails closed`);
    }
  }
  assert.equal(typeof Core.biometricLogin, "undefined", "legacy account biometric login is absent");
  assert.equal(typeof Core.setupBiometrics, "undefined", "legacy account biometric setup is absent");
  assert.equal(await Core.lazyLogin("alice"), false, "account auto-login is retired");
  assert.equal(bootCalls, 0, "retired account shortcuts cannot boot an account");
  assert.equal(await Core.encryptForBio("secret"), null, "software account secret encryption is unavailable");

  for (const method of ["encryptWithHardware", "decryptWithHardware"]) {
    if (typeof Core[method] !== "undefined") {
      assert.equal(await Core[method]("secret", new Uint8Array(32)), false, `${method} fails closed`);
    }
  }
  assert.equal(typeof Core.encryptWithHardware, "undefined", "legacy account hardware wrapper is absent");
  assert.equal(typeof Core.decryptWithHardware, "undefined", "legacy account hardware unwrap is absent");

  assert.equal(await Core.setupDeviceBiometrics(), false, "device enrollment fails closed while locked");
  assert.equal(context.window.DeviceRoot.enrollCalls, 0, "locked enrollment never reaches DeviceRoot");
  console.log("Account biometric security: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
