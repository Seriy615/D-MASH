#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const alerts = [];
let prfCalls = 0;
let bootstrapCalls = 0;
let bootCalls = 0;
let pinFallbackCalls = 0;
const previousState = { root: Uint8Array.of(9), identity: { deviceId: "old" } };
const unlockedState = {
  root: Uint8Array.of(1),
  identity: { deviceId: "d1_biometric", fingerprints: { signing: "s", agreement: "a" }, signing: { publicKey: "sign" }, agreement: { publicKey: "agree" } }
};
const deviceRoot = {
  state: previousState,
  async unlockWithWebAuthnPrf() { prfCalls += 1; return unlockedState; },
  async bootstrap() { bootstrapCalls += 1; throw new Error("PIN bootstrap must not run"); },
  async unlock() { pinFallbackCalls += 1; throw new Error("PIN fallback must not run"); }
};
const nodeManager = { calls: 0, async onDeviceUnlocked() { this.calls += 1; } };
const context = {
  window: { crypto: webcrypto, DeviceRoot: deviceRoot, NodeManager: nodeManager, addEventListener() {} },
  crypto: webcrypto, document: { getElementById() { return null; }, querySelector() { return null; } },
  localStorage: { getItem() { return null; } }, sessionStorage: {}, URL: { revokeObjectURL() {} },
  console, setInterval() { return 1; }, clearInterval() {}, TextEncoder, Uint8Array, Array, Map, Object, Math, Date, JSON, Promise
};
vm.runInNewContext(fs.readFileSync(require.resolve("../js/core_engine.js"), "utf8"), context, { filename: "core_engine.js" });
const Core = context.window.Core;
Core.customAlert = (...args) => alerts.push(args);
Core.boot = async () => { bootCalls += 1; throw new Error("account boot must not run"); };

(async () => {
  assert.equal(await Core.unlockDeviceWithBiometrics(), true, "successful PRF unlock succeeds");
  assert.equal(prfCalls, 1, "uses DeviceRoot PRF exactly once");
  assert.equal(Core.deviceState, unlockedState, "commits device state only after successful PRF unlock");
  assert.equal(Core.device.id, "d1_biometric", "publishes only device identity");
  assert.equal(nodeManager.calls, 1, "notifies device-scoped node lifecycle");
  assert.equal(bootstrapCalls, 0, "never bootstraps from biometric unlock");
  assert.equal(pinFallbackCalls, 0, "never falls back to PIN unlock");
  assert.equal(bootCalls, 0, "never boots an account");

  const committedState = Core.deviceState;
  deviceRoot.unlockWithWebAuthnPrf = async () => { prfCalls += 1; throw new Error("PRF rejected"); };
  assert.equal(await Core.unlockDeviceWithBiometrics(), false, "PRF failure fails closed");
  assert.equal(Core.deviceState, committedState, "PRF failure does not change device state");
  assert.equal(bootstrapCalls, 0, "failure never bootstraps");
  assert.equal(pinFallbackCalls, 0, "failure never uses PIN");
  assert.equal(bootCalls, 0, "failure never enters account boot");

  delete deviceRoot.unlockWithWebAuthnPrf;
  assert.equal(await Core.unlockDeviceWithBiometrics(), false, "unavailable PRF fails explicitly");
  assert.equal(Core.deviceState, committedState, "unavailable PRF does not change device state");
  assert.equal(bootstrapCalls, 0, "unavailable PRF never bootstraps");
  assert.equal(pinFallbackCalls, 0, "unavailable PRF never uses PIN");
  assert.equal(bootCalls, 0, "unavailable PRF never boots an account");
  assert.equal(alerts.length, 2, "failure and unavailable outcomes are explicitly reported");
  console.log("Device biometric unlock integration: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
