#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const gateBox = { innerHTML: "" };
const calculator = { style: {}, dataset: {}, addEventListener() {} };
const settingsLayer = { style: { setProperty() {} } };
const local = new Map();
const document = {
  querySelector(selector) { return selector === ".gate-container" ? gateBox : null; },
  getElementById(id) { return id === "app-container" ? calculator : (id === "settings-layer" ? settingsLayer : null); }
};
const context = {
  window: { addEventListener() {}, NodeManager: null }, document, localStorage: { getItem(key) { return local.get(key) || null; }, setItem(key, value) { local.set(key, value); } },
  console, Promise, setTimeout() {}, requestAnimationFrame(callback) { callback(); }, TextEncoder
};

vm.runInNewContext(fs.readFileSync(require.resolve("../js/ui_logic.js"), "utf8"), context, { filename: "ui_logic.js" });
const ui = vm.runInContext("ui", context);

(async () => {
  await ui.renderAccountSelector([{ id: "alice", bio: false, lazy: false }]);
  assert.match(gateBox.innerHTML, /id="global-settings-button"/, "selector exposes the global settings gear");
  assert.match(gateBox.innerHTML, /aria-label="ГЛОБАЛЬНЫЕ НАСТРОЙКИ"/, "gear has an accessible global settings label");

  ui.renderGlobalSettings();
  for (const label of ["NODES", "DEVICE BIOMETRIC AUTH"]) {
    assert.ok(gateBox.innerHTML.includes(label), `global settings lists exact label ${label}`);
  }
  assert.match(gateBox.innerHTML, /global-nodes-button/, "global settings exposes device node management before account selection");
  assert.match(gateBox.innerHTML, /id="global-public-routes-button"/, "global settings exposes device-scoped public route controls");
  assert.match(gateBox.innerHTML, /id="global-quick-names-button"/, "global settings exposes device-scoped Quick Name controls");
  assert.match(gateBox.innerHTML, /ui\.beginBiometricTriggerSetup\(\)/, "global settings sends biometric configuration to the calculator setup flow");

  // Device biometric enrollment is a device-level setting, available only
  // after the DeviceRoot has been unlocked. Account selection alone must not
  // authorize it.
  const deviceState = {};
  context.window.DeviceRoot = { state: deviceState };
  context.Core = { deviceState, async setupDeviceBiometrics() { enrollment += 1; return true; } };
  let enrollment = 0;
  assert.equal(ui.beginBiometricTriggerSetup(), true, "an unlocked device may configure its biometric trigger");
  assert.equal(ui.mode, 6, "biometric setup uses a dedicated calculator mode");
  assert.match(ui.hist, /УДЕРЖИВАЙТЕ/, "setup asks the user to choose a trigger with a hold");
  await ui.handleBiometricHold("3");
  assert.equal(enrollment, 1, "only a deliberate hold starts device biometric enrollment");
  assert.equal(local.get("cfg_biometric_trigger"), "3", "selected calculator token is stored as the trigger");
  assert.equal(ui.mode, 0, "setup returns to ordinary calculator mode");

  let unlocks = 0; let gates = 0;
  context.Core = { async unlockDeviceWithBiometrics() { unlocks += 1; return true; } };
  ui.show_gate = async () => { gates += 1; };
  await ui.handleBiometricHold("4");
  assert.equal(unlocks, 0, "holding an unconfigured key does not invoke WebAuthn");
  await ui.handleBiometricHold("3");
  assert.equal(unlocks, 1, "only the configured key invokes device-only biometric unlock");
  assert.equal(gates, 1, "successful biometric unlock opens account selection");
  console.log("Global settings UI: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
