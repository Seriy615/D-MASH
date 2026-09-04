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
  for (const label of ["ПУБЛИЧНЫЕ МАРШРУТЫ", "БЫСТРЫЕ ИМЕНА", "УЗЛЫ", "БИОМЕТРИЯ УСТРОЙСТВА"]) {
    assert.ok(gateBox.innerHTML.includes(label), `global settings lists exact label ${label}`);
  }
  assert.match(gateBox.innerHTML, /global-nodes-button/, "global settings exposes device node management before account selection");
  assert.match(gateBox.innerHTML, /id="global-public-routes-button"/, "global settings exposes device-scoped public route controls");
  assert.match(gateBox.innerHTML, /id="global-quick-names-button"/, "global settings exposes device-scoped Quick Name controls");
  assert.match(gateBox.innerHTML, /Разблокирует устройство, но не входит в аккаунт/, "global settings makes the biometric scope explicit");
  assert.match(gateBox.innerHTML, /Локальные подписи и значения, зашифрованные ключом устройства/, "Quick Names storage scope is explicit before opening the registry");
  assert.match(gateBox.innerHTML, /ui\.renderGlobalQuickNames\(\)/, "global settings opens the visible pre-account Quick Names registry");

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

  // Quick Names open as a visible pre-account screen and refresh in place after
  // mutations, rather than silently saving into an unexplained registry.
  const quickEntries = [{ id: "qn_1", name: "Дом", value: "dmash://home" }];
  const quickRegistry = {
    async list() { return quickEntries.slice(); },
    async add(entry) { quickEntries.push({ id: "qn_2", ...entry }); },
    async remove(id) { quickEntries.splice(quickEntries.findIndex(item => item.id === id), 1); }
  };
  context.Core = { getQuickNameRegistry() { return quickRegistry; }, customAlert(...args) { throw new Error(args.join(":")); } };
  context.window.Core = context.Core;
  await ui.renderGlobalQuickNames();
  assert.match(gateBox.innerHTML, /СОХРАНЯЮТСЯ ЛОКАЛЬНО/, "registry view explains local encrypted storage");
  assert.match(gateBox.innerHTML, /Дом/, "existing Quick Names are visibly listed");
  const prompts = ["Работа", "dmash:\/\/work"];
  context.window.prompt = () => prompts.shift();
  await ui.addGlobalQuickName();
  assert.equal(quickEntries.length, 2, "add writes into the visible device registry");
  assert.match(gateBox.innerHTML, /Работа/, "added Quick Name is immediately rendered");
  context.window.confirm = () => true;
  await ui.removeGlobalQuickName("qn_1");
  assert.equal(quickEntries.length, 1, "delete mutates only the visible device registry");
  assert.doesNotMatch(gateBox.innerHTML, />Дом</, "deleted Quick Name is removed from the rendered list");
  console.log("Global settings UI: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
