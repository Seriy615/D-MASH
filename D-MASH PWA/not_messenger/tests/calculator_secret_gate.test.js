#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const values = new Map();
const elements = {
  current: { innerText: "" },
  history: { innerText: "" },
  keypad: { dataset: {}, addEventListener() {} },
};
const context = {
  window: { crypto: webcrypto, addEventListener() {}, NodeManager: null },
  crypto: webcrypto,
  TextEncoder, Uint8Array, Array, Object, Number, RegExp, Promise, Math, Date, JSON,
  setTimeout, clearTimeout, console,
  localStorage: { getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, String(value)), clear: () => values.clear() },
  sessionStorage: { clear() {} },
  document: {
    getElementById(id) { return elements[id] || null; },
    querySelector() { return null; },
    body: { style: {} },
  },
};
context.window.window = context.window;
vm.runInNewContext(fs.readFileSync(require.resolve("../js/ui_logic.js"), "utf8"), context, { filename: "ui_logic.js" });
const ui = vm.runInNewContext("ui", context);
const sys = vm.runInNewContext("sys", context);

(async () => {
  // Exact boundary is accepted; the next character is rejected rather than
  // letting an overlong value reach the secret/KDF path.
  ui.mode = 0; ui.resetCalculator();
  for (let i = 0; i < ui.maxInputLength; i++) ui.num("7");
  assert.equal(ui.curr.length, ui.maxInputLength, "calculator accepts its exact input limit");
  ui.num("8");
  assert.equal(ui.curr.length, ui.maxInputLength, "calculator rejects input beyond its limit");
  ui.num(".");
  assert.equal(ui.curr.length, ui.maxInputLength, "decimal cannot bypass the input limit");

  // A calculator expression creates the master secret from its evaluated
  // result, not the visible right operand or stale history.
  values.clear(); ui.mode = 1; ui.resetCalculator();
  for (const digit of "123") ui.num(digit);
  ui.cmd("+");
  for (const digit of "4567") ui.num(digit);
  await ui.eval();
  assert.equal(ui.mode, 2, "valid evaluated expression advances master-secret setup");
  assert.equal(values.get("sys_m"), await sys.fastHash("4690"), "master verifier hashes evaluated expression");
  assert.notEqual(values.get("sys_m"), await sys.fastHash("4567"), "right operand is not used as secret");
  assert.equal(ui.op, null, "expression operator is cleared after secret evaluation");
  assert.equal(ui.leftOperand, null, "expression operand is cleared after secret evaluation");

  // An expression-derived master secret unlocks DeviceRoot exactly once and
  // never reuses prior expression state.
  values.set("sys_configured", "true");
  ui.mode = 0; ui.resetCalculator();
  let unlockPin = null;
  context.Core = { async unlockDevice(pin) { unlockPin = pin; } };
  sys.loadAllLibs = async () => true;
  ui.show_gate = async () => {};
  for (const digit of "1200") ui.num(digit);
  ui.cmd("+");
  for (const digit of "3490") ui.num(digit);
  await ui.eval();
  assert.equal(unlockPin, "4690", "DeviceRoot receives evaluated master secret");
  assert.equal(ui.curr, "0", "unlock clears calculator secret from display state");
  assert.equal(ui.hist, "", "unlock clears calculator history state");
  assert.equal(ui.op, null, "unlock leaves no pending operator");
  assert.equal(ui.leftOperand, null, "unlock leaves no pending left operand");

  // Reconfiguration rewraps the existing device before changing sys_m, so a
  // user cannot be locked out by a calculator-master-secret change.
  let rewrap = null;
  context.Core = { async changeDeviceMasterSecret(current, next) { rewrap = [current, next]; } };
  values.set("sys_m", await sys.fastHash("4690"));
  ui.mode = 3; ui.resetCalculator();
  for (const digit of "4690") ui.num(digit); await ui.eval();
  for (const digit of "2345") ui.num(digit); await ui.eval();
  for (const digit of "6789") ui.num(digit); await ui.eval();
  assert.deepEqual(rewrap, ["4690", "2345"], "device root is rewrapped from the old to new evaluated master secret");
  assert.equal(values.get("sys_m"), await sys.fastHash("2345"), "calculator verifier changes only after successful device rewrap");

  // A rewrap failure must retain the old verifier and report an error rather
  // than stranding the existing device identity.
  context.Core = { async changeDeviceMasterSecret() { throw new Error("rewrap failed"); } };
  values.set("sys_m", await sys.fastHash("2345"));
  ui.mode = 3; ui.resetCalculator();
  for (const digit of "2345") ui.num(digit); await ui.eval();
  for (const digit of "3456") ui.num(digit); await ui.eval();
  for (const digit of "7890") ui.num(digit); await ui.eval();
  assert.equal(values.get("sys_m"), await sys.fastHash("2345"), "failed device rewrap retains the old calculator verifier");
  assert.match(ui.hist, /ОШИБКА УСТРОЙСТВА/, "failed device rewrap is surfaced to the user");

  // Invalid expression results fail validation and cannot replace a verifier.
  const priorMaster = values.get("sys_m");
  ui.mode = 4; ui.resetCalculator(); ui.num("1"); ui.cmd("+"); ui.num("2");
  await ui.eval();
  assert.equal(ui.mode, 4, "too-short evaluated secret stays in configuration mode");
  assert.equal(values.get("sys_m"), priorMaster, "invalid expression never changes stored verifier");
  console.log("Calculator secret gate: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
