#!/usr/bin/env node
"use strict";

// Dependency-free UI acceptance test: production Core is loaded unchanged and
// exercised through mocked DOM, prompts, DeviceRoot, and QuickNameRegistry.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const modal = { style: {}, innerHTML: "" };
const state = { unlocked: true };
const calls = { constructed: 0, add: [], remove: [] };
class QuickNameRegistry {
  constructor(options) { this.options = options; calls.constructed += 1; }
  async list() { return [{ id: "qn_1", name: "Home <Alice>", value: "dmash://alice" }]; }
  async add(entry) { calls.add.push(entry); return entry; }
  async remove(id) { calls.remove.push(id); }
}
const window = {
  crypto: webcrypto,
  DeviceRoot: { state },
  QuickNameRegistry,
  addEventListener() {},
};
const document = { getElementById(id) { return id === "sys-modal" ? modal : null; } };
const context = {
  window, document, crypto: webcrypto, console, TextEncoder,
  Uint8Array, Array, Map, Object, Math, Date, JSON, Promise,
  localStorage: { getItem() { return null; } },
  URL: { revokeObjectURL() {} }, setInterval() { return 1; }, clearInterval() {},
};
vm.runInNewContext(fs.readFileSync(require.resolve("../js/core_engine.js"), "utf8"), context, { filename: "core_engine.js" });
const Core = window.Core;
Core.deviceState = state;
Core.customAlert = (title, message) => { throw new Error(`${title}: ${message}`); };

(async () => {
  await Core.openQuickNames();
  assert.equal(calls.constructed, 1, "registry is constructed after DeviceRoot unlock");
  assert.equal(calls.constructed && Core.quickNameRegistry.options.deviceRoot, window.DeviceRoot, "registry uses DeviceRoot, not account state");
  assert.match(modal.innerHTML, /БЫСТРЫЕ ИМЕНА/, "Quick Names are rendered in a settings modal");
  assert.match(modal.innerHTML, /Home &lt;Alice&gt;/, "persisted names are HTML-escaped");
  assert.match(modal.innerHTML, /ДОБАВИТЬ БЫСТРОЕ ИМЯ/, "add action is rendered");
  assert.match(modal.innerHTML, /УДАЛИТЬ/, "remove action is rendered");

  const responses = ["Work", "dmash://work"];
  Core.customPrompt = (_title, _message, callback) => callback(responses.shift());
  Core.addQuickNameFlow();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.add.length, 1, "add flow writes one registry entry");
  assert.equal(calls.add[0].name, "Work", "add flow preserves the name");
  assert.equal(calls.add[0].value, "dmash://work", "add flow preserves the value");

  Core.customPrompt = (_title, _message, callback) => callback("УДАЛИТЬ");
  Core.removeQuickName("qn_1");
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls.remove, ["qn_1"], "remove flow writes through registry");

  Core.quickNameRegistry = null;
  Core.deviceState = null;
  assert.throws(() => Core.getQuickNameRegistry(), /РАЗБЛОКИРУЙТЕ УСТРОЙСТВО/, "registry is unavailable before DeviceRoot unlock");
  console.log("Quick Name UI acceptance: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
