#!/usr/bin/env node
"use strict";

// Minimal, dependency-free acceptance harness for the public Core lifecycle API.
// The browser runtime is represented by small stubs; production is loaded
// unchanged from core_engine.js through Node's VM.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const elements = new Map();
for (const id of ["workspace", "app-container", "settings-layer"]) {
  elements.set(id, {
    id,
    style: { display: "flex", opacity: "0.4" },
    replaceChildren() { this.childrenCleared = true; },
  });
}
const sessionStorage = { clearCalls: 0, clear() { this.clearCalls += 1; } };
const listeners = [];
const gateCalls = [];
const deviceRoot = { lockCalls: 0, lock() { this.lockCalls += 1; } };
const nodeManager = {
  disconnectCalls: 0,
  disconnectArgs: [],
  disconnect(...args) { this.disconnectCalls += 1; this.disconnectArgs.push(args); },
};
const ui = {
  curr: "99", hist: "stale", op: "+", mode: 9, unlockGeneration: 3,
  updateCalls: 0,
  update() { this.updateCalls += 1; },
  async show_gate() { gateCalls.push("show_gate"); },
};

const window = {
  crypto: webcrypto,
  DeviceRoot: deviceRoot,
  NodeManager: nodeManager,
  ui,
  addEventListener(type, fn) { listeners.push([type, fn]); },
};
const document = {
  getElementById(id) { return elements.get(id) || null; },
};
const context = {
  window, document, crypto: webcrypto, sessionStorage, ui,
  localStorage: { getItem() { return null; } },
  URL: { revokeObjectURL() {} },
  console,
  setInterval() { return 1; },
  clearInterval() {},
  TextEncoder,
  Uint8Array, Array, Map, Object, Math, Date, JSON, Promise,
};
vm.runInNewContext(
  fs.readFileSync(require.resolve("../js/core_engine.js"), "utf8"),
  context,
  { filename: "core_engine.js" }
);
const Core = window.Core;
assert.ok(Core, "core_engine.js exposes window.Core");
// Avoid exercising unrelated media/browser APIs: lifecycle behavior is tested
// through the public methods and their observable collaborators.
Core.killAllMedia = () => { Core.mediaWasKilled = true; };
Core.closeModal = () => { Core.modalWasClosed = true; };

(async () => {
  // Ordinary account logout: clear Account material and return to the gate,
  // while preserving the unlocked device root and active node connections.
  const master = Uint8Array.from([1, 2, 3, 4]);
  const signSecret = Uint8Array.from([5, 6, 7]);
  const boxSecret = Uint8Array.from([8, 9]);
  const blindSalt = Uint8Array.from([10, 11]);
  Core.gammaKeys = { master, sign: { secretKey: signSecret }, box: { secretKey: boxSecret } };
  Core.keys = { sign: { secretKey: signSecret }, box: { secretKey: boxSecret }, pub_hex: "account-public" };
  Core.blindSalt = blindSalt;
  Core.activeIdentity = "account@example";
  Core.activePeerId = "peer-1";
  Core.syncInterval = null;
  await Core.accountLogout();

  assert.deepEqual([...master], [0, 0, 0, 0], "logout zeroizes account master material");
  assert.deepEqual([...signSecret], [0, 0, 0], "logout zeroizes signing material");
  assert.deepEqual([...boxSecret], [0, 0], "logout zeroizes box material");
  assert.deepEqual([...blindSalt], [0, 0], "logout zeroizes blind salt");
  assert.equal(Core.activeIdentity, null, "logout clears active identity");
  assert.equal(Core.activePeerId, null, "logout clears active peer");
  assert.equal(deviceRoot.lockCalls, 0, "logout does not lock DeviceRoot");
  assert.equal(nodeManager.disconnectCalls, 0, "logout does not disconnect NodeManager");
  assert.deepEqual(gateCalls, ["show_gate"], "logout routes to UI gate");

  // Panic/session termination: destroy session state, lock the device, sever
  // transport, and restore the neutral calculator surface.
  const panicSecret = Uint8Array.from([12, 13, 14]);
  Core.gammaKeys = { master: panicSecret };
  Core.keys = { sign: { secretKey: panicSecret }, pub_hex: "session-public" };
  Core.device = { secret: Uint8Array.from([15, 16]) };
  Core.blindSalt = Uint8Array.from([17, 18]);
  Core.activeIdentity = "session@example";
  elements.get("workspace").style.display = "flex";
  elements.get("app-container").style.display = "none";
  elements.get("app-container").style.opacity = "0";
  Core.terminateSession();

  assert.deepEqual([...panicSecret], [0, 0, 0], "termination zeroizes session material");
  assert.equal(deviceRoot.lockCalls, 1, "termination locks DeviceRoot");
  assert.equal(nodeManager.disconnectCalls, 1, "termination disconnects NodeManager");
  assert.deepEqual(nodeManager.disconnectArgs[0], [false], "termination uses non-reloading disconnect");
  assert.equal(Core.activeIdentity, null, "termination clears active identity");
  assert.equal(elements.get("workspace").style.display, "none", "termination hides workspace");
  assert.equal(elements.get("app-container").style.display, "flex", "termination restores calculator");
  assert.equal(elements.get("app-container").style.opacity, "1", "termination restores calculator opacity");
  assert.equal(ui.curr, "0", "termination neutralizes calculator input");
  assert.equal(ui.hist, "", "termination clears calculator history");
  assert.equal(ui.op, null, "termination clears calculator operator");
  assert.equal(ui.mode, 0, "termination resets calculator mode");

  // A successful device unlock may leave asynchronous Core work between the
  // calculator PIN entry and account selection.  Reset again immediately
  // after it resolves so that no stale calculator state reaches the selector.
  const calculatorElements = new Map();
  const calculatorContext = {
    window: {
      addEventListener() {},
      NodeManager: null,
    },
    document: { getElementById(id) { return calculatorElements.get(id) || null; } },
    localStorage: { getItem(key) { return key === "sys_configured" ? "true" : "master"; } },
    sessionStorage: {},
    crypto: webcrypto,
    TextEncoder,
    Core: {
      async unlockDevice() {
        // Model state altered by successful asynchronous unlocking; the UI
        // must clear it before opening its account selector.
        calculatorContext.__ui.curr = "residual";
        calculatorContext.__ui.hist = "residual history";
        calculatorContext.__ui.op = "+";
      },
    },
    console,
    Promise,
    setTimeout,
    clearTimeout,
  };
  calculatorContext.window.crypto = webcrypto;
  vm.runInNewContext(
    `${fs.readFileSync(require.resolve("../js/ui_logic.js"), "utf8")}; globalThis.__ui = ui; globalThis.__sys = sys;`,
    calculatorContext,
    { filename: "ui_logic.js" }
  );
  calculatorContext.__sys.fastHash = async () => "master";
  calculatorContext.__sys.loadAllLibs = async () => true;
  let selectorState;
  calculatorContext.__ui.show_gate = async function() {
    selectorState = { curr: this.curr, hist: this.hist, op: this.op };
  };
  calculatorContext.__ui.curr = "1234";
  calculatorContext.__ui.hist = "123 +";
  calculatorContext.__ui.op = "+";
  await calculatorContext.__ui.eval();

  assert.deepEqual(selectorState, { curr: "0", hist: "", op: null }, "unlock neutralizes calculator before account selection");

  console.log("Core lifecycle acceptance: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
