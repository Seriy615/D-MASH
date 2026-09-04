"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const source = fs.readFileSync(path.join(__dirname, "../js/rescue_patch.js"), "utf8");

// Syntax guard: this intentionally does not execute the browser-only patch.
assert.doesNotThrow(() => new vm.Script(source, { filename: "rescue_patch.js" }));

for (const expected of [
  "ПОЧИНИТЬ ПРИЛОЖЕНИЕ",
  "ЗАПРОСИТЬ УЗЕЛ",
  "ПУБЛИЧНЫЕ МАРШРУТЫ",
  "dmash-calculator-refresh",
  "dmash-pending-contact-row",
  "this.deviceState = deviceState",
  "storage.masterKey = null",
  "DeviceRoot НЕ ИЗМЕНЁН",
  "Core.showMyQR('public')",
  "ПРЕДЫДУЩИЙ",
  "СМЕНИТЬ КЛЮЧ МАРШРУТА"
]) {
  assert.ok(source.includes(expected), `rescue patch keeps invariant marker: ${expected}`);
}

assert.ok(source.includes("navigator.serviceWorker.getRegistrations"), "repair unregisters service workers");
assert.ok(source.includes("global.caches.keys"), "repair clears CacheStorage");
assert.ok(!source.includes("indexedDB.deleteDatabase"), "repair must not erase IndexedDB");
assert.ok(!source.includes("localStorage.clear()"), "repair must not erase LocalStorage policy/state");
assert.ok(!/accountLogoutRescue[\s\S]*sessionStorage\.clear\(\)/.test(source), "account logout must not clear device session routing state");

console.log("rescue_patch_source.test.js: PASS");
