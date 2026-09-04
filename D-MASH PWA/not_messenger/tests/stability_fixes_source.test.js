"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const v50 = fs.readFileSync(path.join(root, "js", "acceptance_v50.js"), "utf8");
const v51 = fs.readFileSync(path.join(root, "js", "acceptance_v51.js"), "utf8");
const release = fs.readFileSync(path.join(root, "js", "release.js"), "utf8");
const css = fs.readFileSync(path.join(root, "css", "runtime_fixes.css"), "utf8");

new vm.Script(v50, { filename: "acceptance_v50.js" });
new vm.Script(v51, { filename: "acceptance_v51.js" });

assert.match(release, /20260905\.51/, "release 51 is visible");
assert.match(release, /acceptance_v50\.js/, "v50 compatibility runtime is loaded");
assert.match(release, /acceptance_v51\.js/, "v51 final acceptance runtime is loaded");
assert.doesNotMatch(release, /stability_fixes\.js/, "obsolete short-tap biometric patch is not loaded");
assert.match(css, /#settings-layer[\s\S]*overflow-y:\s*auto/, "global settings own a vertical scroll surface");

assert.match(v50, /accountBiometricLoginV50/, "Account selector has distinct biometric login");
assert.match(v50, /setupAccountBiometricsV50/, "Account settings expose biometric enrollment");
assert.match(v50, /validRootRecord/, "device biometric enrollment preserves the master wrap");
assert.match(v50, /recipientCertificate,\s*payload:\s*request/, "Public Contact deliver carries the destination certificate");

assert.match(v51, /dm_registry_secure_v1/, "Account registry moves to an encrypted DeviceRoot-scoped database");
assert.match(v51, /readAndEraseLegacy/, "legacy plaintext Account registry is migrated and erased");
assert.match(v51, /HMAC/, "secure registry keys are blind HMAC aliases, not Account IDs");
assert.match(v51, /detachedDeviceUnlockNetwork/, "Device unlock detaches Node connection work");
assert.match(v51, /__dmashAccountCryptoReady/, "heavy account crypto preloads in the background");
assert.match(v51, /calculatorEvalPaintV51/, "decoy calculator paints arithmetic results");
assert.match(v51, /ПОЛНОЕ УДАЛЕНИЕ ДАННЫХ/, "Global Settings exposes explicit recovery wipe");
assert.match(v51, /signalUnknownCredential/, "removed WebAuthn credentials are signalled stale to supported OS providers");
assert.match(v51, /backs\.slice\(1\)/, "pending Contacts modal deduplicates Back actions");

console.log("v51 browser acceptance source regression: all assertions passed");
