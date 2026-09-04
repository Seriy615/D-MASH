"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const stability = fs.readFileSync(path.join(root, "js", "stability_fixes.js"), "utf8");
const publicContact = fs.readFileSync(path.join(root, "js", "public_contact_runtime.js"), "utf8");
const release = fs.readFileSync(path.join(root, "js", "release.js"), "utf8");
const css = fs.readFileSync(path.join(root, "css", "runtime_fixes.css"), "utf8");

new vm.Script(stability, { filename: "stability_fixes.js" });
new vm.Script(publicContact, { filename: "public_contact_runtime.js" });

assert.match(release, /20260905\.49/, "release 49 is visible");
assert.match(release, /stability_fixes\.js/, "stability fixes are loaded");
assert.match(css, /#settings-layer[\s\S]*overflow-y:\s*auto/, "global settings own a vertical scroll surface");
assert.match(stability, /accountBiometricLogin/, "Account biometrics are separate from Device biometrics");
assert.match(stability, /setupAccountBiometrics/, "Account settings expose biometric enrollment");
assert.match(stability, /recoverDeviceAfterConfirmedMaster[\s\S]*RECOVERY_REQUIRED/, "confirmed master failures never auto-wipe DeviceRoot");
assert.match(stability, /validRootRecord/, "biometric enrollment preserves the canonical master wrap");
assert.match(stability, /cfg_biometric_trigger/, "cold-start device biometric trigger is preloaded");
assert.match(stability, /navigator\.credentials\.get/, "biometric login invokes WebAuthn");
assert.doesNotMatch(stability, /БЕСПАРОЛЬНЫЙ ВХОД АККАУНТА/, "retired passwordless Account control is not rendered");
assert.match(publicContact, /clonePlain\(descriptor\.c\)/, "public RouteCertificate is normalized before strict transport validation");

console.log("Stability source regression: all assertions passed");
