"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const v50 = fs.readFileSync(path.join(root, "js", "acceptance_v50.js"), "utf8");
const release = fs.readFileSync(path.join(root, "js", "release.js"), "utf8");
const css = fs.readFileSync(path.join(root, "css", "runtime_fixes.css"), "utf8");

new vm.Script(v50, { filename: "acceptance_v50.js" });

assert.match(release, /20260905\.50/, "release 50 is visible");
assert.match(release, /acceptance_v50\.js/, "v50 acceptance runtime is loaded");
assert.doesNotMatch(release, /stability_fixes\.js/, "obsolete short-tap biometric patch is no longer loaded");
assert.match(css, /#settings-layer[\s\S]*overflow-y:\s*auto/, "global settings own a vertical scroll surface");
assert.match(v50, /accountBiometricLoginV50/, "Account selector has distinct biometric login");
assert.match(v50, /setupAccountBiometricsV50/, "Account settings expose biometric enrollment");
assert.match(v50, /validRootRecord/, "device biometric enrollment preserves the master wrap");
assert.match(v50, /recoverDeviceAfterConfirmedMaster[\s\S]*RECOVERY_REQUIRED/, "confirmed master failures never auto-wipe DeviceRoot");
assert.match(v50, /recipientCertificate,\s*payload:\s*request/, "Public Contact deliver carries the destination certificate");
assert.match(v50, /Quick Names are a chooser/, "Public-contact flow exposes Quick Names as an explicit chooser");
assert.match(v50, /Connected \$\{connected\} Nodes/, "connected-node metric is rendered");
assert.match(v50, /Incoming Contacts: \$\{incoming\}/, "incoming-contact metric is rendered");
assert.match(v50, /scheduleReload\(40\)/, "completed flip-lock/session termination reloads the page");
assert.match(v50, /scheduleReload\(220\)/, "completed device biometric/master rewrap flows reload the page");
assert.doesNotMatch(v50, /addEventListener\("click"[\s\S]*unlockDeviceWithBiometrics/, "v50 does not reintroduce short-tap device biometric login");

console.log("v50 browser acceptance source regression: all assertions passed");
