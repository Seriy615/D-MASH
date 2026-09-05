"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const v50 = fs.readFileSync(path.join(root, "js", "acceptance_v50.js"), "utf8");
const v51 = fs.readFileSync(path.join(root, "js", "acceptance_v51.js"), "utf8");
const v52 = fs.readFileSync(path.join(root, "js", "acceptance_v52.js"), "utf8");
const v53 = fs.readFileSync(path.join(root, "js", "acceptance_v53.js"), "utf8");
const release = fs.readFileSync(path.join(root, "js", "release.js"), "utf8");
const css = fs.readFileSync(path.join(root, "css", "runtime_fixes.css"), "utf8");

new vm.Script(v50, { filename: "acceptance_v50.js" });
new vm.Script(v51, { filename: "acceptance_v51.js" });
new vm.Script(v52, { filename: "acceptance_v52.js" });
new vm.Script(v53, { filename: "acceptance_v53.js" });

assert.match(release, /20260905\.53/, "release 53 is visible");
assert.match(release, /acceptance_v50\.js/, "v50 compatibility runtime is loaded");
assert.match(release, /acceptance_v51\.js/, "v51 compatibility runtime is loaded");
assert.match(release, /acceptance_v52\.js/, "v52 secure-registry runtime is loaded");
assert.match(release, /acceptance_v53\.js/, "v53 emergency-wipe runtime is loaded");
assert.doesNotMatch(release, /stability_fixes\.js/, "obsolete short-tap biometric patch is not loaded");
assert.match(css, /#settings-layer[\s\S]*overflow-y:\s*auto/, "global settings own a vertical scroll surface");

assert.match(v50, /accountBiometricLoginV50/, "Account selector has distinct biometric login");
assert.match(v50, /setupAccountBiometricsV50/, "Account settings expose biometric enrollment");
assert.match(v50, /validRootRecord/, "device biometric enrollment preserves the master wrap");
assert.match(v50, /recipientCertificate,\s*payload:\s*request/, "Public Contact deliver carries the destination certificate");

assert.match(v51, /detachedDeviceUnlockNetwork/, "Device unlock detaches Node connection work");
assert.match(v51, /__dmashAccountCryptoReady/, "heavy account crypto preloads in the background");
assert.match(v51, /calculatorEvalPaintV51/, "decoy calculator paints arithmetic results");
assert.match(v51, /ПОЛНОЕ УДАЛЕНИЕ ДАННЫХ/, "Global Settings exposes explicit recovery wipe");
assert.match(v51, /signalUnknownCredential/, "removed WebAuthn credentials are signalled stale to supported OS providers");
assert.match(v51, /backs\.slice\(1\)/, "pending Contacts modal deduplicates Back actions");

assert.match(v52, /DeviceRoot\.deviceMaterial/, "Account registry key material is protected by DeviceRoot");
assert.match(v52, /dm_registry_secure_v1/, "encrypted registry has a dedicated database");
assert.match(v52, /HMAC/, "Account IDs become blind aliases on disk");
assert.match(v52, /AES-GCM/, "Account registry records are encrypted at rest");
assert.match(v52, /const encryptedRows = \[\]/, "legacy records are encrypted before opening the write transaction");
assert.match(v52, /Only now is the old plaintext registry eligible for deletion/, "plaintext is deleted only after encrypted commit and marker succeed");
assert.match(v52, /const alias = await aliasFor\(record\.id\);?[\s\S]*const tx = db\.transaction/, "crypto finishes before registry write transactions");
assert.match(v52, /loginWithGlobalSettingsV52/, "Global Settings remains reachable when the registry is empty");

assert.match(v53, /const PREFIX = "0010"/, "0010 is reserved as the emergency wipe prefix");
assert.match(v53, /_emergencyWipeSequence/, "leading zeroes are captured from raw calculator presses");
assert.match(v53, /masterMatches/, "emergency wipe requires the configured Master key");
assert.match(v53, /indexedDB\.deleteDatabase/, "emergency wipe removes IndexedDB state");
assert.match(v53, /caches\.keys/, "emergency wipe clears Cache Storage");
assert.match(v53, /getRegistrations/, "emergency wipe unregisters service workers");
assert.match(v53, /localStorage\.clear/, "emergency wipe clears localStorage");
assert.match(v53, /sessionStorage\.clear/, "emergency wipe clears sessionStorage");
assert.match(v53, /location\.replace\("about:blank"\)/, "emergency wipe leaves the app without adding a history entry");

console.log("v53 browser acceptance source regression: all assertions passed");
