"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const v50 = fs.readFileSync(path.join(root, "js", "acceptance_v50.js"), "utf8");
const v51 = fs.readFileSync(path.join(root, "js", "acceptance_v51.js"), "utf8");
const v52 = fs.readFileSync(path.join(root, "js", "acceptance_v52.js"), "utf8");
const v54 = fs.readFileSync(path.join(root, "js", "acceptance_v54.js"), "utf8");
const v55 = fs.readFileSync(path.join(root, "js", "acceptance_v55.js"), "utf8");
const release = fs.readFileSync(path.join(root, "js", "release.js"), "utf8");
const css = fs.readFileSync(path.join(root, "css", "runtime_fixes.css"), "utf8");

new vm.Script(v50, { filename: "acceptance_v50.js" });
new vm.Script(v51, { filename: "acceptance_v51.js" });
new vm.Script(v52, { filename: "acceptance_v52.js" });
new vm.Script(v54, { filename: "acceptance_v54.js" });
new vm.Script(v55, { filename: "acceptance_v55.js" });

const currentRelease = release.match(/id:\s*"([^"]+)"/)[1];
const worker = fs.readFileSync(path.join(root, 'sw.js'), 'utf8');
assert.ok(worker.includes("const RELEASE_ID = '" + currentRelease + "'"), 'page and worker use the same current release');
assert.match(release, /acceptance_v50\.js/, "v50 compatibility runtime is loaded");
assert.match(release, /acceptance_v51\.js/, "v51 compatibility runtime is loaded");
assert.match(release, /acceptance_v52\.js/, "v52 secure-registry runtime is loaded");
assert.match(release, /acceptance_v54\.js/, "v54 authenticated emergency-wipe implementation is loaded");
assert.match(release, /acceptance_v55\.js/, "v55 canonical 0010 recovery-prefix override is loaded");
assert.doesNotMatch(release, /acceptance_v53\.js/, "obsolete intermediate emergency runtime is not loaded");
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

assert.match(v54, /const PREFIX = "1020"/, "v54 retains the internal authenticated wipe prefix implementation");
assert.match(v54, /const BIOMETRIC_HOLD_MS = 1000/, "device biometric hold is one second");
assert.match(v54, /_emergencyWipeSequence/, "emergency sequence is captured independently of the calculator display");
const credentials = fs.readFileSync(path.join(root, 'js', 'local_credentials.js'), 'utf8');
const bootstrap = fs.readFileSync(path.join(root, 'js', 'local_credentials_bootstrap.js'), 'utf8');
assert.match(v54, /service\.emergency\(masterKey\)/, "effective emergency entry delegates to authenticated shared service");
const emergency = credentials.slice(credentials.indexOf('        emergency(master)'), credentials.indexOf('    global.CredentialLifecycle'));
assert.match(emergency, /this\.root\.prepareUnlock\(master, \{ signal \}\)/, "existing root unwrap proves emergency master without a fast verifier");
assert.match(emergency, /wipeCoordinator\.wipe\(\{ signal, assertCurrent: current, heldLock: HELD_CREDENTIAL_LOCK \}\)/, "authenticated service transfers the exclusive credential lock to durable coordinator");
assert.match(credentials, /class DurableWipeCoordinator/, "deletion has one owner");
assert.match(credentials, /await this\.control\.put\(marker, \{ signal, assertCurrent \}\)/, "initial durable intent remains cancellable until transaction commit");
assert.match(credentials, /tx\.oncomplete = \(\) => \{ cleanup\(\); resolve\(\); \}/, "actual IDB completion establishes durable acceptance");
assert.match(credentials, /WIPE_BLOCKED/); assert.match(credentials, /WIPE_DELETE_FAILED/);
assert.match(bootstrap, /caches\?\.keys/); assert.match(bootstrap, /getRegistrations/);
assert.match(bootstrap, /localStorage\.clear\(\)/); assert.match(bootstrap, /sessionStorage\.clear\(\)/);
assert.doesNotMatch(v54, /masterMatches|sys_m|fastHash|indexedDB\.deleteDatabase|localStorage\.clear|sessionStorage\.clear|caches\.keys/, "effective wrapper cannot reintroduce fast authority or independent partial deletion");
assert.match(v54, /location\.replace\("about:blank"\)/, "emergency wipe leaves the app without adding a history entry");
assert.match(v55, /startsWith\("0010"\)/, "public recovery sequence starts with 0010");
assert.match(v55, /"1020" \+ sequence\.slice\(4\)/, "v55 delegates 0010 to the authenticated v54 wipe implementation");

console.log("v55 browser acceptance source regression: all assertions passed");
