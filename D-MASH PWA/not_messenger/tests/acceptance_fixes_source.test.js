"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const sourcePath = path.join(__dirname, "..", "js", "acceptance_fixes.js");
const source = fs.readFileSync(sourcePath, "utf8");

// Parse-only regression: the late-loaded browser patch must remain valid JS.
new vm.Script(source, { filename: "acceptance_fixes.js" });

assert.match(source, /PUBLIC \/ PRIVATE/, "share UI exposes explicit Public/Private mode selection");
assert.match(source, /DMASH_PAIRING_V1/, "private QR carries the authenticated pairing package");
assert.match(source, /copyCurrentSharePayload/, "clipboard copies the exact rendered share payload");
assert.match(source, /selectSharePublicRoute/, "public sharing allows explicit RouteID selection");
assert.match(source, /requestGlobalNode/, "global Node settings expose an explicit public Node request");
assert.match(source, /NodeManager\.requestNode\(\)/, "public Node request uses the manager's explicit catalog request path");
assert.match(source, /РЕЕСТР АККАУНТОВ/, "device-wide account registry is exposed from Global Settings");
assert.match(source, /enterBiometricTriggerSetup/, "biometric enrollment exposes the calculator long-press setup entry point");
assert.doesNotMatch(source, /!window\.DeviceRoutes \|\| !window\.DeviceRoot\?\.state/, "Public Routes view no longer aliases module availability to a fake device-locked error");

console.log("Acceptance UI source regression: all assertions passed");
