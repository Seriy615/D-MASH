"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const worker = fs.readFileSync(path.join(root, "sw.js"), "utf8");
const core = fs.readFileSync(path.join(root, "js", "core_engine.js"), "utf8");
const chatPassword = fs.readFileSync(path.join(root, "js", "chat_password.js"), "utf8");
const index = fs.readFileSync(path.join(root, "index.html"), "utf8");

// Cache the response clone synchronously, before the response is handed back
// to the page and its body can be consumed.
assert.equal((worker.match(/const cachedResponse = response\.clone\(\);/g) || []).length, 2);
assert.match(worker, /event\.waitUntil\(caches\.open\(CACHE_NAME\)/);
assert.doesNotMatch(worker, /cache\.put\(event\.request, response\.clone\(\)\)/);

// Chat passphrases use a masked text control, so Chromium password managers do
// not classify or offer to save these local-only secrets.
assert.match(core, /chat-secret-input/);
assert.match(core, /passwordManagerSafe/);
assert.match(chatPassword, /passwordManagerSafe:true/);
assert.match(index, /<form autocomplete="off" onsubmit="event\.preventDefault\(\); sys\.init\(\);">/);

console.log("Password prompt and service-worker response regression checks passed");
