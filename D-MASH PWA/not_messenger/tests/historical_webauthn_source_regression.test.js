"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const source = fs.readFileSync(require.resolve("../js/release.js"), "utf8");

assert.match(source, /rp:\s*\{\s*name:\s*"MathPro Security",\s*id:\s*global\.location\?\.hostname\s*\}/);
assert.match(source, /pubKeyCredParams:\s*\[\{\s*alg:\s*-7,\s*type:\s*"public-key"\s*\}\]/);
assert.match(source, /authenticatorAttachment:\s*"platform"/);
assert.match(source, /userVerification:\s*"required"/);
assert.match(source, /residentKey:\s*"required"/);
assert.match(source, /extensions:\s*\{\s*prf:\s*\{\s*eval:\s*\{\s*first:\s*salt\s*\}\s*\}\s*\}/);
assert.match(source, /timeout:\s*60000/);
assert.match(source, /Historical flow consumed the PRF result returned by create\(\)/);
assert.doesNotMatch(source, /Software mode|fallback on Master PIN|encryptWithHardware|decryptWithHardware/);

console.log("Historical WebAuthn source regression: all assertions passed");
