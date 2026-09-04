"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "js", "ui_global_bridge.js"), "utf8");
new vm.Script(source, { filename: "ui_global_bridge.js" });
assert.match(source, /typeof ui !== "undefined"/, "bridge waits for the legacy global lexical ui binding");
assert.match(source, /global\.ui = ui/, "bridge exports lexical ui as window.ui for runtime repair modules");
console.log("UI global bridge source regression: all assertions passed");
