#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const {
  parseDmashNodeUri,
  serializeDmashNodeUri,
} = require("../js/dmash_links.js");

const nodeId = "ab".repeat(32);
const descriptor = {
  v: 1,
  e: "wss://node.example.test/dmash-client/v1",
  n: nodeId,
  l: "Example node",
  c: ["STATUS", "START_PROBE"],
};
const canonicalUri = serializeDmashNodeUri(descriptor);

function storage() {
  const values = new Map();
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
  };
}

const localStorage = storage();
const messages = [];
const context = {
  URL,
  JSON,
  Map,
  Set,
  Object,
  Array,
  Error,
  Promise,
  console,
  localStorage,
  sessionStorage: storage(),
  window: {
    location: { href: "https://app.example.test/" },
    parseDmashNodeUri,
    serializeDmashNodeUri,
    dispatchEvent() {},
    alert(message) { messages.push(String(message)); },
  },
  document: { getElementById() { return null; } },
  CustomEvent: class CustomEvent { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
};
context.window.window = context.window;
vm.createContext(context);
vm.runInContext(fs.readFileSync(require.resolve("../js/node_manager.js"), "utf8"), context, { filename: "node_manager.js" });
const manager = context.window.NodeManager;
manager.endpoints = [];
manager.active = null;

const imported = manager.importNodeProvisioning(canonicalUri);
assert.equal(imported.url, "wss://node.example.test/dmash-client/v1");
assert.equal(imported.label, descriptor.l);
assert.equal(imported.nodeId, nodeId);
assert.deepEqual([...imported.capabilities], descriptor.c);
assert.equal(manager.active, imported, "canonical import selects the imported endpoint");
assert.deepEqual(
  parseDmashNodeUri(context.window.serializeDmashNodeUri({ v: 1, e: imported.url, n: imported.nodeId, l: imported.label, c: imported.capabilities })),
  descriptor,
  "QR/copy descriptor derives the canonical node URI"
);

assert.throws(
  () => manager.importNodeProvisioning("#/node/not-a-valid-descriptor"),
  /Descriptor|base64url|UTF-8 JSON/,
  "canonical node imports use the DmashLinks parser"
);

const legacy = JSON.stringify({ type: "DMASH_NODE_V1", version: 1, url: "wss://legacy.example.test/dmp-c/v1", label: "Legacy", password: "not-auth" });
const legacyEndpoint = manager.importNodeProvisioning(legacy);
assert.equal(legacyEndpoint.nodeId, null, "legacy package has no identity assertion");
assert.equal(Object.hasOwn(legacyEndpoint, "password"), false, "legacy password metadata is discarded and cannot imply password auth");
assert.throws(
  () => manager.importNodeProvisioning(JSON.stringify({ type: "DMASH_NODE_V1", version: 1, url: "wss://legacy.example.test/", unexpected: true })),
  /legacy QR/,
  "legacy JSON compatibility is explicitly bounded"
);

manager.showNodeQR(legacyEndpoint);
assert.match(messages.at(-1), /канонический D-MASH/, "legacy endpoint cannot be re-exported as a fake canonical link");

console.log("Node canonical-link integration: all assertions passed");
