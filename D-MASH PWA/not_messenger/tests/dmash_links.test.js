#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const {
  DmashLinkError,
  parseDmashNodeUri, serializeDmashNodeUri,
  parseDmashContactUri, serializeDmashContactUri,
} = require("../js/dmash_links.js");

const nodeId = "ab".repeat(32);
const contactId = "cd".repeat(32);
const contribution = "ef".repeat(32);

const node = { v: 1, e: "wss://node.example.test/dmash-client/v1", n: nodeId, l: "Example node", c: ["STATUS", "START_PROBE"] };
const nodeUri = serializeDmashNodeUri(node);
assert.match(nodeUri, /^#\/node\/[A-Za-z0-9_-]+$/, "node URI is fragment-only base64url");
assert.equal(nodeUri.includes("="), false, "node URI has no base64 padding");
assert.deepEqual(parseDmashNodeUri(nodeUri), node, "node descriptor round-trips canonically");
assert.deepEqual(parseDmashNodeUri(nodeUri, nodeId), node, "expected NodeID string is accepted");
assert.deepEqual(parseDmashNodeUri(nodeUri, { expectedNodeId: nodeId }), node, "expected NodeID option is accepted");

const contact = { v: 1, i: contactId, p: contribution, l: "Alice" };
const contactUri = serializeDmashContactUri(contact);
assert.match(contactUri, /^#\/c\/[A-Za-z0-9_-]+$/, "contact URI is fragment-only base64url");
assert.deepEqual(parseDmashContactUri(contactUri), contact, "contact descriptor round-trips canonically");

const rejects = (fn, description) => assert.throws(fn, DmashLinkError, description);
rejects(() => parseDmashNodeUri(`https://app.test/${nodeUri}`), "absolute URL is rejected");
rejects(() => parseDmashNodeUri("#/node/"), "empty node descriptor is rejected");
rejects(() => parseDmashNodeUri("#/node/e30"), "malformed node descriptor is rejected");
rejects(() => parseDmashNodeUri(nodeUri, "00".repeat(32)), "unexpected NodeID is rejected");
rejects(() => serializeDmashNodeUri({ ...node, v: 2 }), "unknown node version is rejected");
rejects(() => serializeDmashContactUri({ ...contact, v: 99 }), "unknown contact version is rejected");
rejects(() => serializeDmashNodeUri({ ...node, n: nodeId.toUpperCase() }), "noncanonical NodeID is rejected");
rejects(() => serializeDmashNodeUri({ ...node, e: "ws://node.example.test/" }), "remote plaintext WS endpoint is rejected");
rejects(() => serializeDmashNodeUri({ ...node, e: "wss://user:password@node.example.test/" }), "credential-bearing endpoint is rejected");
rejects(() => serializeDmashNodeUri({ ...node, e: "https://node.example.test/" }), "non-WebSocket endpoint is rejected");
rejects(() => serializeDmashNodeUri({ ...node, extra: true }), "unknown fields are rejected");
rejects(() => parseDmashContactUri(nodeUri), "wrong URI kind is rejected");

console.log("D-MASH links: all assertions passed");
