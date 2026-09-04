#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function storage(initial = []) {
  const values = new Map(initial);
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
  };
}

const forgeUrl = "wss://forgeai.isgood.host/dmash-client/v1";
const localStorage = storage([["dmash_node_endpoints_v1", JSON.stringify([
  { url: forgeUrl, label: "persisted Forge" },
  { url: "wss://node.example.test/dmash-client/v1", label: "Allowed" },
])], ["dmash_active_node_v1", forgeUrl]]);
const context = {
  URL, JSON, Map, Set, Object, Array, Error, Promise, console,
  localStorage, sessionStorage: storage(),
  window: { location: { href: "https://app.example.test/" }, dispatchEvent() {}, alert() {} },
  document: { getElementById() { return null; } },
  CustomEvent: class CustomEvent { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
  fetch: async () => ({ ok: true, async json() { return { nodes: [
    { label: "catalog Forge", url: forgeUrl },
    { label: "catalog allowed", url: "wss://catalog.example.test/dmash-client/v1" },
  ] }; } }),
};
context.window.window = context.window;
vm.createContext(context);
vm.runInContext(fs.readFileSync(require.resolve("../js/node_manager.js"), "utf8"), context, { filename: "node_manager.js" });

const manager = context.window.NodeManager;
assert.deepEqual(manager.endpoints.map(endpoint => endpoint.url), ["wss://node.example.test/dmash-client/v1"], "persisted Forge endpoint is discarded");
assert.equal(manager.active, null, "persisted Forge endpoint cannot remain active");
assert.throws(() => manager.add(forgeUrl), /not an eligible Messenger node/, "manual Forge endpoint is rejected");

(async () => {
  const originNodes = await manager.loadOriginList();
  assert.deepEqual(originNodes.map(node => node.url), ["wss://catalog.example.test/dmash-client/v1"], "Forge is absent from catalog candidates");
  assert.deepEqual(JSON.parse(fs.readFileSync(require.resolve("../nodes.json"), "utf8")).nodes.map(node => node.url), ["wss://stage-api-ems.d-mash.ru/dmash-client/v1"], "nodes.json contains no Forge entry");
  console.log("NodeManager Forge exclusion: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
