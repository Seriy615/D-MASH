#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function storage() {
  const values = new Map();
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
  };
}

const sent = [];
const publicRoutes = [{ routeId: "public-route-a" }, { routeId: "public-route-b" }];
const context = {
  URL, JSON, Map, Set, Object, Array, Error, Promise, console,
  localStorage: storage(), sessionStorage: storage(),
  WebSocket: { OPEN: 1 },
  crypto: { randomUUID: (() => { let id = 0; return () => `request-${++id}`; })() },
  setTimeout, clearTimeout, setInterval, clearInterval,
  document: { getElementById() { return null; } },
  CustomEvent: class CustomEvent { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
  window: {
    location: { href: "https://app.example.test/" },
    dispatchEvent() {}, alert(message) { throw new Error(message); },
    DeviceRoutes: { activePublicRoutes: () => publicRoutes },
  },
};
context.window.window = context.window;
vm.createContext(context);
vm.runInContext(fs.readFileSync(require.resolve("../js/node_manager.js"), "utf8"), context, { filename: "node_manager.js" });

const manager = context.window.NodeManager;
manager.syncNotificationBeacon = async () => [];
manager.armStoredRoutes = async () => {};
manager.startPings = () => {};
const connection = {
  endpoint: { url: "wss://node.example.test/" }, state: "connecting", error: null,
  capabilities: new Set(), pendingPings: new Map(), pendingRequests: new Map(),
  socket: {
    readyState: 1,
    send(raw) {
      const message = JSON.parse(raw);
      sent.push(message);
      if (message.type === "START_PROBE") {
        queueMicrotask(() => manager.onMessage(connection, { data: JSON.stringify({ type: "START_PROBE_RESULT", request_id: message.request_id }) }));
      }
    },
  },
};
manager.connections.set(connection.endpoint.url, connection);

assert.equal(sent.filter(message => message.type === "START_PROBE").length, 0, "routes are not periodically or pre-auth probed");
manager.onMessage(connection, { data: JSON.stringify({ type: "AUTH_OK", auth_mode: "DEVICE_AUTH_V1", version: 2, capabilities: ["START_PROBE"] }) });

(async () => {
  for (let attempts = 0; attempts < 10 && sent.filter(message => message.type === "START_PROBE").length !== publicRoutes.length; attempts++) {
    await new Promise(resolve => setImmediate(resolve));
  }
  const probes = sent.filter(message => message.type === "START_PROBE");
  assert.deepEqual(probes.map(({ type, route_locator, back_route_locator, hop_limit }) => ({ type, route_locator, back_route_locator, hop_limit })), [
    { type: "START_PROBE", route_locator: "public-route-a", back_route_locator: "public-route-a", hop_limit: 15 },
    { type: "START_PROBE", route_locator: "public-route-b", back_route_locator: "public-route-b", hop_limit: 15 },
  ], "each active public DeviceRoute is probed once, immediately when authentication connects the node");
  assert.equal(sent.filter(message => message.type === "STATUS").length, 1, "connection lifecycle remains intact");
  console.log("Device route connection lifecycle: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
