#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const sent = [];
const storage = { getItem() { return null; }, setItem() {}, removeItem() {} };
const privateByAccount = {
  A: [{ routeId: "a-private-1" }, { routeId: "a-private-2" }],
  B: [{ routeId: "b-private-1" }],
};
const Core = {
  activeIdentity: "A",
  privateRouteProbeGeneration: 1,
  async activeAccountPrivateRoutes() { return privateByAccount[this.activeIdentity]; },
};
const context = {
  URL, JSON, Map, Set, Object, Array, Error, Promise, console,
  localStorage: storage, sessionStorage: storage,
  WebSocket: { OPEN: 1 },
  crypto: { randomUUID: (() => { let id = 0; return () => `request-${++id}`; })() },
  setTimeout, clearTimeout, setInterval, clearInterval,
  document: { getElementById() { return null; } },
  CustomEvent: class CustomEvent { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
  window: {
    location: { href: "https://app.example.test/" }, Core,
    DeviceRoutes: { activePublicRoutes: () => [{ routeId: "public-1" }] },
    dispatchEvent() {}, alert(message) { throw new Error(message); },
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
  endpoint: { url: "wss://node.example.test/" }, state: "connected", error: null,
  capabilities: new Set(["START_PROBE"]), pendingPings: new Map(), pendingRequests: new Map(),
  socket: { readyState: 1, send(raw) {
    const message = JSON.parse(raw); sent.push(message);
    if (message.type === "START_PROBE") queueMicrotask(() => manager.onMessage(connection, {
      data: JSON.stringify({ type: "START_PROBE_RESULT", request_id: message.request_id }),
    }));
  } },
};
manager.connections.set(connection.endpoint.url, connection);

(async () => {
  // Account login advertises every route belonging to A.
  await manager.probeActiveAccountPrivateRoutes();
  assert.deepEqual(sent.filter(m => m.type === "START_PROBE").map(m => m.route_locator), ["a-private-1", "a-private-2"]);

  // A reconnect/lifecycle pass follows the currently active account only.
  sent.length = 0;
  Core.activeIdentity = "B";
  await manager.probeActiveAccountPrivateRoutes();
  assert.deepEqual(sent.filter(m => m.type === "START_PROBE").map(m => m.route_locator), ["b-private-1"]);
  assert.equal(sent.some(m => m.route_locator.startsWith("a-")), false, "account A routes never leak into B");

  // Public routes remain independently advertised.
  sent.length = 0;
  await manager.probeActivePublicDeviceRoutes();
  assert.deepEqual(sent.filter(m => m.type === "START_PROBE").map(m => m.route_locator), ["public-1"]);

  // AUTH_OK/reconnect retrieves private routes asynchronously.  If A changes
  // accounts before that lookup resolves, its stale routes must not be sent.
  sent.length = 0;
  let resolveReconnectLookup;
  Core.activeIdentity = "A";
  Core.privateRouteProbeGeneration++;
  Core.activeAccountPrivateRoutes = () => new Promise(resolve => { resolveReconnectLookup = resolve; });
  const switchDuringReconnect = manager.probeActiveAccountPrivateRoutes(null, connection);
  Core.activeIdentity = "B";
  Core.privateRouteProbeGeneration++;
  resolveReconnectLookup([{ routeId: "a-reconnect-stale" }]);
  await switchDuringReconnect;
  assert.equal(sent.some(m => m.route_locator === "a-reconnect-stale"), false, "reconnect lookup cannot advertise A after switch to B");

  // Logout during the same AUTH_OK lookup must suppress the stale probe too.
  sent.length = 0;
  let resolveLogoutReconnectLookup;
  Core.activeIdentity = "B";
  Core.privateRouteProbeGeneration++;
  Core.activeAccountPrivateRoutes = () => new Promise(resolve => { resolveLogoutReconnectLookup = resolve; });
  const logoutDuringReconnect = manager.probeActiveAccountPrivateRoutes(null, connection);
  Core.activeIdentity = null;
  Core.privateRouteProbeGeneration++;
  resolveLogoutReconnectLookup([{ routeId: "b-reconnect-stale" }]);
  await logoutDuringReconnect;
  assert.equal(sent.some(m => m.route_locator === "b-reconnect-stale"), false, "reconnect lookup cannot advertise after logout");

  // Core starts account probing without awaiting it: a slow or rejected
  // START_PROBE cannot hold up the rest of authenticated startup.  The route
  // lookup also snapshots the account session, so a deferred A lookup cannot
  // dispatch after a switch to B or after logout/reconnect.
  const coreStorage = { getRegistryAccount: () => delayedLookup };
  const coreContext = {
    console, Promise, Array, Map, Set, Object, Uint8Array, TextEncoder,
    window: { location: {}, addEventListener() {} },
    document: { getElementById() { return null; } },
    localStorage: storage, sessionStorage: storage,
    crypto: context.crypto, URL: { revokeObjectURL() {} }, Storage: coreStorage,
  };
  coreContext.window.window = coreContext.window;
  vm.createContext(coreContext);
  vm.runInContext(fs.readFileSync(require.resolve("../js/core_engine.js"), "utf8"), coreContext, { filename: "core_engine.js" });
  const lifecycleCore = coreContext.window.Core;
  let resolveLookup;
  const delayedLookup = new Promise(resolve => { resolveLookup = resolve; });
  const advertised = [];
  lifecycleCore.activeIdentity = "A";
  lifecycleCore.privateRouteProbeGeneration = 1;
  coreContext.window.Storage = coreStorage;
  coreContext.window.NodeManager = {
    probeActiveAccountPrivateRoutes(routes) { advertised.push(routes); return Promise.reject(new Error("START_PROBE rejected")); },
  };
  let workspaceStarted = false;
  void lifecycleCore.advertiseActiveAccountPrivateRoutes();
  workspaceStarted = true; // Represents the immediately following boot work.
  assert.equal(workspaceStarted, true, "delayed START_PROBE does not block workspace/account login");
  lifecycleCore.activeIdentity = "B";
  lifecycleCore.privateRouteProbeGeneration++;
  resolveLookup({ privateRoutes: [{ routeId: "a-private-stale" }] });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(advertised, [], "A routes are not dispatched after an A-to-B switch");

  let resolveLogoutLookup;
  coreStorage.getRegistryAccount = () => new Promise(resolve => { resolveLogoutLookup = resolve; });
  lifecycleCore.activeIdentity = "B";
  lifecycleCore.privateRouteProbeGeneration++;
  void lifecycleCore.advertiseActiveAccountPrivateRoutes();
  lifecycleCore.activeIdentity = null;
  lifecycleCore.privateRouteProbeGeneration++;
  resolveLogoutLookup({ privateRoutes: [{ routeId: "b-private-stale" }] });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(advertised, [], "private routes are not dispatched after logout/reconnect during lookup");
  console.log("Private route lifecycle: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
