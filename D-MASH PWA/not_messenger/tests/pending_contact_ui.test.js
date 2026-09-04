#!/usr/bin/env node
"use strict";

// Dependency-free UI acceptance test. It exercises the production Core through
// a mocked device-global inbox, ContactPayloads, Account registry, and dialogs.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { ContactPayloads } = require("../js/contact_payloads.js");

const modal = { style: {}, innerHTML: "" };
const deviceState = { unlocked: true };
const accountIdentifier = "f".repeat(64);
const request = {
  id: "request_1",
  displayName: "Alice <remote>",
  intro: "Hello from Alice",
  replyRoute: "reply-route",
  receivedRoute: "received-route",
  receivedAt: 100,
  updatedAt: 100,
  status: "pending",
  bootstrap: {}
};
const transitions = [];
class PendingContactRequestStore {
  constructor(options) { this.options = options; PendingContactRequestStore.constructed += 1; }
  static normalizeDisplayName(value) {
    const normalized = String(value || "").trim().replace(/\s+/g, " ");
    if (!normalized) throw new Error("Quick Name is required");
    return normalized;
  }
  async list() { return [structuredClone(request)]; }
  async read(id) { return id === request.id ? structuredClone(request) : null; }
  async accept(id) { assert.equal(id, request.id); request.status = "accepted"; transitions.push("accepted"); return structuredClone(request); }
  async reject(id) { assert.equal(id, request.id); request.status = "rejected"; transitions.push("rejected"); return structuredClone(request); }
}
PendingContactRequestStore.constructed = 0;

const window = {
  crypto: webcrypto,
  DeviceRoot: { state: deviceState },
  PendingContactRequestStore,
  ContactPayloads,
  addEventListener() {},
};
const document = { getElementById(id) { return id === "sys-modal" ? modal : null; } };
const context = {
  window, document, crypto: webcrypto, console, TextEncoder, TextDecoder,
  Uint8Array, Array, Map, Object, Math, Date, JSON, Promise,
  localStorage: { getItem() { return null; } },
  URL: { revokeObjectURL() {} }, setInterval() { return 1; }, clearInterval() {},
};
vm.runInNewContext(fs.readFileSync(require.resolve("../js/core_engine.js"), "utf8"), context, { filename: "core_engine.js" });
const Core = window.Core;
Core.deviceState = deviceState;
Core.customAlert = (title, message) => { modal.innerHTML = `<h4>${title}</h4>${message}`; };
Core.customConfirm = (_title, _message, onYes) => onYes();
context.Storage = { async getAllRegistryAccounts() { return [{ id: "Account One", pk: accountIdentifier + "a".repeat(64) }]; } };

(async () => {
  await Core.openPendingContacts();
  assert.equal(PendingContactRequestStore.constructed, 1, "inbox store is constructed once at DeviceRoot scope");
  assert.equal(Core.pendingContactRequestStore.options.deviceRoot, window.DeviceRoot, "inbox is bound to DeviceRoot, not Account state");
  assert.match(modal.innerHTML, /ЗАПРОСЫ В КОНТАКТЫ/, "pending-contact list is rendered");
  assert.match(modal.innerHTML, /color:#49b9ff/, "pending contact list uses the required blue presentation");
  assert.match(modal.innerHTML, /Alice &lt;remote&gt;/, "untrusted display name is escaped");

  await Core.readPendingContactRequest(request.id);
  assert.match(modal.innerHTML, /ПРИНЯТЬ/, "request detail exposes accept");
  assert.match(modal.innerHTML, /ОТКЛОНИТЬ/, "request detail exposes reject");
  assert.match(modal.innerHTML, /ЗАКРЫТЬ/, "request detail exposes close");
  assert.match(modal.innerHTML, /ОТПРАВКА В СЕТЬ НЕ ВЫПОЛНЯЕТСЯ/, "detail clearly states local-only behavior");

  const prompts = ["Alice local"];
  Core.customPrompt = (_title, _message, callback) => callback(prompts.shift());
  Core.startAcceptPendingContactRequest(request.id);
  await new Promise(resolve => setImmediate(resolve));
  assert.match(modal.innerHTML, /Quick Name: Alice local/, "acceptance requires Quick Name before Account selection");
  assert.match(modal.innerHTML, new RegExp(accountIdentifier), "registered Account identifier is shown for selection");

  await Core.acceptPendingContactRequest(request.id, "Alice local", accountIdentifier);
  assert.deepEqual(transitions, ["accepted"], "acceptance makes only the local pending transition");
  assert.equal(request.status, "accepted", "request is locally resolved");
  assert.match(modal.innerHTML, /Сетевой CONTACT_ACCEPT не отправлялся/, "completion repeats that transport was not implemented");

  request.status = "pending";
  await Core.rejectPendingContactRequest(request.id);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(transitions, ["accepted", "rejected"], "rejection makes the local pending transition");
  assert.equal(request.status, "rejected", "rejection resolves the request locally");

  Core.pendingContactRequestStore = null;
  Core.deviceState = null;
  assert.throws(() => Core.getPendingContactRequestStore(), /РАЗБЛОКИРУЙТЕ УСТРОЙСТВО/, "device inbox is unavailable before DeviceRoot unlock");
  console.log("Pending contact UI acceptance: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
