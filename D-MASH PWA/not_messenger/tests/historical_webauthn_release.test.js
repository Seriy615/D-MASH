"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { TextEncoder, TextDecoder } = require("node:util");

(async () => {
  const source = fs.readFileSync(require.resolve("../js/release.js"), "utf8");
  const domListeners = new Map();
  const keypadListeners = new Map();
  const performedHolds = [];
  const createCalls = [];
  const getCalls = [];

  const credentialId = Uint8Array.from([1, 2, 3, 4]);
  const prfOutput = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const credential = {
    rawId: credentialId.buffer.slice(0),
    getClientExtensionResults() {
      return { prf: { results: { first: prfOutput.buffer.slice(0) } } };
    }
  };
  const credentials = {
    async create(options) { createCalls.push(options); return credential; },
    async get(options) { getCalls.push(options); return credential; }
  };

  const rootBytes = Uint8Array.from({ length: 32 }, (_, index) => 31 - index);
  const store = {
    record: { id: "root", version: 1, materials: {} },
    async get() { return this.record; },
    async put(record) { this.record = record; }
  };

  class DeviceRootError extends Error {
    constructor(code, message) { super(message); this.code = code; this.name = "DeviceRootError"; }
  }

  const DeviceRoot = {
    VERSION: 1,
    state: null,
    _crypto: webcrypto,
    _requireCrypto() {},
    _requireWebAuthn() {},
    _credentials() { return credentials; },
    _webauthnChallenge() { return webcrypto.getRandomValues(new Uint8Array(32)); },
    _credentialId(value) { return Buffer.from(new Uint8Array(value.rawId)).toString("base64"); },
    _prfResult(value) {
      const result = value.getClientExtensionResults().prf.results.first;
      const bytes = new Uint8Array(result);
      if (bytes.length !== 32) throw new DeviceRootError("WEBAUTHN_PRF_UNAVAILABLE", "invalid PRF");
      return new Uint8Array(bytes);
    },
    async _prfWrapKey(output) {
      return webcrypto.subtle.importKey("raw", output, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    },
    _store() { return store; },
    async deviceIdentity(root) { return { deviceId: `d1_${root[0]}` }; },
    lock() { this.state = null; }
  };
  DeviceRoot.state = { root: new Uint8Array(rootBytes), identity: { deviceId: "d1_test" }, record: store.record, created: false };

  const keypad = {
    addEventListener(type, callback, capture) { keypadListeners.set(`${type}:${!!capture}`, callback); }
  };
  const ui = {
    _suppressToken: null,
    async handleBiometricHold(token) { performedHolds.push(token); return true; }
  };
  const badge = { textContent: "" };

  const context = {
    console,
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    Buffer,
    setTimeout,
    clearTimeout,
    DeviceRoot,
    DeviceRootError,
    ui,
    location: { hostname: "messenger.d-mash.ru" },
    navigator: { credentials },
    btoa(value) { return Buffer.from(value, "binary").toString("base64"); },
    atob(value) { return Buffer.from(value, "base64").toString("binary"); },
    document: {
      getElementById(id) { if (id === "keypad") return keypad; if (id === "dmash-build-id") return badge; return null; }
    },
    addEventListener(type, callback) { domListeners.set(type, callback); }
  };
  context.window = context;
  context.globalThis = context;

  vm.runInNewContext(source, context, { filename: "release.js" });
  domListeners.get("DOMContentLoaded")();

  const enrolled = await DeviceRoot.enrollWebAuthnPrf();
  assert.deepEqual(enrolled, { enrolled: true });
  assert.equal(createCalls.length, 1, "enrollment uses one historical credentials.create call");
  assert.equal(getCalls.length, 0, "enrollment must not immediately request a second biometric assertion");
  const createPk = createCalls[0].publicKey;
  assert.equal(createPk.rp.id, "messenger.d-mash.ru");
  assert.equal(createPk.rp.name, "MathPro Security");
  assert.equal(createPk.pubKeyCredParams[0].alg, -7);
  assert.equal(createPk.authenticatorSelection.authenticatorAttachment, "platform");
  assert.equal(createPk.authenticatorSelection.userVerification, "required");
  assert.equal(createPk.authenticatorSelection.residentKey, "required");
  assert.equal(createPk.extensions.prf.eval.first.length, 32);
  assert.equal(store.record.biometricWrap.wrap, "webauthn-prf-aes-256-gcm-v1");

  DeviceRoot.state = null;
  const unlocked = await DeviceRoot.unlockWithWebAuthnPrf();
  assert.deepEqual([...unlocked.root], [...rootBytes]);
  assert.equal(getCalls.length, 1, "unlock uses one credentials.get assertion");
  const getPk = getCalls[0].publicKey;
  assert.equal(getPk.timeout, 60000);
  assert.equal(getPk.userVerification, "required");
  assert.deepEqual([...getPk.allowCredentials[0].id], [...credentialId]);
  assert.equal(getPk.extensions.prf.eval.first.length, 32);

  // Existing timer callback only qualifies a long press. WebAuthn-capable work
  // starts from the trusted pointerup event, mirroring the old direct UI flow.
  await ui.handleBiometricHold("3");
  assert.deepEqual(performedHolds, [], "timer qualification must not perform biometric work");
  const pointerUp = keypadListeners.get("pointerup:true");
  pointerUp({ target: { closest() { return { dataset: { calcToken: "3" } }; } } });
  await Promise.resolve();
  assert.deepEqual(performedHolds, ["3"], "qualified hold performs on trusted pointerup");
  assert.equal(ui._suppressToken, "3", "long press remains suppressed as calculator input");

  assert.equal(badge.textContent, "D-MASH build m1.5-device-auth-v2-20260901.44");
  console.log("Historical WebAuthn device compatibility: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
