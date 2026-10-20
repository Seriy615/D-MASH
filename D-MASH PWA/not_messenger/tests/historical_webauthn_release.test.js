"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { TextEncoder, TextDecoder } = require("node:util");

(async () => {
  const source = fs.readFileSync(require.resolve("../js/release.js"), "utf8");
  const domListeners = new Map();
  const loadedScripts = [];
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

  Object.defineProperty(global, "isSecureContext", { value: true, configurable: true });
  Object.defineProperty(global, "navigator", { value: { credentials }, configurable: true });
  global.location = { hostname: "messenger.d-mash.ru" };
  global.nacl = require("../js/vendor/nacl-fast.min.js");
  const { DeviceRoot, DeviceRootError } = require("../js/device_root.js");
  DeviceRoot.setStoreForTests(store);
  DeviceRoot.state = { root: new Uint8Array(rootBytes), identity: { deviceId: "d1_test" }, record: store.record, created: false };

  const keypad = {
    addEventListener(type, callback, capture) { keypadListeners.set(`${type}:${!!capture}`, callback); }
  };
  const ui = {
    _suppressToken: null,
    async show_gate() {},
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
    queueMicrotask,
    setTimeout,
    clearTimeout,
    setInterval() { throw new Error("release-managed runtime must not use an installer timer"); },
    clearInterval() {},
    DeviceRoot,
    DeviceRootError,
    ui,
    sys: {},
    location: { hostname: "messenger.d-mash.ru" },
    navigator: { credentials },
    btoa(value) { return Buffer.from(value, "binary").toString("base64"); },
    atob(value) { return Buffer.from(value, "base64").toString("binary"); },
    document: {
      readyState: "loading",
      scripts: [],
      createElement(tag) { return { tagName: tag }; },
      head: { appendChild(element) {
        if (element.tagName === "script") {
          loadedScripts.push(element.src);
          if (element.src.startsWith('js/call_session.js?')) context.DmashCallSession = { CallSignalingSession: class {} };
          element.onload();
        }
      } },
      getElementById(id) { if (id === "keypad") return keypad; if (id === "dmash-build-id") return badge; return null; }
    },
    addEventListener(type, callback) { domListeners.set(type, callback); }
  };
  context.window = context;
  context.globalThis = context;

  vm.runInNewContext(source, context, { filename: "release.js" });
  await domListeners.get("DOMContentLoaded")();
  assert.ok(loadedScripts.some(src => src.startsWith("js/runtime_fixes.js?")), "release loads the actual WebAuthn integration");
  // The implementation moved out of release.js; exercise the same runtime
  // module the loader selected, retaining the historical WebAuthn contract.
  vm.runInNewContext(fs.readFileSync(require.resolve("../js/ui_global_bridge.js"), "utf8"), context, { filename: "ui_global_bridge.js" });
  vm.runInNewContext(fs.readFileSync(require.resolve("../js/runtime_fixes.js"), "utf8"), context, { filename: "runtime_fixes.js" });
  context.DmashRuntimeReadiness.flush();
  // This fixture deliberately has no Core/NodeManager. The real installer can
  // expose DeviceRoot/gesture stages, but must not report full UI readiness.
  await assert.rejects(context.DmashRuntimeReadiness.compose(), /UI_RUNTIME_NOT_READY/);
  const enrollReference = DeviceRoot.enrollWebAuthnPrf;
  const holdReference = ui.handleBiometricHold;
  context.DmashRuntimeReadiness.flush();
  assert.equal(DeviceRoot.enrollWebAuthnPrf, enrollReference, "readiness retries preserve installed WebAuthn wrappers");
  assert.equal(ui.handleBiometricHold, holdReference, "readiness retries must not duplicate the trusted gesture wrapper");

  const enrolled = await DeviceRoot.enrollWebAuthnPrf();
  assert.equal(enrolled.enrolled, true);
  assert.equal(enrolled.credentialCount, 1);
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

  DeviceRoot.lock();
  DeviceRoot.__dmashBiometricRecordCache = await store.get();
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

  assert.equal(badge.textContent, `D-MASH build ${context.DMASH_RELEASE.id}`);
  console.log("Historical WebAuthn device compatibility: all assertions passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
