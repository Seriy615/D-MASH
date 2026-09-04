#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { ContactTransport, ContactTransportError } = require("../js/contact_transport.js");

const key = character => character.repeat(43);
const request = Object.freeze({
  type: "CONTACT_REQUEST_V1", version: 1, request_id: key("a"),
  sender_display_name: "Alice", intro_message: "Private hello",
  reply_route_certificate: { routeId: key("b") }, bootstrap_encryption_public: key("c"),
  protocol_capabilities: ["CONTACT_ACCEPT_V1"]
});
const destinationCertificate = Object.freeze({ routeId: key("d") });
const bytes = new TextEncoder().encode(JSON.stringify(request));
const validator = {
  validateRequest(value) {
    if (!value || value.type !== "CONTACT_REQUEST_V1" || value.request_id !== request.request_id) throw new Error("malformed canonical request");
    return request;
  },
  serializeRequest(value) { assert.equal(value, request); return bytes; },
  deserializeRequest(value) { assert.deepEqual(value, bytes); return request; }
};

(async () => {
  const submitted = [], stored = [], seen = new Set();
  const transport = new ContactTransport({
    validator,
    async encrypt({ plaintext, recipientCertificate }) {
      assert.deepEqual(plaintext, bytes);
      assert.equal(recipientCertificate.routeId, destinationCertificate.routeId,
        "first request is encrypted to destination Route, never sender reply Route");
      assert.notEqual(recipientCertificate.routeId, request.reply_route_certificate.routeId);
      return key("z");
    },
    async submit(value) { submitted.push(value); },
    async decrypt({ envelope, receivedRoute }) {
      assert.equal(receivedRoute, "inbox-route");
      assert.equal(envelope.request_id, request.request_id);
      return { authenticated: true, plaintext: bytes };
    },
    async dedupe({ requestId }) { const replay = seen.has(requestId); seen.add(requestId); return replay; },
    async store(entry) { stored.push(entry); return entry.request; },
    now: () => 99
  });

  const routeLocator = destinationCertificate.routeId;
  const envelope = await transport.deliver({ routeLocator, recipientCertificate: destinationCertificate, payload: request });
  assert.deepEqual(Object.keys(envelope).sort(), ["ciphertext", "request_id", "type", "version"]);
  const metadata = JSON.stringify(envelope).toLowerCase();
  for (const secret of ["alice", "private hello", "account", request.reply_route_certificate.routeId.toLowerCase()]) {
    assert.equal(metadata.includes(secret), false, "opaque metadata excludes plaintext and account identity");
  }
  assert.deepEqual(submitted, [{ routeLocator, envelope }], "only injected submit receives an opaque envelope");

  await assert.rejects(
    () => transport.deliver({ routeLocator, payload: request }),
    (error) => error instanceof ContactTransportError && error.code === "INVALID_RECIPIENT_CERTIFICATE",
    "destination RouteCertificate is mandatory"
  );
  await assert.rejects(
    () => transport.deliver({ routeLocator, recipientCertificate: { routeId: key("e") }, payload: request }),
    (error) => error instanceof ContactTransportError && error.code === "ROUTE_CERTIFICATE_MISMATCH",
    "certificate cannot be transplanted to another RouteID"
  );

  for (const invalidRouteLocator of ["node-route", "contact:alice", "account-identifier", "A".repeat(64)]) {
    await assert.rejects(
      () => transport.deliver({ routeLocator: invalidRouteLocator, recipientCertificate: destinationCertificate, payload: request }),
      (error) => error instanceof ContactTransportError && error.code === "INVALID_ROUTE_LOCATOR",
      "plaintext or non-canonical route locators reject before submission"
    );
  }
  assert.equal(submitted.length, 1, "rejected route locators never reach submit");

  const received = await transport.ingest({ envelope, receivedRoute: "inbox-route" });
  assert.equal(received.request, request);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].receivedAt, 99);
  assert.equal(Object.hasOwn(stored[0], "account"), false, "transport has no Account mutation path");

  await assert.rejects(
    () => transport.ingest({ envelope, receivedRoute: "inbox-route" }),
    (error) => error instanceof ContactTransportError && error.code === "REPLAY_DETECTED"
  );
  assert.equal(stored.length, 1);

  await assert.rejects(
    () => transport.ingest({ envelope: { ...envelope, ciphertext: "%%%" }, receivedRoute: "inbox-route" }),
    (error) => error instanceof ContactTransportError && error.code === "INVALID_CIPHERTEXT"
  );

  assert.throws(
    () => new ContactTransport({ validator, submit: async () => {}, decrypt: async () => {}, dedupe: async () => false, store: async () => {} }),
    (error) => error instanceof ContactTransportError && error.code === "CALLBACK_REQUIRED"
  );
  console.log("Contact transport acceptance: all assertions passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
