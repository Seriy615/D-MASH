#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { ContactPayloads, ContactPayloadError } = require("../js/contact_payloads.js");

const key = (character) => character.repeat(43);
const request = Object.freeze({
  type: "CONTACT_REQUEST_V1",
  version: 1,
  request_id: key("a"),
  sender_display_name: "Alice",
  intro_message: "Hello from the physics class.",
  reply_route_certificate: {
    version: 1,
    routeId: key("b"),
    signingPublicKey: key("b"),
    boxPublicKey: key("c"),
    issuedAt: 123456,
    signature: key("d") + key("d")
  },
  bootstrap_encryption_public: key("e"),
  protocol_capabilities: ["CONTACT_ACCEPT_V1", "PRIVATE_ROUTE_BOOTSTRAP_V1"]
});
const accept = Object.freeze({
  type: "CONTACT_ACCEPT_V1",
  version: 1,
  request_id: request.request_id,
  my_display_name: "Bob",
  selected_account_public_key: "f".repeat(64),
  account_handshake_material: key("g"),
  established_private_route_bootstrap: key("h")
});

const error = (fn, code) => assert.throws(fn, (reason) => reason instanceof ContactPayloadError && reason.code === code);

const requestWire = ContactPayloads.serializeRequest(request);
assert.equal(new TextDecoder().decode(requestWire), JSON.stringify(request), "request serialization is canonical JSON");
assert.deepEqual(ContactPayloads.deserializeRequest(requestWire), request, "canonical request round-trips");
assert.equal(new TextDecoder().decode(requestWire).includes("account"), false, "request wire contains no Account identity field");

const withAccountIdentity = { ...request, selected_account_public_key: "f".repeat(64) };
error(() => ContactPayloads.validateRequest(withAccountIdentity), "INVALID_CONTACT_REQUEST", "request rejects Account identity fields");
error(() => ContactPayloads.validateRequest({ ...request, protocol_capabilities: [...request.protocol_capabilities].reverse() }), "NON_CANONICAL_PROTOCOL_CAPABILITIES");
error(() => ContactPayloads.deserializeRequest(new TextDecoder().decode(requestWire).replace("Alice", "\\u0041lice")), "NON_CANONICAL_CONTACT_REQUEST");
error(() => ContactPayloads.validateRequest({ ...request, reply_route_certificate: { ...request.reply_route_certificate, routeId: key("z") } }), "INVALID_REPLY_ROUTE_CERTIFICATE");

const acceptWire = ContactPayloads.serializeAccept(accept, request);
assert.equal(new TextDecoder().decode(acceptWire), JSON.stringify(accept), "accept serialization is canonical JSON");
assert.deepEqual(ContactPayloads.deserializeAccept(acceptWire, request), accept, "canonical accept round-trips only with its accepted request");
error(() => ContactPayloads.validateAccept(accept, { ...request, request_id: key("i") }), "INVALID_CONTACT_ACCEPT");
error(() => ContactPayloads.validateAccept({ ...accept, selected_account_public_key: key("j") }, request), "INVALID_SELECTED_ACCOUNT_PUBLIC_KEY");
error(() => ContactPayloads.deserializeAccept(new TextDecoder().decode(acceptWire).replace("Bob", "B\\u006fb"), request), "NON_CANONICAL_CONTACT_ACCEPT");

console.log("Contact payloads acceptance: all assertions passed");
