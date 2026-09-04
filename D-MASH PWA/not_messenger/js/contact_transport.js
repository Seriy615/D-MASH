"use strict";

/*
 * CONTACT_REQUEST_V1's deliberately small transport boundary.
 *
 * This module neither imports application state nor knows about Accounts.  Its
 * callers supply canonical-payload validation and every I/O/cryptographic
 * operation.  A node therefore sees only this envelope, never request text or
 * an Account identity.
 */
(function (global) {
    const VERSION = 1;
    const TYPE = "CONTACT_REQUEST_V1";
    const B64URL = /^[A-Za-z0-9_-]+$/;
    // RouteIDs are unpadded base64url encodings of 32-byte signing keys.
    // Pairing-derived mesh locators and descriptor IDs are lowercase 32-byte
    // hexadecimal tokens.  Do not accept a general string here: this boundary
    // must never forward contact or Account-like plaintext as routing data.
    const ROUTE_LOCATOR = /^(?:[A-Za-z0-9_-]{43}|[0-9a-f]{64})$/;

    class ContactTransportError extends Error {
        constructor(code, message) {
            super(message);
            this.name = "ContactTransportError";
            this.code = code;
        }
    }
    const fail = (code, message) => { throw new ContactTransportError(code, message); };
    const plainObject = (value, name) => {
        if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
            fail("INVALID_" + name, name + " must be a plain object.");
        }
        return value;
    };
    const callback = (value, name) => {
        if (typeof value !== "function") fail("CALLBACK_REQUIRED", name + " callback is required.");
        return value;
    };
    const opaque = (value, name) => {
        if (typeof value !== "string" || !value || value.length > 131072 || !B64URL.test(value)) {
            fail("INVALID_" + name, name + " must be opaque base64url data.");
        }
        return value;
    };

    class ContactTransport {
        constructor({ validator, encrypt, submit, decrypt, dedupe, store, now = () => Date.now() } = {}) {
            plainObject(validator, "VALIDATOR");
            for (const method of ["validateRequest", "serializeRequest", "deserializeRequest"]) {
                if (typeof validator[method] !== "function") fail("VALIDATOR_REQUIRED", "validator." + method + " is required.");
            }
            this.validator = validator;
            this.encrypt = callback(encrypt, "encrypt"); // No crypto fallback is permitted.
            this.submit = callback(submit, "submit");
            this.decrypt = callback(decrypt, "decrypt");
            this.dedupe = callback(dedupe, "dedupe");
            this.store = callback(store, "store");
            this.now = callback(now, "now");
        }

        static validateEnvelope(value) {
            plainObject(value, "ENVELOPE");
            const keys = Object.keys(value).sort();
            const expected = ["ciphertext", "request_id", "type", "version"];
            if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
                fail("INVALID_ENVELOPE", "Envelope has missing or unsupported metadata.");
            }
            if (value.version !== VERSION || value.type !== TYPE || typeof value.request_id !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.request_id)) {
                fail("INVALID_ENVELOPE", "Envelope version, type, or request ID is invalid.");
            }
            return Object.freeze({ version: VERSION, type: TYPE, request_id: value.request_id, ciphertext: opaque(value.ciphertext, "CIPHERTEXT") });
        }

        async deliver({ routeLocator, payload } = {}) {
            if (typeof routeLocator !== "string" || !ROUTE_LOCATOR.test(routeLocator)) {
                fail("INVALID_ROUTE_LOCATOR", "Route locator must be a canonical opaque RouteID or mesh token.");
            }
            const request = this.validator.validateRequest(payload);
            const plaintext = this.validator.serializeRequest(request);
            const ciphertext = await this.encrypt({ plaintext, recipientCertificate: request.reply_route_certificate });
            const envelope = ContactTransport.validateEnvelope({ version: VERSION, type: TYPE, request_id: request.request_id, ciphertext });
            await this.submit({ routeLocator, envelope });
            return envelope;
        }

        async ingest({ envelope: rawEnvelope, receivedRoute } = {}) {
            if (typeof receivedRoute !== "string" || !receivedRoute) fail("INVALID_RECEIVED_ROUTE", "Received route is invalid.");
            const envelope = ContactTransport.validateEnvelope(rawEnvelope);
            const opened = await this.decrypt({ envelope, receivedRoute });
            if (!opened || opened.authenticated !== true || opened.plaintext === undefined) {
                fail("DECRYPT_REJECTED", "Ingress decryption did not authenticate the envelope.");
            }
            const request = this.validator.deserializeRequest(opened.plaintext);
            if (request.request_id !== envelope.request_id) fail("REQUEST_BINDING_INVALID", "Request does not bind to its envelope.");
            if (await this.dedupe({ requestId: request.request_id, envelope })) fail("REPLAY_DETECTED", "Contact request was already received.");
            const stored = await this.store({ request, receivedRoute, receivedAt: this.now(), envelope });
            return { request: stored === undefined ? request : stored, envelope };
        }
    }

    global.ContactTransport = ContactTransport;
    global.ContactTransportError = ContactTransportError;
    if (typeof module !== "undefined") module.exports = { ContactTransport, ContactTransportError, VERSION, TYPE };
})(typeof window !== "undefined" ? window : globalThis);
