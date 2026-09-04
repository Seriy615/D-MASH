"use strict";

/*
 * CONTACT_REQUEST_V1 / CONTACT_ACCEPT_V1 opaque transport boundary.
 *
 * The destination RouteCertificate is an explicit transport input.  Never
 * confuse it with reply_route_certificate inside plaintext: encrypting a first
 * request to the sender's reply key makes the request undecryptable by the
 * destination and was the previous implementation bug.
 */
(function (global) {
    const VERSION = 1;
    const TYPE = "CONTACT_REQUEST_V1";
    const ACCEPT_TYPE = "CONTACT_ACCEPT_V1";
    const B64URL = /^[A-Za-z0-9_-]+$/;
    const ROUTE_LOCATOR = /^(?:[A-Za-z0-9_-]{43}|[0-9a-f]{64})$/;

    class ContactTransportError extends Error {
        constructor(code, message) { super(message); this.name = "ContactTransportError"; this.code = code; }
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
    const route = value => {
        if (typeof value !== "string" || !ROUTE_LOCATOR.test(value)) fail("INVALID_ROUTE_LOCATOR", "Route locator must be a canonical opaque RouteID or mesh token.");
        return value;
    };
    const certificate = value => {
        plainObject(value, "RECIPIENT_CERTIFICATE");
        if (typeof value.routeId !== "string" || !ROUTE_LOCATOR.test(value.routeId)) {
            fail("INVALID_RECIPIENT_CERTIFICATE", "Destination RouteCertificate is required.");
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
            this.encrypt = callback(encrypt, "encrypt");
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
            if (value.version !== VERSION || ![TYPE, ACCEPT_TYPE].includes(value.type) ||
                typeof value.request_id !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.request_id)) {
                fail("INVALID_ENVELOPE", "Envelope version, type, or request ID is invalid.");
            }
            return Object.freeze({ version: VERSION, type: value.type, request_id: value.request_id, ciphertext: opaque(value.ciphertext, "CIPHERTEXT") });
        }

        async deliver({ routeLocator, recipientCertificate, payload } = {}) {
            route(routeLocator);
            recipientCertificate = certificate(recipientCertificate);
            if (recipientCertificate.routeId !== routeLocator) fail("ROUTE_CERTIFICATE_MISMATCH", "Destination certificate does not match RouteID.");
            const request = this.validator.validateRequest(payload);
            const plaintext = this.validator.serializeRequest(request);
            const ciphertext = await this.encrypt({ plaintext, recipientCertificate });
            const envelope = ContactTransport.validateEnvelope({ version: VERSION, type: TYPE, request_id: request.request_id, ciphertext });
            await this.submit({ routeLocator, envelope });
            return envelope;
        }

        async deliverAccept({ routeLocator, recipientCertificate, payload, acceptedRequest } = {}) {
            route(routeLocator);
            recipientCertificate = certificate(recipientCertificate);
            if (recipientCertificate.routeId !== routeLocator) fail("ROUTE_CERTIFICATE_MISMATCH", "Destination certificate does not match RouteID.");
            if (typeof this.validator.validateAccept !== "function" || typeof this.validator.serializeAccept !== "function") {
                fail("VALIDATOR_REQUIRED", "validator accept methods are required.");
            }
            const accept = this.validator.validateAccept(payload, acceptedRequest);
            const plaintext = this.validator.serializeAccept(accept, acceptedRequest);
            const ciphertext = await this.encrypt({ plaintext, recipientCertificate });
            const envelope = ContactTransport.validateEnvelope({ version: VERSION, type: ACCEPT_TYPE, request_id: accept.request_id, ciphertext });
            await this.submit({ routeLocator, envelope });
            return envelope;
        }

        async ingest({ envelope: rawEnvelope, receivedRoute } = {}) {
            if (typeof receivedRoute !== "string" || !receivedRoute) fail("INVALID_RECEIVED_ROUTE", "Received route is invalid.");
            const envelope = ContactTransport.validateEnvelope(rawEnvelope);
            if (envelope.type !== TYPE) fail("INVALID_ENVELOPE", "Expected CONTACT_REQUEST_V1.");
            const opened = await this.decrypt({ envelope, receivedRoute });
            if (!opened || opened.authenticated !== true || opened.plaintext === undefined) fail("DECRYPT_REJECTED", "Ingress decryption did not authenticate the envelope.");
            const request = this.validator.deserializeRequest(opened.plaintext);
            if (request.request_id !== envelope.request_id) fail("REQUEST_BINDING_INVALID", "Request does not bind to its envelope.");
            if (await this.dedupe({ requestId: request.request_id, envelope })) fail("REPLAY_DETECTED", "Contact request was already received.");
            const stored = await this.store({ request, receivedRoute, receivedAt: this.now(), envelope });
            return { request: stored === undefined ? request : stored, envelope };
        }

        async ingestAccept({ envelope: rawEnvelope, receivedRoute, acceptedRequest } = {}) {
            if (typeof receivedRoute !== "string" || !receivedRoute) fail("INVALID_RECEIVED_ROUTE", "Received route is invalid.");
            const envelope = ContactTransport.validateEnvelope(rawEnvelope);
            if (envelope.type !== ACCEPT_TYPE) fail("INVALID_ENVELOPE", "Expected CONTACT_ACCEPT_V1.");
            if (typeof this.validator.deserializeAccept !== "function") fail("VALIDATOR_REQUIRED", "validator.deserializeAccept is required.");
            const opened = await this.decrypt({ envelope, receivedRoute });
            if (!opened || opened.authenticated !== true || opened.plaintext === undefined) fail("DECRYPT_REJECTED", "Ingress decryption did not authenticate the envelope.");
            const accept = this.validator.deserializeAccept(opened.plaintext, acceptedRequest);
            if (accept.request_id !== envelope.request_id) fail("REQUEST_BINDING_INVALID", "Accept does not bind to its envelope.");
            if (await this.dedupe({ requestId: accept.request_id, envelope })) fail("REPLAY_DETECTED", "Contact accept was already received.");
            const stored = await this.store({ accept, acceptedRequest, receivedRoute, receivedAt: this.now(), envelope });
            return { accept: stored === undefined ? accept : stored, envelope };
        }
    }

    global.ContactTransport = ContactTransport;
    global.ContactTransportError = ContactTransportError;
    if (typeof module !== "undefined") module.exports = { ContactTransport, ContactTransportError, VERSION, TYPE, ACCEPT_TYPE };
})(typeof window !== "undefined" ? window : globalThis);
