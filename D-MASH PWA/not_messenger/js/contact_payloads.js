"use strict";

/*
 * CONTACT_REQUEST_V1 / CONTACT_ACCEPT_V1 wire payloads.
 *
 * These functions deliberately operate on plaintext payloads only.  Transport
 * encryption is responsible for ensuring requests and accepts stay opaque to
 * nodes.  The request schema has no Account-related field; an Account public
 * key is released only by a validated accept associated with that request.
 */
(function (global) {
    const VERSION = 1;
    const REQUEST_TYPE = "CONTACT_REQUEST_V1";
    const ACCEPT_TYPE = "CONTACT_ACCEPT_V1";
    const B64URL = /^[A-Za-z0-9_-]+$/;
    const HEX_32 = /^[0-9a-f]{64}$/;
    const encoder = new TextEncoder();

    class ContactPayloadError extends Error {
        constructor(code, message) { super(message); this.name = "ContactPayloadError"; this.code = code; }
    }
    const fail = (code, message) => { throw new ContactPayloadError(code, message); };
    const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
    const object = (value, name) => {
        if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
            fail("INVALID_" + name.toUpperCase(), name + " must be a plain object.");
        }
        return value;
    };
    const exactKeys = (value, keys, name) => {
        const actual = Object.keys(value).sort();
        const expected = [...keys].sort();
        if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
            fail("INVALID_" + name.toUpperCase(), name + " has missing or unsupported fields.");
        }
    };
    const string = (value, name, max, { allowEmpty = false } = {}) => {
        if (typeof value !== "string" || (!allowEmpty && !value) || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) {
            fail("INVALID_" + name.toUpperCase(), name + " is invalid.");
        }
        return value;
    };
    const b64url32 = (value, name) => {
        string(value, name, 43);
        if (!B64URL.test(value) || value.length !== 43) fail("INVALID_" + name.toUpperCase(), name + " must be an unpadded 32-byte base64url public key.");
        return value;
    };
    const opaque = (value, name) => {
        string(value, name, 16384);
        if (!B64URL.test(value)) fail("INVALID_" + name.toUpperCase(), name + " must be unpadded base64url data.");
        return value;
    };
    const requestId = (value) => b64url32(value, "request_id");
    const capabilities = (value) => {
        if (!Array.isArray(value) || !value.length || value.length > 32 || value.some((item) => typeof item !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(item))) {
            fail("INVALID_PROTOCOL_CAPABILITIES", "protocol_capabilities must be a non-empty list of protocol tokens.");
        }
        const canonical = [...new Set(value)].sort();
        if (canonical.length !== value.length || canonical.some((item, index) => item !== value[index])) {
            fail("NON_CANONICAL_PROTOCOL_CAPABILITIES", "protocol_capabilities must be sorted and duplicate-free.");
        }
        return canonical;
    };
    const routeCertificate = (value) => {
        object(value, "reply_route_certificate");
        exactKeys(value, ["version", "routeId", "signingPublicKey", "boxPublicKey", "issuedAt", "signature"], "reply_route_certificate");
        if (value.version !== VERSION || !Number.isSafeInteger(value.issuedAt) || value.issuedAt < 0) {
            fail("INVALID_REPLY_ROUTE_CERTIFICATE", "reply_route_certificate version or issue time is invalid.");
        }
        b64url32(value.routeId, "reply_route_certificate.routeId");
        b64url32(value.signingPublicKey, "reply_route_certificate.signingPublicKey");
        b64url32(value.boxPublicKey, "reply_route_certificate.boxPublicKey");
        if (value.routeId !== value.signingPublicKey) fail("INVALID_REPLY_ROUTE_CERTIFICATE", "Reply RouteID must equal its signing public key.");
        string(value.signature, "reply_route_certificate.signature", 86);
        if (!B64URL.test(value.signature) || value.signature.length !== 86) fail("INVALID_REPLY_ROUTE_CERTIFICATE", "Reply route signature is invalid.");
        return { version: VERSION, routeId: value.routeId, signingPublicKey: value.signingPublicKey, boxPublicKey: value.boxPublicKey, issuedAt: value.issuedAt, signature: value.signature };
    };
    const canonicalJson = (value) => JSON.stringify(value);
    const parse = (bytes, name) => {
        if (typeof bytes !== "string" && !(bytes instanceof Uint8Array)) fail("INVALID_SERIALIZED_" + name, "Serialized " + name + " must be UTF-8 text or bytes.");
        let source;
        try { source = typeof bytes === "string" ? bytes : new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
        catch (_) { fail("INVALID_SERIALIZED_" + name, "Serialized " + name + " is not valid UTF-8."); }
        let value;
        try { value = JSON.parse(source); } catch (_) { fail("INVALID_SERIALIZED_" + name, "Serialized " + name + " is not valid JSON."); }
        return { value, source };
    };

    const ContactPayloads = {
        VERSION,
        REQUEST_TYPE,
        ACCEPT_TYPE,
        validateRequest(payload) {
            object(payload, "contact_request");
            exactKeys(payload, ["type", "version", "request_id", "sender_display_name", "intro_message", "reply_route_certificate", "bootstrap_encryption_public", "protocol_capabilities"], "contact_request");
            if (payload.type !== REQUEST_TYPE || payload.version !== VERSION) fail("INVALID_CONTACT_REQUEST", "Unsupported contact request type or version.");
            const result = {
                type: REQUEST_TYPE, version: VERSION, request_id: requestId(payload.request_id),
                sender_display_name: string(payload.sender_display_name, "sender_display_name", 128),
                intro_message: string(payload.intro_message, "intro_message", 4096, { allowEmpty: true }),
                reply_route_certificate: routeCertificate(payload.reply_route_certificate),
                bootstrap_encryption_public: b64url32(payload.bootstrap_encryption_public, "bootstrap_encryption_public"),
                protocol_capabilities: capabilities(payload.protocol_capabilities)
            };
            return Object.freeze(result);
        },
        serializeRequest(payload) { return encoder.encode(canonicalJson(this.validateRequest(payload))); },
        deserializeRequest(bytes) {
            const { value, source } = parse(bytes, "CONTACT_REQUEST_V1"); const payload = this.validateRequest(value);
            if (source !== canonicalJson(payload)) fail("NON_CANONICAL_CONTACT_REQUEST", "CONTACT_REQUEST_V1 JSON is not canonical.");
            return payload;
        },
        validateAccept(payload, acceptedRequest) {
            const request = this.validateRequest(acceptedRequest);
            object(payload, "contact_accept");
            exactKeys(payload, ["type", "version", "request_id", "my_display_name", "selected_account_public_key", "account_handshake_material", "established_private_route_bootstrap"], "contact_accept");
            if (payload.type !== ACCEPT_TYPE || payload.version !== VERSION || requestId(payload.request_id) !== request.request_id) {
                fail("INVALID_CONTACT_ACCEPT", "Accept must explicitly reference the accepted CONTACT_REQUEST_V1.");
            }
            if (typeof payload.selected_account_public_key !== "string" || !HEX_32.test(payload.selected_account_public_key)) {
                fail("INVALID_SELECTED_ACCOUNT_PUBLIC_KEY", "selected_account_public_key must be an explicit lowercase 32-byte Account public key.");
            }
            return Object.freeze({
                type: ACCEPT_TYPE, version: VERSION, request_id: request.request_id,
                my_display_name: string(payload.my_display_name, "my_display_name", 128),
                selected_account_public_key: payload.selected_account_public_key,
                account_handshake_material: opaque(payload.account_handshake_material, "account_handshake_material"),
                established_private_route_bootstrap: opaque(payload.established_private_route_bootstrap, "established_private_route_bootstrap")
            });
        },
        serializeAccept(payload, acceptedRequest) { return encoder.encode(canonicalJson(this.validateAccept(payload, acceptedRequest))); },
        deserializeAccept(bytes, acceptedRequest) {
            const { value, source } = parse(bytes, "CONTACT_ACCEPT_V1"); const payload = this.validateAccept(value, acceptedRequest);
            if (source !== canonicalJson(payload)) fail("NON_CANONICAL_CONTACT_ACCEPT", "CONTACT_ACCEPT_V1 JSON is not canonical.");
            return payload;
        }
    };

    global.ContactPayloads = ContactPayloads;
    global.ContactPayloadError = ContactPayloadError;
    if (typeof module !== "undefined") module.exports = { ContactPayloads, ContactPayloadError };
})(typeof window !== "undefined" ? window : globalThis);
