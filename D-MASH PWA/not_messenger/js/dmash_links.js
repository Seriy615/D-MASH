"use strict";

/*
 * Canonical, fragment-only D-MASH share links.
 *
 * Node:    #/node/<base64url(JSON)>
 * Contact: #/c/<base64url(JSON)>
 *
 * The compact descriptor fields are deliberately fixed.  The parser requires
 * the exact canonical JSON/base64url representation so a QR payload has one
 * unambiguous spelling and cannot smuggle unsupported future fields.
 */
(function (global) {
    const VERSION = 1;
    const NODE_PREFIX = "#/node/";
    const CONTACT_PREFIX = "#/c/";
    const HEX_32 = /^[0-9a-f]{64}$/;
    const B64URL = /^[A-Za-z0-9_-]+$/;
    const MAX_LABEL_LENGTH = 120;
    const MAX_CAPABILITIES = 32;
    const MAX_CAPABILITY_LENGTH = 64;

    class DmashLinkError extends Error {
        constructor(message) { super(message); this.name = "DmashLinkError"; }
    }

    const fail = message => { throw new DmashLinkError(message); };
    const utf8 = new TextEncoder();
    const decoder = new TextDecoder("utf-8", { fatal: true });

    function bytesToBase64(bytes) {
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return btoa(binary);
    }

    function base64ToBytes(value) {
        const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
        try {
            const binary = atob(padded);
            return Uint8Array.from(binary, character => character.charCodeAt(0));
        } catch (_) {
            return fail("Descriptor is not valid base64url.");
        }
    }

    function encodeDescriptor(value) {
        return bytesToBase64(utf8.encode(JSON.stringify(value)))
            .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    }

    function decodeDescriptor(uri, prefix) {
        if (typeof uri !== "string" || !uri.startsWith(prefix)) fail("D-MASH link must be a fragment-only URI.");
        const encoded = uri.slice(prefix.length);
        if (!encoded || !B64URL.test(encoded) || encoded.includes("=")) fail("Descriptor is not valid base64url.");
        let descriptor;
        try { descriptor = JSON.parse(decoder.decode(base64ToBytes(encoded.replaceAll("-", "+").replaceAll("_", "/")))); }
        catch (_) { fail("Descriptor is not valid UTF-8 JSON."); }
        if (!isPlainObject(descriptor)) fail("Descriptor must be an object.");
        return { descriptor, encoded };
    }

    function isPlainObject(value) {
        return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
    }

    function requireOnlyKeys(value, keys) {
        if (Object.keys(value).some(key => !keys.includes(key))) fail("Descriptor contains unsupported fields.");
    }

    function nodeId(value, field = "NodeID") {
        if (typeof value !== "string" || !HEX_32.test(value)) fail(`${field} must be a lowercase 32-byte hexadecimal value.`);
        return value;
    }

    function optionalLabel(value) {
        if (value === undefined) return undefined;
        if (typeof value !== "string" || !value || value.length > MAX_LABEL_LENGTH || /[\u0000-\u001f\u007f]/.test(value)) fail("Label is invalid.");
        return value;
    }

    function capabilities(value) {
        if (value === undefined) return undefined;
        if (!Array.isArray(value) || value.length > MAX_CAPABILITIES || new Set(value).size !== value.length ||
            value.some(item => typeof item !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(item) || item.length > MAX_CAPABILITY_LENGTH)) {
            fail("Capabilities are invalid.");
        }
        return value.slice();
    }

    function safeEndpoint(value) {
        if (typeof value !== "string" || !value || value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) fail("Node endpoint is invalid.");
        let url;
        try { url = new URL(value); } catch (_) { fail("Node endpoint is invalid."); }
        if (!["wss:", "ws:"].includes(url.protocol) || !url.hostname ||
            url.username || url.password || url.search || url.hash) fail("Node endpoint is unsafe.");
        const host = url.hostname.toLowerCase();
        if (url.protocol === "ws:" && host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]") {
            fail("Unencrypted node endpoints are allowed only on localhost.");
        }
        return url.href;
    }

    function expectedNodeId(value) {
        if (value === undefined || value === null) return null;
        const expected = typeof value === "string" ? value : value.expectedNodeId;
        return nodeId(expected, "Expected NodeID");
    }

    function canonicalNode(input) {
        if (!isPlainObject(input)) fail("Node descriptor must be an object.");
        requireOnlyKeys(input, ["v", "e", "n", "l", "c"]);
        if (input.v !== VERSION) fail("Unsupported node descriptor version.");
        const result = { v: VERSION, e: safeEndpoint(input.e), n: nodeId(input.n) };
        const label = optionalLabel(input.l); if (label !== undefined) result.l = label;
        const caps = capabilities(input.c); if (caps !== undefined) result.c = caps;
        return result;
    }

    function canonicalContact(input) {
        if (!isPlainObject(input)) fail("Contact descriptor must be an object.");
        requireOnlyKeys(input, ["v", "i", "p", "l"]);
        if (input.v !== VERSION) fail("Unsupported contact descriptor version.");
        const result = { v: VERSION, i: nodeId(input.i, "Contact ID"), p: nodeId(input.p, "Pairing contribution") };
        const label = optionalLabel(input.l); if (label !== undefined) result.l = label;
        return result;
    }

    function assertCanonical(encoded, descriptor) {
        if (encodeDescriptor(descriptor) !== encoded) fail("Descriptor is not canonically encoded.");
    }

    function serializeDmashNodeUri(descriptor) { return NODE_PREFIX + encodeDescriptor(canonicalNode(descriptor)); }
    function serializeDmashContactUri(descriptor) { return CONTACT_PREFIX + encodeDescriptor(canonicalContact(descriptor)); }

    function parseDmashNodeUri(uri, options) {
        const { descriptor, encoded } = decodeDescriptor(uri, NODE_PREFIX);
        const result = canonicalNode(descriptor);
        assertCanonical(encoded, result);
        const expected = expectedNodeId(options);
        if (expected && result.n !== expected) fail("Node descriptor does not match the expected NodeID.");
        return result;
    }

    function parseDmashContactUri(uri) {
        const { descriptor, encoded } = decodeDescriptor(uri, CONTACT_PREFIX);
        const result = canonicalContact(descriptor);
        assertCanonical(encoded, result);
        return result;
    }

    const api = Object.freeze({
        DmashLinkError, parseDmashNodeUri, serializeDmashNodeUri, parseDmashContactUri, serializeDmashContactUri
    });
    Object.assign(global, api);
    if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
