'use strict';
(function (global) {
    const codec = () => global.DmashSecureSession;
    const text = value => new TextEncoder().encode(value);
    const unhex = value => Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
    const hex = value => Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('');
    const urlBytes = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const transcript = body => text('D-MASH|CONTACT-BOOTSTRAP|V3\0' + codec().canonical(body));
    const routeTranscript = (body, signature) => text('D-MASH|CONTACT-ROUTE-BINDING|V3\0' + codec().canonical({body, account_signature: signature}));
    const fields = ['version', 'phase', 'request_id', 'recipient_route_id', 'route_certificate', 'account_bundle',
        'contribution', 'display_name', 'created_at', 'expires_at', 'accept_hash'];
    function validate(body, now) {
        if (!body || Object.keys(body).sort().join(',') !== fields.slice().sort().join(',') || body.version !== 3 ||
            !['ACCEPT', 'CONFIRM'].includes(body.phase) || !/^[A-Za-z0-9_-]{43}$/.test(body.request_id || '') ||
            !/^[A-Za-z0-9_-]{43}$/.test(body.recipient_route_id || '') ||
            !global.DeviceRoutes.verifyCertificate(body.route_certificate) ||
            !/^[0-9a-f]{2496}$/.test(body.account_bundle || '') || !/^[0-9a-f]{64}$/.test(body.contribution || '') ||
            typeof body.display_name !== 'string' || !body.display_name.trim() || body.display_name.length > 128 ||
            /[\u0000-\u001f\u007f]/.test(body.display_name) ||
            !Number.isSafeInteger(body.created_at) || !Number.isSafeInteger(body.expires_at) ||
            body.created_at > now + 60 || body.created_at < 0 || body.expires_at <= now ||
            body.expires_at <= body.created_at || body.expires_at - body.created_at > 86400 ||
            (body.phase === 'ACCEPT' ? body.accept_hash !== null : !/^[0-9a-f]{64}$/.test(body.accept_hash || ''))) {
            throw Error('Invalid contact bootstrap');
        }
        return body;
    }
    function create(body, accountSigning, routeSigning, now = Math.floor(Date.now() / 1000)) {
        body = JSON.parse(codec().canonical(body));
        validate(body, now);
        if (hex(accountSigning.publicKey) !== body.account_bundle.slice(0, 64) ||
            hex(routeSigning.publicKey) !== hex(urlBytes(body.route_certificate.signingPublicKey))) throw Error('Contact signing key mismatch');
        const account_signature = codec().b64(global.nacl.sign.detached(transcript(body), accountSigning.secretKey));
        return {body, account_signature,
            route_signature: codec().b64(global.nacl.sign.detached(routeTranscript(body, account_signature), routeSigning.secretKey))};
    }
    function verify(message, {requestId, recipientRouteId, senderRouteId, phase, acceptHash = null,
                             now = Math.floor(Date.now() / 1000)} = {}) {
        if (!message || Object.keys(message).sort().join(',') !== 'account_signature,body,route_signature') throw Error('Invalid bootstrap signatures');
        const body = validate(message.body, now);
        if (body.request_id !== requestId || body.recipient_route_id !== recipientRouteId ||
            body.route_certificate.routeId !== senderRouteId || body.phase !== phase || body.accept_hash !== acceptHash) throw Error('Contact bootstrap context mismatch');
        if (!global.nacl.sign.detached.verify(transcript(body), codec().unb64(message.account_signature, 64), unhex(body.account_bundle.slice(0, 64))) ||
            !global.nacl.sign.detached.verify(routeTranscript(body, message.account_signature), codec().unb64(message.route_signature, 64), urlBytes(body.route_certificate.signingPublicKey))) throw Error('Contact bootstrap signature rejected');
        return JSON.parse(codec().canonical(body));
    }
    async function digest(message) {
        return hex(new Uint8Array(await global.crypto.subtle.digest('SHA-256', text('D-MASH|CONTACT-ACCEPT-HASH|V3\0' + codec().canonical(message)))));
    }
    global.ContactBootstrapV3 = Object.freeze({create, verify, digest});
    if (typeof module !== 'undefined') module.exports = global.ContactBootstrapV3;
})(typeof window !== 'undefined' ? window : globalThis);
