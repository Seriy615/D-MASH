'use strict';
(function (global) {
    const text = value => new TextEncoder().encode(value);
    const hex = value => Array.from(value, b => b.toString(16).padStart(2, '0')).join('');
    const unhex = value => Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
    const derive = (key, context) => global.DmashSecureSession.hkdf(key, new Uint8Array(32), text(context), 32);
    async function locator(publicKey) {
        const prefix = text('D-MASH|PRIVATE-LOCATOR|V3\0');
        const input = new Uint8Array(prefix.length + 32); input.set(prefix); input.set(publicKey, prefix.length);
        return hex(new Uint8Array(await global.crypto.subtle.digest('SHA-256', input)));
    }
    async function direction(root, label, generation) {
        const seed = await derive(root, `D-MASH|PRIVATE-ROUTE-AUTHORITY|V3|${label}|${generation}`);
        const boxSeed = await derive(root, `D-MASH|PRIVATE-ROUTE-DEVICE-BOX|V3|${label}|${generation}`);
        let signing, box;
        try {
            signing = global.nacl.sign.keyPair.fromSeed(seed);
            box = global.nacl.box.keyPair.fromSecretKey(boxSeed);
            const routeId = await locator(signing.publicKey);
            return {routeId, signing, box};
        } catch (error) { signing?.secretKey.fill(0); box?.secretKey.fill(0); throw error; }
        finally { seed.fill(0); boxSeed.fill(0); }
    }
    async function pair(ownContribution, peerContribution, generation = 1) {
        if (![ownContribution, peerContribution].every(value => typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)) ||
            !Number.isSafeInteger(generation) || generation < 1) throw Error('Invalid private route material');
        const own = ownContribution.toLowerCase(), peer = peerContribution.toLowerCase();
        if (own === peer) throw Error('Pairing contributions must differ');
        const sorted = [own, peer].sort();
        const ikm = new Uint8Array(64); ikm.set(unhex(sorted[0])); ikm.set(unhex(sorted[1]), 32);
        let root, incoming, outgoing;
        try {
            root = await derive(ikm, 'D-MASH|ROUTING_ROOT|V1');
            const forward = own === sorted[0] ? 'A_TO_B' : 'B_TO_A';
            outgoing = await direction(root, forward, generation);
            incoming = await direction(root, forward === 'A_TO_B' ? 'B_TO_A' : 'A_TO_B', generation);
            return {version: 3, generation, routeLocator: outgoing.routeId, backRouteLocator: incoming.routeId,
                incoming, outgoing, close() {
                    for (const route of [incoming, outgoing]) { route.signing.secretKey.fill(0); route.box.secretKey.fill(0); }
                }};
        } catch (error) {
            for (const route of [incoming, outgoing]) { route?.signing.secretKey.fill(0); route?.box.secretKey.fill(0); }
            throw error;
        } finally { ikm.fill(0); root?.fill(0); }
    }
    global.PrivateRoutesV3 = Object.freeze({pair, locator});
    if (typeof module !== 'undefined') module.exports = global.PrivateRoutesV3;
})(typeof window !== 'undefined' ? window : globalThis);
