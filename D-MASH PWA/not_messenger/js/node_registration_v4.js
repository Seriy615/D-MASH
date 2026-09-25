'use strict';
// Pure transcript/validation contract. No route or mailbox authority is granted.
(function(global) {
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
    const field = (value, length) => {
        if (typeof value !== 'string' || !(new RegExp('^[0-9a-f]{'+length+'}$')).test(value)) throw Error('Invalid registration field');
        return value;
    };
    const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
    function resource(issuer, recipient, dnss, transcriptHash) {
        field(issuer,64); field(recipient,64); field(dnss,32);
        if (issuer === recipient || !(transcriptHash instanceof Uint8Array) || transcriptHash.length !== 32) throw Error('Invalid registration context');
        return ['D-MASH','NODE-DNSS','V4',issuer,recipient,dnss,hex(transcriptHash)].join('|');
    }
    function verifyRegistration(session, request, difficulty, {now = Math.floor(Date.now()/1000), expectedDnss = null} = {}) {
        try {
            if (session.version !== 4 || session.closed || session.localRole !== 'NODE' || session.peerRole !== 'NODE' ||
                !Number.isInteger(difficulty) || difficulty < 20 || difficulty > 24 || !Number.isSafeInteger(now)) return false;
            if (!exact(request,'dnss,pow,type') || request.type !== 'NODE_REGISTER') return false;
            field(request.dnss,32);
            if (expectedDnss !== null && request.dnss !== field(expectedDnss,32)) return false;
            const work = resource(session.peerId,session.localId,request.dnss,session.transcriptHash);
            const p = request.pow;
            if (!exact(p,'difficulty,digest,expires_at,nonce,resource,type,v') || p.v !== 1 || p.type !== 'DNSS' || p.resource !== work ||
                p.difficulty !== difficulty || !Number.isSafeInteger(p.expires_at) || p.expires_at <= now || p.expires_at > now+180 ||
                !Number.isSafeInteger(p.nonce) || p.nonce < 0) return false;
            field(p.digest,64);
            const digest = global.DmashResourcePow.activationDigest(session.localId,'DNSS',session.peerId,work,p.nonce,p.expires_at);
            return hex(digest) === p.digest && global.DmashResourcePow.leadingZeroBits(digest) >= difficulty;
        } catch (_) { return false; }
    }
    global.DmashNodeRegistrationV4 = Object.freeze({resource,verifyRegistration});
    if (typeof module !== 'undefined') module.exports = global.DmashNodeRegistrationV4;
})(typeof window !== 'undefined' ? window : globalThis);
