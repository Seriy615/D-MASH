// Local history encryption. Transport keys and packets are unaffected.
(function (global) {
    'use strict';
    const hex = value => Array.from(value, x => x.toString(16).padStart(2, '0')).join('');
    const bytes = (value, length) => {
        if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(value) || (length && value.length !== length * 2)) throw Error('Invalid chat ciphertext');
        return Uint8Array.from(value.match(/../g), x => parseInt(x, 16));
    };
    const text = value => new TextEncoder().encode(value);
    async function wrappingKey(masterKey, password, salt, alias) {
        if (!masterKey || !password || password.length > 1024) throw Error('Введите пароль (до 1024 символов)');
        // Combine password-stretched material with a domain-specific vault-key output.
        // A fresh 256-bit salt supplies the nonce; repeated unlock attempts
        // encrypt exactly the same fixed plaintext under that nonce.
        const input = await crypto.subtle.importKey('raw', text(password), 'PBKDF2', false, ['deriveBits']);
        const stretched = new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2', hash:'SHA-256', iterations:600000,
            salt:bytes(salt, 32)}, input, 256));
        let combined;
        try {
            combined = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv:bytes(salt,32).slice(0,12),
                additionalData:text('D-MASH|LOCAL-CHAT|V1|COMBINE|' + alias)}, masterKey, text('local-chat-domain')));
            const mixed = new Uint8Array(stretched.length + combined.length);
            mixed.set(stretched); mixed.set(combined, stretched.length);
            const material = await crypto.subtle.importKey('raw', mixed, 'HKDF', false, ['deriveKey']);
            mixed.fill(0);
            return await crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt:bytes(salt,32),
                info:text('D-MASH|LOCAL-CHAT|V1|WRAP|' + alias)}, material, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
        } finally {stretched.fill(0); combined?.fill(0);}
    }
    async function wrap(master, password, secret, alias) {
        const publicKey = hex(global.nacl.box.keyPair.fromSecretKey(secret).publicKey);
        const salt = hex(crypto.getRandomValues(new Uint8Array(32))), iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await wrappingKey(master, password, salt, alias);
        const cipher = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text(alias + '|' + publicKey)}, key, secret);
        const domain = await crypto.subtle.encrypt({name:'AES-GCM',iv:new Uint8Array(12),
            additionalData:text('D-MASH|LOCAL-CHAT|V1|ALIAS|' + alias)},key,new Uint8Array(16));
        const aliasEntropy = hex(new Uint8Array(await crypto.subtle.digest('SHA-256',domain)));
        return {version:1, salt, iv:hex(iv), publicKey, aliasEntropy, wrapped:hex(new Uint8Array(cipher))};
    }
    async function unwrap(master, password, record, alias) {
        if (record?.version !== 1) throw Error('Invalid chat encryption version');
        bytes(record.publicKey,32);
        const key = await wrappingKey(master, password, record.salt, alias);
        const secret = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(record.iv,12),
            additionalData:text(alias + '|' + record.publicKey)}, key, bytes(record.wrapped,48)));
        if (hex(global.nacl.box.keyPair.fromSecretKey(secret).publicKey) !== record.publicKey) {secret.fill(0); throw Error('Invalid chat key');}
        return secret;
    }
    function seal(value, record) {
        const ephemeral = global.nacl.box.keyPair(), nonce = global.nacl.randomBytes(24);
        try {return {chatCipher:1, ephemeral:hex(ephemeral.publicKey), nonce:hex(nonce),
            cipher:hex(global.nacl.box(text(JSON.stringify(value)),nonce,bytes(record.publicKey,32),ephemeral.secretKey))};}
        finally {ephemeral.secretKey.fill(0);}
    }
    function open(value, secret) {
        if (value?.chatCipher !== 1) throw Error('Protected history contains unencrypted data');
        const plain = global.nacl.box.open(bytes(value.cipher),bytes(value.nonce,24),bytes(value.ephemeral,32),secret);
        if (!plain) throw Error('Chat decryption failed');
        try {return JSON.parse(new TextDecoder().decode(plain));} finally {plain.fill(0);}
    }
    global.DmashChatCipher = Object.freeze({wrap,unwrap,seal,open});
})(typeof window === 'undefined' ? globalThis : window);
