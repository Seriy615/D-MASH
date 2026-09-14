const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
global.crypto ||= nodeCrypto.webcrypto;
global.window = global;
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/account_ratchet.js');
require('../js/account_ratchet_runtime.js');

const Runtime = global.DmashAccountRatchetRuntime;
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const fromHex = value => Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
const root = new Uint8Array(32).fill(0x42);
const senderKeys = global.nacl.sign.keyPair();
const recipientKeys = global.nacl.sign.keyPair();
const sender = {keys: {pub_hex: hex(senderKeys.publicKey), sign: {secretKey: senderKeys.secretKey}},
    bytesToHex: hex, hexToBytes: fromHex};
const recipient = {keys: {pub_hex: hex(recipientKeys.publicKey), sign: {secretKey: recipientKeys.secretKey}},
    bytesToHex: hex, hexToBytes: fromHex};
const senderSecrets = {ratchetRoot: hex(root), ratchetEpoch: 1};
const recipientSecrets = {ratchetRoot: hex(root), ratchetEpoch: 1};

(async () => {
    const packet = await Runtime.encryptPacket(sender, JSON.stringify({type: 'dmash_message', body: 'ratchet'}),
        hex(recipientKeys.publicKey), senderSecrets);
    const opened = await Runtime.decryptPacket(recipient, fromHex(packet), hex(senderKeys.publicKey), recipientSecrets);
    assert.equal(opened, JSON.stringify({type: 'dmash_message', body: 'ratchet'}));
    assert.equal(packet.slice(0, 2), '04');
    console.log('account_ratchet_runtime.test.js: authenticated epoch packet round-trip passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
