// Python interoperability harness, real bundled TweetNaCl and WebCrypto.
const fs = require('node:fs');
global.nacl = require('../js/vendor/nacl-fast.min.js');
const { Initiator } = require('../js/secure_session.js');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
    const signing = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(41));
    const handshake = new Initiator(signing, input.role || 'DEVICE');
    handshake.private.set(new Uint8Array(32).fill(73));
    const hello = handshake.initiate();
    if (!input.challenge) { process.stdout.write(JSON.stringify(hello)); return; }
    handshake.hello = input.hello;
    const { auth, session } = await handshake.finish(input.challenge, input.nodeId, 100);
    const frame = session.seal({ type: 'PING', text: 'Привет 🌐', number: 17 });
    const opened = input.frame ? session.open(input.frame) : null;
    process.stdout.write(JSON.stringify({ auth, frame, opened, erased: !handshake.private.some(Boolean) }));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
