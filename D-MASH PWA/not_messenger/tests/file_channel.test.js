const assert = require('node:assert/strict');
require('../js/file_channel.js');
const {FileChannel, describe, MAX_SIZE} = DmashFileChannel;
function pair(transform = value => value) {
    const a = {readyState: 'open', bufferedAmount: 0}, b = {...a};
    a.send = frame => {const data = transform(structuredClone(frame)); if (data) queueMicrotask(() => b.onmessage?.({data}));};
    b.send = frame => {queueMicrotask(() => a.onmessage?.({data: structuredClone(frame)}));};
    for (const [self, other] of [[a,b],[b,a]]) self.close = () => {
        if (self.readyState === 'closed') return;
        self.readyState = other.readyState = 'closed'; queueMicrotask(() => {self.onclose?.(); other.onclose?.();});
    };
    return [a,b];
}
const deferred = () => {let resolve; const promise = new Promise(r => {resolve=r;}); return {promise, resolve};};
async function transfer(file, manifest, transform) {
    const [a,b] = pair(transform), sent = deferred(), received = deferred(), errors = [];
    const receiver = new FileChannel({channel: b, manifest, onComplete: blob => received.resolve(blob),
        onError: e => {errors.push(e); received.resolve(null);}});
    const sender = new FileChannel({channel: a, manifest, file, onComplete: () => sent.resolve(true),
        onError: e => {errors.push(e); sent.resolve(false);}});
    const result = await Promise.all([sent.promise, received.promise]);
    sender.close(); receiver.close(); return {result, errors, sender, receiver};
}
(async () => {
    const content = new Uint8Array(3 * 32768 + 13); content.forEach((_,i) => {content[i] = i % 251;});
    const file = new File([content], 'private.bin', {type:'application/octet-stream'});
    const manifest = await describe(file, 'a'.repeat(64));
    const normal = await transfer(file, manifest);
    assert(normal.result[0]); assert.equal(normal.errors.length, 0);
    assert.deepEqual(new Uint8Array(await normal.result[1].arrayBuffer()), content);
    assert.equal(normal.receiver.parts.length, 0);
    assert.equal(normal.sender.manifest.key, null);
    let damaged = false;
    const tampered = await transfer(file, manifest, frame => {
        if (!damaged) {new Uint8Array(frame)[20] ^= 1; damaged = true;} return frame;
    });
    assert.equal(tampered.result[0], false); assert.equal(tampered.result[1], null);
    assert(tampered.errors.length > 0);
    const reordered = await transfer(file, manifest, frame => {new DataView(frame).setUint32(0, 12); return frame;});
    assert.equal(reordered.result[1], null);
    const wrongHash = await transfer(file, {...manifest, sha256:'b'.repeat(64)});
    assert.equal(wrongHash.result[1], null, 'Authenticated chunks do not bypass whole-file hash');

    const [a,b] = pair(() => null);
    const cancelled = deferred();
    const sender = new FileChannel({channel:a, manifest, file, onError: () => cancelled.resolve()});
    while (!sender.pending) await new Promise(r => setTimeout(r, 1));
    a.close(); await cancelled.promise;
    assert(sender.closed); assert.equal(sender.pending, null);
    await assert.rejects(describe({size:MAX_SIZE + 1}, 'a'.repeat(64)));
    console.log('file_channel.test.js: integrity, ordering, bounds and cancellation passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
