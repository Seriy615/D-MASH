const assert = require('node:assert/strict');
require('../js/call_signaling.js');
const {WebSocketSignaling: Transport, validEndpoint} = globalThis.DmashCallSignaling;
class Socket {
    constructor() { this.readyState = 1; this.bufferedAmount = 0; queueMicrotask(() => this.onopen()); }
    send(value) { this.sent = value; }
    close() { this.readyState = 3; }
    receive(value) { this.onmessage({data: JSON.stringify(value)}); }
}
(async () => {
    for (const endpoint of ['ws://remote.test/signal', 'https://remote.test/signal',
        'wss://user:secret@remote.test/signal', 'wss://remote.test/signal?ticket=secret', 'wss://remote.test/#secret']) {
        assert.throws(() => validEndpoint(endpoint));
    }
    assert.equal(validEndpoint('ws://127.0.0.1/signal'), 'ws://127.0.0.1/signal');
    const transport = new Transport({endpoint: 'wss://example.test/signal', WebSocket: Socket});
    await transport.connect();
    transport.socket.receive({type: 'ice', payload: 'first'});
    transport.socket.receive({type: 'ice', payload: 'second'});
    assert(transport.queueBytes > 0);
    assert.equal((await transport.next()).payload, 'first');
    assert.equal((await transport.next()).payload, 'second');
    assert.equal(transport.queueBytes, 0);
    const pending = transport.next();
    await assert.rejects(transport.next(), /Concurrent/);
    transport.close();
    await assert.rejects(pending, /closed/);
    await assert.rejects(transport.connect(), /closed/);
    assert.equal(transport.socket.readyState, 3);

    const bounded = new Transport({endpoint: 'wss://example.test/signal', WebSocket: Socket});
    await bounded.connect();
    for (let i = 0; i < 5; i++) bounded.socket.receive({type: 'ice', payload: 'x'.repeat(256 * 1024)});
    assert(bounded.closed, 'Aggregate byte budget applies before 128-message cap');
    assert.equal(bounded.queue.length, 0);
    assert.equal(bounded.queueBytes, 0);
    console.log('call_signaling.test.js: ok');
})().catch(error => { console.error(error); process.exitCode = 1; });
