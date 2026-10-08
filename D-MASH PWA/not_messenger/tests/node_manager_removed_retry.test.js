"use strict";
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const timers = new Map(); let nextTimer = 0, attempts = 0, closed = 0;
const storage = () => { const values = new Map(); return { getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key) }; };
const context = {
    URL, Map, Set, Object, Promise, Error,
    localStorage: storage(), sessionStorage: storage(),
    setTimeout: callback => { const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id), clearInterval: id => timers.delete(id),
    WebSocket: { OPEN: 1, CONNECTING: 0 },
    document: { getElementById: () => null },
    CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
    window: {
        location: { href: 'https://app.example.test/' }, dispatchEvent() {},
        Core: { device: { signing: {} } }, DeviceRoot: { state: { root: {} } },
        DeviceClientV3: class {
            constructor(options) { this.options = options; this.state = 'disconnected'; this.socket = null; }
            connect() {
                attempts++; this.state = 'connecting'; this.socket = { readyState: 3, close: () => {} };
                return new Promise(() => {});
            }
            fail(error) { if (this.state === 'disconnected') return; this.state = 'disconnected'; this.options.onClose(error); }
            close() { closed++; this.fail(new Error('closed')); }
        }
    }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(require.resolve('../js/node_manager.js'), 'utf8'), context);
const manager = context.window.NodeManager;
const endpoint = manager.add('wss://127.0.0.1:65001/dmp-c/v3');
const first = manager.connectEndpoint(endpoint);
first.client.fail(new Error('offline'));
assert.equal(timers.size, 1, 'offline Node retains intentional retry');
const replacedCallback = [...timers.values()][0];
manager.connectEndpoint(endpoint);
assert.equal(attempts, 2, 'manual retry opens a new connection');
assert.equal(timers.size, 0, 'manual retry cancels the old timer');
assert.equal(closed, 1, 'replaced client is closed');
replacedCallback();
assert.equal(attempts, 2, 'a queued callback from the replaced connection cannot open another socket');
const second = manager.connections.get(endpoint.url);
second.client.fail(new Error('offline'));
assert.equal(timers.size, 1, 'new connection still retries when unavailable');
const staleCallback = [...timers.values()][0];
manager.remove(endpoint.url);
assert.equal(timers.size, 0, 'Delete cancels the current timer');
staleCallback();
assert.equal(attempts, 2, 'even an already queued timer cannot resurrect a removed Node');
assert.equal(manager.connections.size, 0);
const retained = manager.add('wss://127.0.0.1:65002/dmp-c/v3');
manager.connectEndpoint(retained).client.fail(new Error('offline'));
const retry = [...timers.values()][0];
retry();
assert.equal(attempts, 4, 'a saved Node still reconnects');
assert.equal(manager.connections.get(retained.url).state, 'connecting');
const direct = new context.window.NodeEndpoint('wss://127.0.0.1:65003/dmp-c/v3');
const directConnection = manager.connectEndpoint(direct);
assert.equal(directConnection, manager.connections.get(direct.url), 'directly supplied endpoint still connects');
directConnection.client.fail(new Error('offline'));
const directRetry = [...timers.values()].at(-1);
manager.remove(direct.url);
directRetry();
assert.equal(attempts, 5, 'removed direct endpoint also cannot reconnect');
console.log('NodeManager removed retry: all assertions passed');
