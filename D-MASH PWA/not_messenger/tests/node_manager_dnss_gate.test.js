'use strict';
const assert = require('node:assert/strict');

global.window = global;
global.location = {href: 'http://127.0.0.1/'};
global.WebSocket = {OPEN: 1};
global.localStorage = {getItem: () => null, setItem: () => {}, removeItem: () => {}};
global.sessionStorage = {getItem: () => null, setItem: () => {}, removeItem: () => {}};
global.document = {getElementById: () => null};
require('../js/node_manager.js');

(async () => {
    let pulls = 0;
    NodeManager.connections = new Map();
    NodeManager._deviceInboxV3 = {
        async canPull() { return true; },
        async stageTransport() {},
        async drainTransport() { return {processed: 0}; },
        async drain() { return {processed: 0}; }
    };
    const pending = {
        state: 'connected', socket: {readyState: 1},
        client: {request: async () => { pulls++; return {type: 'MAILBOX_DRAIN_RESULT', entries: []}; }},
        capabilities: new Set(['PULL']), dnssReadyState: 'pending', nodeId: 'aa'.repeat(32)
    };
    NodeManager.connections.set('pending', pending);
    const deferred = await NodeManager.pullDeviceMailboxV3();
    assert.equal(pulls, 0, 'PULL is not sent while DNSS binding is still pending');
    assert.equal(deferred.deferred, true, 'pending DNSS is reported as deferred without an error');

    pending.dnssReadyState = 'ready';
    const ready = await NodeManager.pullDeviceMailboxV3();
    assert.equal(pulls, 1, 'PULL starts after DNSS binding becomes ready');
    assert.equal(ready.deferred, false);
    console.log('NodeManager DNSS gate prevents premature PULL and warning storm');
})().catch(error => { console.error(error); process.exitCode = 1; });
