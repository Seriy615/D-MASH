'use strict';
const assert = require('node:assert/strict');
const {DeviceRoot} = require('../js/device_root.js');
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return {promise, resolve}; };
function setup() {
    DeviceRoot.lock();
    const store = {record: {id:'root', version:1, materials:{}}, fail:false,
        async put(record) { if(this.fail) throw Error('disk full'); this.record = structuredClone(record); }};
    DeviceRoot.setStoreForTests(store);
    DeviceRoot.state = {root:crypto.getRandomValues(new Uint8Array(32)), record:structuredClone(store.record)};
    return store;
}
(async () => {
    let store = setup(), creates = 0;
    const results = await Promise.all([
        DeviceRoot.deviceMaterial('a', async () => { creates++; return new Uint8Array([1,2]); }),
        DeviceRoot.deviceMaterial('b', async () => new Uint8Array([3,4])),
        DeviceRoot.deviceMaterial('a', async () => { creates++; return new Uint8Array([9,9]); })
    ]);
    assert.equal(creates, 1);
    assert.deepEqual(results[0], results[2]);
    assert.deepEqual(Object.keys(store.record.materials).sort(), ['a','b']);
    // Real AES-GCM storage is reopened after losing all in-memory state.
    const root = DeviceRoot.state.root.slice();
    DeviceRoot.lock(); DeviceRoot.state = {root, record:structuredClone(store.record)};
    assert.deepEqual(await DeviceRoot.deviceMaterial('b', () => { throw Error('must not regenerate'); }), new Uint8Array([3,4]));

    store = setup(); store.fail = true;
    const failedBytes = new Uint8Array([5,6]);
    await assert.rejects(DeviceRoot.deviceMaterial('a', async () => failedBytes), /disk full/);
    assert.deepEqual([...failedBytes], [0,0]);
    assert.deepEqual(DeviceRoot.state.record.materials, {});
    store.fail = false;
    assert.deepEqual(await DeviceRoot.deviceMaterial('a', async () => new Uint8Array([7])), new Uint8Array([7]));

    store = setup();
    const entered = deferred(), release = deferred(), stale = new Uint8Array([8,9]);
    const pending = DeviceRoot.deviceMaterial('stale', async () => { entered.resolve(); await release.promise; return stale; });
    const rejection = assert.rejects(pending, error => error.code === 'DEVICE_LOCKED');
    let queuedCalled = false;
    const queued = DeviceRoot.deviceMaterial('queued', async () => { queuedCalled = true; return new Uint8Array([1]); });
    const queuedRejection = assert.rejects(queued, error => error.code === 'DEVICE_LOCKED');
    await entered.promise;
    const nextStore = setup();
    release.resolve(); await Promise.all([rejection, queuedRejection]);
    assert.equal(queuedCalled, false);
    assert.deepEqual([...stale], [0,0]);
    assert.deepEqual(store.record.materials, {});
    assert.deepEqual(nextStore.record.materials, {});
    DeviceRoot.lock();
    console.log('PASS DeviceRoot material serialization, persistence failure, session replacement and secret cleanup');
})().catch(error => {console.error(error);process.exitCode=1;});
