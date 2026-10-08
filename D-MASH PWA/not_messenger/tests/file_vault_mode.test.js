const assert = require('node:assert/strict');
require('../js/file_vault.js');

const id = char => char.repeat(64);
const account = id('a'), peer = id('b'), fileId = id('c'), alias = id('d');
globalThis.DeviceRoot = {state: {generation: 1}};
const core = {keys: {server_id: account}, blindSalt: new Uint8Array(32),
    activeIdentity: 'synthetic-account'};
const storage = {db: {objectStoreNames: {contains: () => true}}, masterKey: {}};
const vault = new DmashFileVault(core, storage);
const base = {schema: 'dmash_file_v1', account, peer, fileId, size: 1, sha256: id('e'),
    name: 'file.bin', mime: 'application/octet-stream', inbound: false, status: 'waiting',
    attempts: 0, nextAttempt: 0, createdAt: 1};

assert.equal(vault.validMeta(vault.capture(), peer, fileId, base), true,
    'authenticated pre-mode rows remain readable');
assert.equal(vault.validMeta(vault.capture(), peer, fileId, {...base, controlMode: 'node-v4'}), true);
assert.equal(vault.validMeta(vault.capture(), peer, fileId, {...base, controlMode: 'unknown'}), false,
    'unknown authority must fail closed');

vault.ownerAlias = async () => alias;
vault.fileAlias = async () => alias;
let entryMode, metadataMode;
vault.owner = async () => ({row: {revision: 1}, value: {schema: 'dmash_file_owner_v1', account,
    entries: [{alias, peer, fileId, size: 1, inbound: false, status: 'waiting',
        ...(entryMode === undefined ? {} : {controlMode: entryMode})}]}});
vault.meta = async () => ({...base, ...(metadataMode === undefined ? {} : {controlMode: metadataMode})});

(async () => {
    const details = {name: 'file.bin', mime: 'application/octet-stream', size: 1,
        sha256: id('e'), inbound: false};
    await assert.rejects(vault.put(peer, fileId, new Blob(['x']), details), /Invalid local file/,
        'every new file must state its control authority');
    await assert.rejects(vault.put(peer, fileId, new Blob(['x']),
        {...details, controlMode: 'unknown'}), /Invalid local file/);
    entryMode = undefined; metadataMode = undefined;
    assert.equal((await vault.list()).length, 1,
        'matching pre-mode inventory and metadata remain readable');
    entryMode = 'node-v4'; metadataMode = 'node-v4';
    assert.equal((await vault.list())[0].controlMode, 'node-v4');
    entryMode = 'node-v4'; metadataMode = undefined;
    await assert.rejects(vault.list(), /Corrupt file inventory/,
        'Node inventory cannot be paired with a v3-private legacy meta');
    await assert.rejects(vault.prepareDeletePeer(peer), /Corrupt file owner/,
        'a mismatched authority tag must block owner-scoped deletion');
    await assert.rejects(vault.prepareDeleteOne(peer, fileId), /Corrupt file owner/);
    entryMode = undefined; metadataMode = 'node-v4';
    await assert.rejects(vault.list(), /Corrupt file inventory/,
        'a legacy inventory cannot silently adopt Node authority');
    const normalize = new DmashFileVault(core, storage);
    normalize.fileAlias = async () => alias;
    normalize.open = async () => base;
    storage.db.transaction = () => ({objectStore: () => ({get: () => {
        const query = {};
        queueMicrotask(() => {query.result = {alias}; query.onsuccess();});
        return query;
    }})});
    assert.equal((await normalize.meta(peer, fileId)).controlMode, 'v3-private',
        'actual legacy row read normalizes only to v3-private');
    console.log('file_vault_mode.test.js: authority ownership and legacy separation passed');
})().catch(error => {console.error(error);process.exitCode = 1;});
