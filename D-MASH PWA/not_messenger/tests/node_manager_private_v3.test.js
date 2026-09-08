'use strict';
const assert = require('node:assert/strict');
global.window = global;
global.location = {href: 'http://127.0.0.1/'};
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
require('../js/device_envelope.js');
const {DeviceInbox} = require('../js/device_inbox.js');
const Routes = require('../js/private_routes_v3.js');
const local = () => {const data = new Map(); return {getItem: key => data.get(key) || null, setItem: (key, value) => data.set(key, value), removeItem: key => data.delete(key)};};
global.localStorage = local(); global.sessionStorage = local();
global.document = {getElementById: () => null};
global.Core = {activeIdentity: 'A'};
require('../js/node_manager.js');
class Store {
    constructor() {this.rows = new Map();}
    async all() {return structuredClone([...this.rows.values()]);}
    async get(key) {return structuredClone(this.rows.get(key) || null);}
    async write(record, absent) {if (absent && this.rows.has(record.key)) return false; this.rows.set(record.key, structuredClone(record)); return true;}
}
(async () => {
    const root = nacl.randomBytes(32), store = new Store();
    const inbox = new DeviceInbox({store, getRoot: () => root});
    NodeManager._deviceInboxV3 = inbox;
    NodeManager.setMeshRoute('legacy-test-peer', '12'.repeat(32), '34'.repeat(32));
    await NodeManager.blindLegacyRouteConfigV3();
    assert.equal(NodeManager.getMeshRoute('legacy-test-peer').routeLocator, await inbox.routeAlias('12'.repeat(32)));
    const beforeSecondMigration = JSON.stringify(NodeManager.getRouteConfig());
    await NodeManager.blindLegacyRouteConfigV3();
    assert.equal(JSON.stringify(NodeManager.getRouteConfig()), beforeSecondMigration, 'migration does not hash existing blind aliases again');
    const a = await Routes.pair('11'.repeat(32), '22'.repeat(32));
    const peer = 'ab'.repeat(32);
    await NodeManager.installPrivateRouteV3(peer, a);
    const config = NodeManager.getMeshRoute(peer);
    assert.equal(config.routeLocator, await inbox.routeAlias(a.routeLocator));
    assert.equal(config.backRouteLocator, await inbox.routeAlias(a.backRouteLocator));
    for (const row of await store.all()) {
        const plain = JSON.stringify(await inbox._open(row));
        for (const value of [a.routeLocator, a.backRouteLocator, peer]) assert.equal(plain.includes(value), false, 'Device records contain neither raw Account RouteID nor Account peer identity');
    }
    const sent = [];
    const connection = {state: 'connected', nodeId: 'cc'.repeat(32), socket: {readyState: 1},
        capabilities: new Set(['REGISTER_ROUTE', 'START_PROBE']),
        authority: {route: async (operation, resource, payload) => {sent.push({operation, routeId: resource.routeId, target: payload?.route_locator});}}};
    await NodeManager.probePrivateRoutesV3(connection);
    assert.equal(sent[0].routeId, a.backRouteLocator, 'Device reconstructs transient routing context from capability');
    assert.equal(sent[1].target, a.routeLocator);
    const plaintext = {ciphertext: 'opaque Account ciphertext', sender_proof: 'opaque Account proof'};
    connection.client = {request: async (operation, payload) => {sent.push({operation, payload}); return {state: 'NODE_ACCEPTED'};}};
    NodeManager.connections.set('test', connection);
    NodeManager.routeStatus = async () => ({connection});
    const result = await NodeManager.submitEnvelope(config.routeLocator, plaintext);
    assert.equal(result.state, 'NODE_ACCEPTED');
    const submitted = sent.at(-1);
    assert.equal(submitted.operation, 'SUBMIT');
    assert.equal(submitted.payload.route_locator, a.routeLocator);
    const opened = DeviceEnvelope.open(a.outgoing.box.secretKey, submitted.payload.ciphertext);
    assert.deepEqual(JSON.parse(opened.account_payload), plaintext, 'Device transports opaque Account payload unchanged');
    Core.activeIdentity = 'B';
    await assert.rejects(NodeManager.submitEnvelope(config.routeLocator, plaintext), /restored/);
    a.close();
    console.log('Device blind private-route storage and opaque Account handoff tests passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
