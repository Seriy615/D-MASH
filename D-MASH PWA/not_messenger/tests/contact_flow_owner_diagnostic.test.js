'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
require('../js/device_routes.js');
require('../js/contact_payloads.js');
require('../js/contact_transport.js');
const Envelope = require('../js/device_envelope.js');
const Bootstrap = require('../js/contact_bootstrap_v3.js');
const Flow = require('../js/contact_flow_v3.js');
const {DeviceInbox} = require('../js/device_inbox.js');
const b64url = value => Buffer.from(value).toString('base64url');
class Store {
    constructor() {this.rows = new Map();}
    async all() {return structuredClone([...this.rows.values()]);}
    async get(key) {return structuredClone(this.rows.get(key) || null);}
    async write(record, absent) {if (absent && this.rows.has(record.key)) return false; this.rows.set(record.key, structuredClone(record)); return true;}
}
function device(slot) {
    const route = nacl.sign.keyPair(), box = nacl.box.keyPair(), account = nacl.sign.keyPair(), root = nacl.randomBytes(32);
    const now = Math.floor(Date.now() / 1000);
    const certificate = {version: 1, routeId: b64url(route.publicKey), signingPublicKey: b64url(route.publicKey), boxPublicKey: b64url(box.publicKey), issuedAt: now};
    certificate.signature = b64url(nacl.sign.detached(DeviceRoutes.certificateTranscript(certificate), route.secretKey));
    const bundle = Buffer.concat([Buffer.from(account.publicKey), Buffer.from(nacl.box.keyPair().publicKey), Buffer.from(nacl.randomBytes(1184))]).toString('hex');
    const store = new DeviceInbox({store: new Store(), getRoot: () => root});
    const self = {certificate, box, bundle, store, slot, active: slot, sent: [], imported: [], failSend: false};
    self.options = {store, activeAccount: () => self.active,
        makeBootstrap: async options => Bootstrap.create({version: 3, phase: options.phase, request_id: options.request.request_id,
            recipient_route_id: options.peerCertificate.routeId, route_certificate: certificate,
            account_bundle: bundle, contribution: (slot === 'A' ? '11' : '22').repeat(32), display_name: options.displayName,
            created_at: now, expires_at: now + 3600, accept_hash: options.acceptHash}, account, route),
        importPeer: async (body, expectedSlot) => {assert.equal(expectedSlot, self.active); self.imported.push(body.account_bundle);},
        send: async (recipient, message) => {
            if (self.failSend) throw Error('simulated socket failure');
            const publicKey = Buffer.from(recipient.boxPublicKey, 'base64url');
            self.sent.push(Envelope.seal(publicKey, Envelope.create(recipient.routeId, 'CONN_ACCEPT', JSON.stringify(message))));
        }};
    self.flow = new Flow(self.options);
    return self;
}
(async () => {
 const sender=device('Sender'), recipient=device('A');
 const request={type:'CONTACT_REQUEST_V1',version:1,request_id:b64url(nacl.randomBytes(32)),reply_route_certificate:sender.certificate,sender_display_name:'Sender',intro_message:'',bootstrap_encryption_public:sender.certificate.boxPublicKey,protocol_capabilities:['CONTACT_BOOTSTRAP_V3','DMP_C_V3']};
 recipient.failSend=true;
 await assert.rejects(recipient.flow.accept(request,recipient.certificate,'A'),/socket failure/);
 const original=(await recipient.flow.read(request.request_id)).accept;
 for(const phase of ['accept_prepared','accept_sent']) {
  assert.equal((await recipient.flow.read(request.request_id)).status,phase);
  const encrypted=JSON.stringify(await recipient.store.store.all());
  const sends=recipient.sent.length;
  recipient.active='B';
  await assert.rejects(recipient.flow.accept(request,recipient.certificate,'B'),/owner mismatch/);
  assert.equal(JSON.stringify(await recipient.store.store.all()),encrypted,'wrong Account must not mutate encrypted row');
  assert.equal(recipient.sent.length,sends);
  recipient.active='A';recipient.failSend=false;
  await recipient.flow.accept(request,recipient.certificate,'A');
  assert.deepEqual((await recipient.flow.read(request.request_id)).accept,original);
 }
 const outgoing={...request,request_id:b64url(nacl.randomBytes(32)),reply_route_certificate:recipient.certificate,bootstrap_encryption_public:recipient.certificate.boxPublicKey};
 await recipient.flow.recordOutgoing(outgoing,sender.certificate,'A');
 for(const active of ['A','B']) {
  recipient.active=active;
  const encrypted=JSON.stringify(await recipient.store.store.all());
  await assert.rejects(recipient.flow.accept(outgoing,recipient.certificate,active),/owner mismatch/);
  assert.equal(JSON.stringify(await recipient.store.store.all()),encrypted,'caller role must never be reassigned');
 }
 recipient.active='A';
 const actualNow=Date.now;
 try {
  Date.now=()=>actualNow()+7200000;
  const count=recipient.sent.length;
  await recipient.flow.resume();
  assert.equal(recipient.sent.length,count,'automatic resume skips expired Accept');
  assert.equal((await recipient.flow.read(request.request_id)).status,'accept_sent','expiry currently has no truthful terminal status');
  await recipient.flow.accept(request,recipient.certificate,'A');
  assert.equal(recipient.sent.length,count+1,'BUG: explicit accept resends expired signed Accept');
  const expired=JSON.parse(Envelope.open(sender.box.secretKey,recipient.sent.at(-1)).account_payload);
  assert.throws(()=>Bootstrap.verify(expired,{requestId:request.request_id,recipientRouteId:sender.certificate.routeId,senderRouteId:recipient.certificate.routeId,phase:'ACCEPT',acceptHash:null}),/Invalid/);
 } finally {Date.now=actualNow;}
 console.log('PASS: A→B prepared/sent and caller/self owner conflicts reproduced; encrypted rows unchanged; original owner exact Accept resume; expired explicit Accept resend BUG reproduced');
})().catch(error=>{console.error(error);process.exitCode=1;});
