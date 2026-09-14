const assert = require('node:assert/strict');
require('../js/file_runtime.js');
class Element {
    constructor() {this.children = [];}
    setAttribute() {}
    append(...items) {this.children.push(...items);}
    remove() {this.removed=true;}
}
globalThis.document = {body:new Element(), createElement: () => new Element()};
const invitation = {version:2,call_id:'a'.repeat(64), expires_at:Math.floor(Date.now()/1000)+900,
    signaling:{wss_endpoint:'wss://example.test',session_id:'s'.repeat(43),one_time_key:'t'.repeat(43)}};
let transport;
class Transport {
    constructor() {this.invitation=invitation; transport=this;}
    static async create() {return new Transport();}
    async open() {}
    async send() {}
    close() {this.closed=true;}
}
globalThis.DmashCallSignaling={WebSocketSignaling:Transport};
globalThis.DmashCallSignaling.validEndpoint=()=>true;
globalThis.DmashCallRuntime={validate:r=>r};
globalThis.DmashFileChannel={MAX_SIZE:64*1024*1024,validate:r=>r,
    async describe(file,id) {return {id,size:file.size,name:file.name};}};
globalThis.NodeManager={async selectCallService(options) {assert(options.file); return 'wss://example.test';}};
globalThis.DmashFileSession={create(options) {return {async startOffer() {},async accept() {this.accepted=true;},close() {this.closed=true;}};}};
function core() {return {activePeerId:'fixed-peer',customAlert() {},async sendMessage(value,handshake,peer,alias,noQueue) {
    this.message=value; assert.equal(peer,'fixed-peer'); assert(noQueue); return true;
}};}
(async () => {
    const sender=core();
    assert(await DmashFileRuntime.send(sender,{size:1024,name:'test.bin'}));
    assert.equal(sender.message.type,'voip_file_request');
    assert(!sender.message.data);
    const task=sender._fileTransfer;
    DmashFileRuntime.cancel(sender);
    assert(task.closed); assert(task.session.closed); assert(transport.closed); assert(task.box.removed);
    assert.equal(sender._fileTransfer,null);

    const receiver=core();
    const metadata = btoa(JSON.stringify({id:'a'.repeat(64),version:1,size:1024,name:'incoming',mime:'',
        chunk_bytes:32768,sha256:'c'.repeat(64),key:'k'.repeat(44),nonce:'n'.repeat(12)}));
    const request = {version:1,session_id:'a'.repeat(64),expires_at:invitation.expires_at,
        signaling:invitation.signaling,encrypted_metadata:metadata,size_bytes:1024,
        chunk_bytes:32768,sha256:'c'.repeat(64),resumable:false};
    assert(await DmashFileRuntime.incoming(receiver,request,'peer'));
    const incoming=receiver._fileTransfer;
    assert(!incoming.session,'No connection or transfer before consent');
    await incoming.box.children.at(-1).onclick();
    assert(incoming.session.accepted);
    DmashFileRuntime.cancel(receiver);
    assert(incoming.session.closed);
    console.log('file_runtime.test.js: PWA consent, cancellation and invitation-only delivery passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
