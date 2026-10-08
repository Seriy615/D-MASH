const assert = require('node:assert/strict');
const crypto = require('node:crypto');
require('../js/file_runtime.js');

class Element {
    constructor() {this.children=[];this.textContent='';}
    setAttribute() {}
    append(...nodes) {this.children.push(...nodes);}
    remove() {this.removed=true;}
}
globalThis.document={body:new Element(),createElement:()=>new Element()};
globalThis.navigator.storage={estimate:async()=>({quota:100*1024*1024,usage:0})};
globalThis.DmashCallSession={CallSignalingSession:class {}};
const invitation={call_id:'a'.repeat(64),expires_at:Math.floor(Date.now()/1000)+900,
    signaling:{wss_endpoint:'wss://example.test',session_id:'s'.repeat(43),one_time_key:'t'.repeat(43)}};
globalThis.DmashCallSignaling={
    validEndpoint:value=>{assert.equal(value,'wss://example.test');return value;},
    WebSocketSignaling:class {
        constructor() {this.invitation=invitation;}
        static async create() {return new this();}
        close() {this.closed=true;}
    }
};
const sessions=[];
globalThis.DmashFileSession={create(options) {
    const session={options,async startOffer(){this.offered=true;},
        async accept(){this.accepted=true;},async close(){this.closed=true;}};
    sessions.push(session);return session;
}};
globalThis.DmashFileChannel={
    MAX_SIZE:64*1024*1024,
    validate:manifest=>{
        assert.equal(manifest.version,1);
        if(manifest.size>64*1024*1024)throw Error('Invalid file manifest');
    },
    async describe(file,id) {
        const bytes=Buffer.from(await file.arrayBuffer());
        return {version:1,id,size:file.size,name:file.name,mime:file.type,
            chunk_bytes:32768,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),
            key:'k'.repeat(44),nonce:'n'.repeat(12)};
    }
};
globalThis.NodeManager={async selectCallService(options){
    assert.equal(options.file,true);return 'wss://example.test';
}};
const owned=new WeakMap();
globalThis.DmashFileVault=class {
    constructor(core) {this.core=core;if(!owned.has(core))owned.set(core,new Map());}
    capture() {return {check:()=>{if(this.core.changed)throw Error('Account changed');}};}
    async put(peer,fileId,blob,details) {
        const meta={...details,peer,fileId,status:details.inbound?'delivered':'waiting',
            attempts:0,nextAttempt:0,createdAt:Date.now()};
        owned.get(this.core).set(fileId,{meta,blob});return meta;
    }
    async meta(peer,fileId) {return owned.get(this.core).get(fileId)?.meta||null;}
    async get(peer,fileId) {return owned.get(this.core).get(fileId)||null;}
    async list(peer,statuses) {return [...owned.get(this.core).values()].map(row=>row.meta)
        .filter(row=>(!peer||row.peer===peer)&&(!statuses||statuses.includes(row.status)));}
    async update(peer,fileId,status,changes={}) {
        const row=owned.get(this.core).get(fileId);
        if(!row)throw Error('Missing file');
        if(row.meta.status==='delivered'&&status!=='delivered')return row.meta;
        if(row.meta.status==='cancelled'&&status!=='delivered')return row.meta;
        row.meta={...row.meta,status,...changes};return row.meta;
    }
};
function core() {return {activePeerId:'f'.repeat(64),alerts:[],history:[],
    customAlert(title,text){this.alerts.push({title,text});},
    async loadChat(){},async renderPeers(){},
    async sendMessage(value,handshake,peer,alias,noQueue) {
        assert.equal(peer,this.activePeerId);assert.equal(noQueue,true);
        this.messages||=[];this.messages.push(value);return true;
    },
    refreshMessageTransportState(peer,fileId,status){this.lastTransportStatus=status;}
};}
function storageFor(owner) {return {
    async getAlias(peer){return peer;},
    async getBox(table){return table==='blind_peers'
        ? {id:owner.activePeerId}:{staticShared:'e'.repeat(64)};},
    async hasMessageWireId(peer,id){return owner.history.some(row=>row.id===id);},
    async saveMessageGamma(peer,content,inbound,read,status,id){
        owner.history.push({peer,content,inbound,status,id});
    },
    async updateMessageTransportState(peer,id){
        owner.storageStatus='DELIVERED';
        const row=owner.history.find(item=>item.id===id);
        if(row)row.status='DELIVERED';
    },
    async markMessageSendFailure(peer,id,reason){
        const row=owner.history.find(item=>item.id===id);
        if(!row)return false;
        row.status=reason==='FILE_CANCELLED'?'CANCELLED':'FAILED';return true;
    }
};}
(async()=>{
    const sender=core(),receiver=core(),bytes=Buffer.from('synthetic authenticated inline file');
    const file=new File([bytes],'synthetic.txt',{type:'text/plain'});
    globalThis.DMashStorage=storageFor(sender);
    assert.equal(await DmashFileRuntime.send(sender,file),true);
    await DmashFileRuntime.flush(sender);
    assert.equal(sender.history.length,1,'sender intent is durable before invitation');
    assert.equal(sender.history[0].content.type,'file_ref');
    assert.equal(sender.history[0].status,'WAITING');
    const request=sender.messages.at(-1).request;
    assert.equal(request.version,2);
    assert.match(request.file_id,/^[0-9a-f]{64}$/);
    assert(!('data' in request),'control carries no file bytes');

    globalThis.DMashStorage=storageFor(receiver);
    assert.equal(await DmashFileRuntime.incoming(receiver,request,receiver.activePeerId),true);
    const inbound=sessions.at(-1);
    assert.equal(inbound.accepted,true,'trusted peer auto-accepts without a click');
    assert(!receiver._fileTransfer.box.children.some(node=>node.textContent==='Принять'));
    await inbound.options.onCommit(new Blob([bytes]));
    inbound.options.onComplete();
    assert.equal(receiver.history.length,1,'receiver commits one inline file message');
    assert.equal(receiver.history[0].content.type,'file_ref');
    assert.equal(receiver.history[0].inbound,true);
    assert.equal(owned.get(receiver).get(request.file_id).meta.status,'delivered');
    assert.equal(await DmashFileRuntime.incoming(receiver,request,receiver.activePeerId),true);
    assert.equal(receiver.history.length,1,'authenticated retry does not duplicate');
    assert.equal(receiver.messages.at(-1).type,'voip_file_complete');
    receiver._fileTransfer.cancel.onclick();
    assert.equal(receiver.messages.length,1,'closing a completed panel never rejects a delivered file');

    const cancelling=core();
    globalThis.DMashStorage=storageFor(cancelling);
    assert.equal(await DmashFileRuntime.incoming(cancelling,request,cancelling.activePeerId),true);
    const cancelledSession=sessions.at(-1);
    cancelling._fileTransfer.cancel.onclick();
    await new Promise(resolve=>setTimeout(resolve,10));
    assert.equal(cancelledSession.closed,true,'receiver cancel closes the S-TURN session');
    assert.equal(cancelling.messages.at(-1).type,'voip_file_reject');
    assert.equal(cancelling.messages.at(-1).reason,'RECEIVER_DECLINED');

    const oversize=core();
    globalThis.DMashStorage=storageFor(oversize);
    const tooLarge={...request,size_bytes:64*1024*1024+1};
    assert.equal(await DmashFileRuntime.incoming(oversize,tooLarge,oversize.activePeerId),false);
    assert.match(oversize.alerts.at(-1).text,/64 МиБ/,'confirmed peer size failure is visible');
    assert.equal(oversize._fileTransfer,undefined,'invalid size never opens S-TURN');

    const noSpace=core();
    globalThis.DMashStorage=storageFor(noSpace);
    globalThis.navigator.storage.estimate=async()=>({quota:100,usage:99});
    assert.equal(await DmashFileRuntime.incoming(noSpace,request,noSpace.activePeerId),false);
    assert.equal(noSpace._fileTransfer.failed,true,'quota failure remains visible');
    assert.equal(noSpace.messages.at(-1).type,'voip_file_reject');
    DmashFileRuntime.cancel(noSpace);

    globalThis.DMashStorage=storageFor(sender);
    sessions[0].options.onComplete();
    await new Promise(resolve=>setTimeout(resolve,10));
    assert.equal(owned.get(sender).get(request.file_id).meta.status,'delivered');
    assert.equal(sender.storageStatus,'DELIVERED');
    assert.equal(sender.lastTransportStatus,'DELIVERED');
    assert.equal(await DmashFileRuntime.outcome(sender,{type:'voip_file_reject',
        file_id:request.file_id,sha256:sender.history[0].content.sha256,
        reason:'RECEIVER_STORAGE_FULL'},sender.activePeerId),true);
    assert.equal(sender.history[0].status,'DELIVERED','late reject cannot overwrite a verified receipt');
    assert.equal(sender.lastTransportStatus,'DELIVERED');
    const sender2=core();
    globalThis.DMashStorage=storageFor(sender2);
    assert.equal(await DmashFileRuntime.send(sender2,file),true);
    await DmashFileRuntime.flush(sender2);
    const request2=sender2.messages.at(-1).request;
    const noSpace2=core();
    globalThis.DMashStorage=storageFor(noSpace2);
    assert.equal(await DmashFileRuntime.incoming(noSpace2,request2,noSpace2.activePeerId),false);
    globalThis.DMashStorage=storageFor(sender2);
    assert.equal(await DmashFileRuntime.outcome(sender2,noSpace2.messages.at(-1),sender2.activePeerId),true);
    assert.equal(sender2.history[0].status,'FAILED','quota failure survives a chat reload');
    assert.equal(owned.get(sender2).get(request2.file_id).meta.status,'failed');
    assert(owned.get(sender2).get(request2.file_id).blob,'failed sender keeps encrypted local file');
    DmashFileRuntime.cancel(noSpace2);DmashFileRuntime.cancel(sender2);
    const sender3=core();
    globalThis.DMashStorage=storageFor(sender3);
    assert.equal(await DmashFileRuntime.send(sender3,file),true);
    await DmashFileRuntime.flush(sender3);
    const request3=sender3.messages.at(-1).request;
    assert.equal(await DmashFileRuntime.cancelFile(sender3,sender3.activePeerId,request3.file_id),true);
    assert.equal(owned.get(sender3).get(request3.file_id).meta.status,'cancelled');
    assert.equal(sender3.history[0].status,'CANCELLED','sender cancel survives reload');
    assert(owned.get(sender3).get(request3.file_id).blob,'cancel preserves encrypted local bytes');
    await DmashFileRuntime.outcome(sender3,{type:'voip_file_reject',
        file_id:request3.file_id,sha256:sender3.history[0].content.sha256,
        reason:'RECEIVER_DECLINED'},sender3.activePeerId);
    assert.equal(sender3.history[0].status,'CANCELLED','late reject cannot reverse cancellation');
    await DmashFileRuntime.outcome(sender3,{type:'voip_file_complete',
        file_id:request3.file_id,sha256:sender3.history[0].content.sha256},sender3.activePeerId);
    assert.equal(sender3.history[0].status,'DELIVERED','authenticated durable receipt corrects a cancellation race');
    DmashFileRuntime.cancel(sender3);
    DmashFileRuntime.cancel(sender);DmashFileRuntime.cancel(receiver);
    console.log('file_runtime.test.js: durable intent, trusted auto-receive, inline history and retry dedupe passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
