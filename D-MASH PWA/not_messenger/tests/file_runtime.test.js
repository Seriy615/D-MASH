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
        static async create() {const transport=new this();
            if(globalThis.nextSyntheticCallId)
                transport.invitation={...invitation,call_id:globalThis.nextSyntheticCallId};
            return transport;}
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
const pendingOutcomes=new WeakMap();
globalThis.DmashFileVault=class {
    constructor(core) {this.core=core;if(!owned.has(core))owned.set(core,new Map());
        if(!pendingOutcomes.has(core))pendingOutcomes.set(core,new Map());}
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
    async stageOutcome(details) {
        if(this.core.failOutcome)throw Error('Synthetic outcome journal unavailable');
        const rows=pendingOutcomes.get(this.core);
        const prior=[...rows.values()].find(row=>row.peer===details.peer&&row.fileId===details.fileId&&
            row.sha256===details.sha256&&row.type===details.type&&row.reason===details.reason&&
            row.transportId===details.transportId&&row.controlDigest===details.controlDigest);
        if(prior)return prior;
        rows.set(details.operationId,details);return details;
    }
    async listOutcomes() {return [...pendingOutcomes.get(this.core).values()].filter(x=>!x.queued);}
    async terminalOutcome(peer,fileId,sha256,size,transportId,controlDigest) {
        return [...pendingOutcomes.get(this.core).values()].find(x=>x.peer===peer&&x.fileId===fileId&&
            x.sha256===sha256&&x.size===size&&x.transportId===transportId&&
            x.controlDigest===controlDigest&&x.terminalUntil>Date.now())||null;
    }
    async retireOutcome(operationId) {
        const rows=pendingOutcomes.get(this.core),row=rows.get(operationId);
        if(!row)return false;
        if(row.terminalUntil>Date.now())row.queued=true;else rows.delete(operationId);
        return true;
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
    const nodeManaged=core();
    nodeManaged.accountTransportMode=()=> 'node-v4';
    globalThis.DMashStorage=storageFor(nodeManaged);
    assert.equal(await DmashFileRuntime.send(nodeManaged,file),false,
        'managed Node file click cannot use a surviving v3 staticShared secret');
    assert.match(nodeManaged.alerts.at(-1).text,/NODE_MEDIA_CONTROL_UNAVAILABLE/);
    assert.equal(owned.get(nodeManaged).size,0,'fail-closed click creates no v3 intent');
    const oldFileId='9'.repeat(64),oldDigest=crypto.createHash('sha256').update(bytes).digest('hex');
    await new DmashFileVault(nodeManaged).put(nodeManaged.activePeerId,oldFileId,file,
        {name:file.name,mime:file.type,size:file.size,sha256:oldDigest,inbound:false,
            controlMode:'v3-private'});
    await DmashFileRuntime.flush(nodeManaged);
    assert.equal(owned.get(nodeManaged).get(oldFileId).meta.status,'waiting',
        'pre-migration v3 pending file stays durable under managed Node');
    assert.equal(nodeManaged.messages,undefined,'managed Node never sends legacy file invitation');
    const nodeReady=core(),authority=Object.freeze({synthetic:true}),
        service=Object.freeze({endpoint:'wss://example.test',wssEndpoint:'wss://example.test',
            nodeId:'e'.repeat(64)});
    nodeReady.accountTransportMode=()=> 'node-v4';
    nodeReady.canQueueNodeMediaV4=async()=>true;
    nodeReady.confirmedNodeMediaPeerV4=async()=>authority;
    nodeReady.selectNodeMediaServiceV4=async args=>{
        assert.equal(args.peer,nodeReady.activePeerId);
        assert.equal(args.authority,authority);
        assert.equal(args.file,true);
        return service;
    };
    nodeReady.sendNodeMediaControlV4=async args=>{
        nodeReady.nodeControl=args;
        return {durable:true,queued:false,recipientAck:false};
    };
    globalThis.DMashStorage=storageFor(nodeReady);
    const oldSelect=NodeManager.selectCallService;
    NodeManager.selectCallService=()=>{throw Error('managed Node used v3 service selection');};
    try {
        assert.equal(await DmashFileRuntime.send(nodeReady,file),true,
            'confirmed managed contact can queue locally');
        await DmashFileRuntime.flush(nodeReady);
        assert.equal(nodeReady.history.length,1);
        assert.equal(nodeReady.history[0].status,'WAITING');
        assert.equal(nodeReady.nodeControl.service,service,
            'signed same-channel service object passes unchanged');
        assert.equal(nodeReady.nodeControl.authority,authority);
        assert.equal(nodeReady.nodeControl.message.type,'voip_file_request');
        assert.equal(nodeReady.nodeControl.record.transportId,
            nodeReady.nodeControl.message.request.session_id);
        assert.equal(nodeReady.nodeControl.record.transferId,
            nodeReady.nodeControl.message.request.file_id);
        assert.match(nodeReady.nodeControl.operationId,/^[0-9a-f]{64}$/);
        assert.equal(nodeReady.messages,undefined,'Node control never enters legacy Core.sendMessage');
        assert.equal([...owned.get(nodeReady).values()][0].meta.controlMode,'node-v4');
    } finally {
        NodeManager.selectCallService=oldSelect;
        DmashFileRuntime.cancel(nodeReady);
    }
    const nodeRequest=nodeReady.nodeControl.message.request;
    const nodeReceiver=core(),inboundAuthority=Object.freeze({inbound:true}),
        taskToken=Object.freeze({task:true});
    nodeReceiver.accountTransportMode=()=> 'node-v4';
    nodeReceiver.confirmedNodeMediaPeerV4=async()=>authority;
    nodeReceiver.verifyNodeMediaControlV4=async (cap,expected)=>{
        assert.equal(cap,inboundAuthority);
        assert.equal(expected.peer,nodeReceiver.activePeerId);
        assert.equal(expected.message.type,'voip_file_request');
        if(expected.phase==='commit')assert.equal(expected.taskToken,taskToken);
        return true;
    };
    nodeReceiver.beginNodeFileTransferV4=async (cap,details)=>{
        assert.equal(cap,inboundAuthority);
        assert.equal(details.transferId,nodeRequest.file_id);
        assert.equal(details.transportId,nodeRequest.session_id);
        return taskToken;
    };
    nodeReceiver.sendNodeMediaControlV4=async args=>{
        nodeReceiver.outcomes||=[];nodeReceiver.outcomes.push(args);
        return {durable:true,queued:false,recipientAck:false};
    };
    globalThis.DMashStorage=storageFor(nodeReceiver);
    assert.equal(await DmashFileRuntime.incoming(nodeReceiver,nodeRequest,nodeReceiver.activePeerId),false,
        'managed Node refuses a raw v3-looking invitation without private authority');
    assert.deepEqual(await DmashFileRuntime.incoming(nodeReceiver,nodeRequest,nodeReceiver.activePeerId,
        {controlMode:'node-v4',authority:inboundAuthority}),{accepted:true});
    const nodeInbound=sessions.at(-1);
    assert.equal(nodeInbound.accepted,true,'Node receiver accepts only after durable task begin');
    await nodeInbound.options.onCommit(new Blob([bytes]));
    await DmashFileRuntime.flush(nodeReceiver);
    assert.equal(nodeReceiver.history.length,1);
    assert.equal(owned.get(nodeReceiver).get(nodeRequest.file_id).meta.controlMode,'node-v4');
    assert(nodeReceiver.outcomes.some(item=>item.message.type==='voip_file_complete'),
        'receiver retains and enqueues typed COMMIT_ACK after durable file commit');
    assert.equal((await new DmashFileVault(nodeReceiver).listOutcomes()).length,0,
        'durable N4 enqueue retires send work while retaining bounded terminal proof');
    assert.deepEqual(await DmashFileRuntime.incoming(nodeReceiver,nodeRequest,nodeReceiver.activePeerId,
        {controlMode:'node-v4',authority:inboundAuthority}),{accepted:true});
    assert.equal(nodeReceiver.history.length,1,'authenticated Node replay does not duplicate chat file');
    nodeInbound.options.onComplete();
    nodeReceiver._fileTransfer.cancel.onclick();
    DmashFileRuntime.cancel(nodeReceiver);
    const nodeExpired=core(),expiredRequest={...nodeRequest,
        expires_at:Math.floor(Date.now()/1000)-1};
    nodeExpired.accountTransportMode=()=> 'node-v4';
    nodeExpired.verifyNodeMediaControlV4=async (cap,expected)=>
        cap===inboundAuthority&&expected.phase==='commit'&&expected.taskToken===taskToken;
    nodeExpired.beginNodeFileTransferV4=async()=>{throw Error('expired resume restarted task');};
    globalThis.DMashStorage=storageFor(nodeExpired);
    assert.deepEqual(await DmashFileRuntime.incoming(nodeExpired,expiredRequest,nodeExpired.activePeerId,
        {controlMode:'node-v4',authority:inboundAuthority,resuming:true,taskToken}),{accepted:true},
    'a private durable APPLIED task may structurally resume after INVITE expiry');
    DmashFileRuntime.cancel(nodeExpired);
    const nodeDecliner=core();
    nodeDecliner.accountTransportMode=()=> 'node-v4';
    nodeDecliner.verifyNodeMediaControlV4=async()=>true;
    nodeDecliner.beginNodeFileTransferV4=async()=>taskToken;
    nodeDecliner.confirmedNodeMediaPeerV4=async()=>authority;
    nodeDecliner.sendNodeMediaControlV4=async()=>({durable:true});
    globalThis.DMashStorage=storageFor(nodeDecliner);
    assert.deepEqual(await DmashFileRuntime.incoming(nodeDecliner,nodeRequest,nodeDecliner.activePeerId,
        {controlMode:'node-v4',authority:inboundAuthority}),{accepted:true});
    const startedSessions=sessions.length;
    nodeDecliner._fileTransfer.cancel.onclick();
    await new Promise(resolve=>setTimeout(resolve,10));
    await DmashFileRuntime.flush(nodeDecliner);
    assert([...pendingOutcomes.get(nodeDecliner).values()].some(x=>x.reason==='RECEIVER_DECLINED'&&
        x.queued&&x.terminalUntil>Date.now()),'cancel retains encrypted terminal replay suppression');
    assert.deepEqual(await DmashFileRuntime.incoming(nodeDecliner,nodeRequest,nodeDecliner.activePeerId,
        {controlMode:'node-v4',authority:inboundAuthority,resuming:true,taskToken}),{accepted:true});
    assert.equal(sessions.length,startedSessions,'accepted cancelled task never restarts bytes on replay');
    DmashFileRuntime.cancel(nodeDecliner);
    const savedEstimate=navigator.storage.estimate;
    navigator.storage.estimate=async()=>({quota:100,usage:99});
    try {
        const nodeQuota=core();
        nodeQuota.accountTransportMode=()=> 'node-v4';
        nodeQuota.verifyNodeMediaControlV4=async()=>true;
        nodeQuota.beginNodeFileTransferV4=async()=>{throw Error('quota started transport');};
        globalThis.DMashStorage=storageFor(nodeQuota);
        assert.deepEqual(await DmashFileRuntime.incoming(nodeQuota,nodeRequest,nodeQuota.activePeerId,
            {controlMode:'node-v4',authority:inboundAuthority}),{accepted:true},
        'quota rejection is consumed only after encrypted DECLINE intent');
        assert.equal(nodeQuota._fileTransfer.failed,true);
        assert((await new DmashFileVault(nodeQuota).listOutcomes()).some(x=>
            x.reason==='RECEIVER_STORAGE_FULL'));
        DmashFileRuntime.cancel(nodeQuota);
        const nodeFault=core();
        nodeFault.accountTransportMode=()=> 'node-v4';
        nodeFault.verifyNodeMediaControlV4=async()=>true;
        nodeFault.beginNodeFileTransferV4=async()=>{throw Error('quota started transport');};
        nodeFault.failOutcome=true;
        globalThis.DMashStorage=storageFor(nodeFault);
        assert.equal(await DmashFileRuntime.incoming(nodeFault,nodeRequest,nodeFault.activePeerId,
            {controlMode:'node-v4',authority:inboundAuthority}),false,
        'failed encrypted outcome commit never reports authenticated receipt');
        assert.equal(nodeFault._fileTransfer.failed,true);
        DmashFileRuntime.cancel(nodeFault);
    } finally {navigator.storage.estimate=savedEstimate;}
    globalThis.DMashStorage=storageFor(nodeReady);
    nodeReady.verifyNodeMediaControlV4=async (cap,expected)=>
        cap===inboundAuthority&&expected.message.type==='voip_file_complete';
    const completed={type:'voip_file_complete',file_id:nodeRequest.file_id,
        sha256:nodeReady.nodeControl.record.sha256};
    assert.equal(await DmashFileRuntime.outcome(nodeReady,completed,nodeReady.activePeerId,
        {controlMode:'node-v4',authority:{forged:true}}),false,
        'forged Node receipt cannot update sender status');
    assert.deepEqual(await DmashFileRuntime.outcome(nodeReady,completed,nodeReady.activePeerId,
        {controlMode:'node-v4',authority:inboundAuthority}),{accepted:true});
    assert.equal(owned.get(nodeReady).get(nodeRequest.file_id).meta.status,'delivered');
    globalThis.DMashStorage=storageFor(sender);
    assert.equal(await DmashFileRuntime.send(sender,file),true);
    await DmashFileRuntime.flush(sender);
    const senderSession=sessions.at(-1);
    assert.equal(sender.history.length,1,'sender intent is durable before invitation');
    assert.equal(sender.history[0].content.type,'file_ref');
    assert.equal(sender.history[0].status,'WAITING');
    const request=sender.messages.at(-1).request;
    globalThis.DMashStorage=storageFor(nodeManaged);
    assert.equal(await DmashFileRuntime.incoming(nodeManaged,request,nodeManaged.activePeerId),false,
        'managed Node does not accept unauthenticated v3 file controls');
    assert.equal(await DmashFileRuntime.outcome(nodeManaged,{type:'voip_file_complete',
        file_id:oldFileId,sha256:oldDigest},nodeManaged.activePeerId),false);
    globalThis.DMashStorage=storageFor(sender);
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
    senderSession.options.onComplete();
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
    // A second authenticated invitation during an active receive gets a
    // transient, attempt-bound BUSY response. Its local file must remain
    // encrypted and retryable; a delayed old BUSY cannot stop a new attempt.
    globalThis.navigator.storage.estimate=async()=>({quota:100*1024*1024,usage:0});
    const busySender=core(),busyReceiver=core();
    globalThis.DMashStorage=storageFor(busySender);
    assert.equal(await DmashFileRuntime.send(busySender,file),true);
    await DmashFileRuntime.flush(busySender);
    const busyRequest=busySender.messages.at(-1).request;
    globalThis.DMashStorage=storageFor(busyReceiver);
    assert.equal(await DmashFileRuntime.incoming(busyReceiver,request,busyReceiver.activePeerId),true);
    const firstSession=sessions.at(-1),sessionCount=sessions.length;
    assert.equal(await DmashFileRuntime.incoming(busyReceiver,busyRequest,busyReceiver.activePeerId),true);
    assert.equal(sessions.length,sessionCount,'busy receiver does not start a second S-TURN session');
    assert.equal(firstSession.closed,undefined,'first transfer remains active');
    const busyAnswer=busyReceiver.messages.at(-1);
    assert.equal(busyAnswer.reason,'RECEIVER_BUSY');
    assert.equal(busyAnswer.file_id,busyRequest.file_id);
    assert.equal(busyAnswer.session_id,busyRequest.session_id);
    assert.equal(busyReceiver._fileTransfer.box.children.filter(node=>
        /Ещё один файл ожидает/.test(node.textContent)).length,1,'receiver has visible busy status');
    globalThis.DMashStorage=storageFor(busySender);
    assert.equal(await DmashFileRuntime.outcome(busySender,busyAnswer,busySender.activePeerId),true);
    const busyMeta=owned.get(busySender).get(busyRequest.file_id).meta;
    assert.equal(busyMeta.status,'waiting');
    assert(busyMeta.nextAttempt>Date.now(),'busy response rate-bounds retry');
    assert.equal(busySender.history[0].status,'WAITING','busy is not permanent rejection');
    assert(owned.get(busySender).get(busyRequest.file_id).blob,'busy preserves local file');
    busyMeta.nextAttempt=0;
    globalThis.nextSyntheticCallId='b'.repeat(64);
    await DmashFileRuntime.flush(busySender);
    const newerRequest=busySender.messages.at(-1).request,newerSession=sessions.at(-1);
    assert.equal(newerRequest.file_id,busyRequest.file_id,'retry keeps durable file identity');
    assert.notEqual(newerRequest.session_id,busyRequest.session_id,'retry gets a fresh transport session');
    await DmashFileRuntime.outcome(busySender,busyAnswer,busySender.activePeerId);
    assert.equal(newerSession.closed,undefined,'stale busy cannot close newer attempt');
    assert.equal(owned.get(busySender).get(busyRequest.file_id).meta.status,'connecting');
    globalThis.nextSyntheticCallId=null;
    DmashFileRuntime.cancel(busySender);DmashFileRuntime.cancel(busyReceiver);
    // An Account switch during the awaited vault read must never create an
    // object URL or attach the old Account's file to a same-peer chat card.
    const previewCore=core(),previewId='d'.repeat(64),previewRef={fileId:previewId,
        sha256:'e'.repeat(64),size:bytes.length,name:'synthetic.txt',mime:'text/plain'};
    const previewTarget=new Element(),previewCard=new Element();
    previewCard.dataset={fileId:previewId};previewCard.isConnected=true;
    previewCard.closest=()=>({id:'msg-box-synthetic'});
    previewCard.querySelector=selector=>selector==='.dmash-file-preview'?previewTarget:null;
    const oldQuery=document.querySelectorAll;
    document.querySelectorAll=()=>[previewCard];
    const originalGet=DmashFileVault.prototype.get;
    let releaseGet,urlCalls=0;
    DmashFileVault.prototype.get=()=>new Promise(resolve=>{releaseGet=resolve;});
    const oldCreateUrl=URL.createObjectURL;
    URL.createObjectURL=()=>{urlCalls++;return 'blob:synthetic';};
    try {
        const opening=DmashFileRuntime.openInline(previewCore,previewCore.activePeerId,previewRef,'synthetic');
        await new Promise(resolve=>setTimeout(resolve,0));
        assert.equal(typeof releaseGet,'function','preview vault read is pending');
        previewCore.changed=true;
        releaseGet({meta:{...previewRef},blob:new Blob([bytes])});
        await assert.rejects(opening,/Account changed/);
        assert.equal(urlCalls,0,'old Account bytes never become a BlobURL');
        assert.notEqual(previewCard.dataset.loaded,'true');
    } finally {
        document.querySelectorAll=oldQuery;
        DmashFileVault.prototype.get=originalGet;
        URL.createObjectURL=oldCreateUrl;
    }
    DmashFileRuntime.cancel(sender3);
    DmashFileRuntime.cancel(sender);DmashFileRuntime.cancel(receiver);
    console.log('file_runtime.test.js: durable intent, trusted auto-receive, inline history and retry dedupe passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
