const assert = require('node:assert/strict');
require('../js/file_channel.js');
const {FileChannel, describe, MAX_SIZE} = DmashFileChannel;
function pair(transform = value => value, ackTransform = value => value) {
    const a = {readyState: 'open', bufferedAmount: 0}, b = {...a};
    a.send = frame => {const data = transform(structuredClone(frame)); if (data) queueMicrotask(() => b.onmessage?.({data}));};
    b.send = frame => {const data=ackTransform(structuredClone(frame));if(data)queueMicrotask(() => a.onmessage?.({data}));};
    for (const [self, other] of [[a,b],[b,a]]) self.close = () => {
        if (self.readyState === 'closed') return;
        self.readyState = other.readyState = 'closed'; queueMicrotask(() => {self.onclose?.(); other.onclose?.();});
    };
    return [a,b];
}
const deferred = () => {let resolve; const promise = new Promise(r => {resolve=r;}); return {promise, resolve};};
async function transfer(file, manifest, transform, afterComplete) {
    const [a,b] = pair(transform), sent = deferred(), received = deferred(), errors = [];
    const receiver = new FileChannel({channel: b, manifest, onComplete: blob => received.resolve(blob),
        onError: e => {errors.push(e); received.resolve(null);}});
    const sender = new FileChannel({channel: a, manifest, file, onComplete: () => sent.resolve(true),
        onError: e => {errors.push(e); sent.resolve(false);}});
    const result = await Promise.all([sent.promise, received.promise]);
    afterComplete?.({a,b,sender,receiver,errors});
    sender.close(); receiver.close(); return {result, errors, sender, receiver};
}
(async () => {
    const content = new Uint8Array(3 * 32768 + 13); content.forEach((_,i) => {content[i] = i % 251;});
    const file = new File([content], 'private.bin', {type:'application/octet-stream'});
    const manifest = await describe(file, 'a'.repeat(64));
    const normal = await transfer(file, manifest);
    assert(normal.result[0]); assert.equal(normal.errors.length, 0);
    assert.deepEqual(new Uint8Array(await normal.result[1].arrayBuffer()), content);
    assert.equal(normal.receiver.parts.length, 0);
    assert.equal(normal.sender.manifest.key, null);
    const terminal = await transfer(file, manifest, undefined, ({b,receiver,errors}) => {
        assert(receiver.complete, 'Whole-file SHA-256 must be verified before terminal event');
        b.onerror?.(new Event('error'));
        assert.equal(errors.length, 0, 'A late DataChannel error must not revoke verified completion');
        assert.equal(receiver.closed, false, 'Verified receiver remains available until normal channel close');
    });
    assert(terminal.result[0]);
    let damaged = false;
    const tampered = await transfer(file, manifest, frame => {
        if (!damaged) {new Uint8Array(frame)[20] ^= 1; damaged = true;} return frame;
    });
    assert.equal(tampered.result[0], false); assert.equal(tampered.result[1], null);
    assert(tampered.errors.length > 0);
    const reordered = await transfer(file, manifest, frame => {new DataView(frame).setUint32(0, 12); return frame;});
    assert.equal(reordered.result[1], null);
    const wrongHash = await transfer(file, {...manifest, sha256:'b'.repeat(64)});
    assert.equal(wrongHash.result[1], null, 'Authenticated chunks do not bypass whole-file hash');

    // Final transport ACK must wait for durable receiver history commit.
    const [commitA,commitB]=pair(), entered=deferred(), release=deferred(), finished=deferred();let sentBeforeCommit=false;
    const commitReceiver=new FileChannel({channel:commitB,manifest,onCommit:async()=>{entered.resolve();await release.promise;},onError:e=>{throw e;}});
    const commitSender=new FileChannel({channel:commitA,manifest,file,onComplete:()=>{sentBeforeCommit=true;finished.resolve();},onError:e=>{throw e;}});
    await entered.promise;assert.equal(sentBeforeCommit,false);assert(commitSender.pending);
    release.resolve();await finished.promise;assert(commitReceiver.complete);commitSender.close();commitReceiver.close();

    const [a,b] = pair(() => null);
    const cancelled = deferred();
    const sender = new FileChannel({channel:a, manifest, file, onError: () => cancelled.resolve()});
    while (!sender.pending) await new Promise(r => setTimeout(r, 1));
    a.close(); await cancelled.promise;
    assert(sender.closed); assert.equal(sender.pending, null);

    // Ordered data may receive authenticated ACKs out of order. The bounded
    // window must count each byte exactly once and wait for the final ACK.
    const wider=new File([new Uint8Array(16*32768+13)],'window.bin');
    const wideManifest=await describe(wider,'c'.repeat(64));
    const [wa,wb]=pair(),wideSent=deferred(),wideReceived=deferred(),wideErrors=[];
    let wideSender,maxPending=0,firstAck=null;const progress=[];
    const originalSend=wa.send;
    wa.send=frame=>{maxPending=Math.max(maxPending,wideSender?.pending?.size||0);originalSend(frame);};
    wb.send=frame=>{
        const index=new DataView(frame).getUint32(0);
        if(index===0){firstAck=structuredClone(frame);return;}
        if(index===1&&firstAck){
            const held=firstAck;firstAck=null;
            queueMicrotask(()=>wa.onmessage?.({data:structuredClone(frame)}));
            queueMicrotask(()=>wa.onmessage?.({data:held}));return;
        }
        queueMicrotask(()=>wa.onmessage?.({data:structuredClone(frame)}));
    };
    const wideReceiver=new FileChannel({channel:wb,manifest:wideManifest,onComplete:blob=>wideReceived.resolve(blob),
        onError:error=>{wideErrors.push(error);wideReceived.resolve(null);}});
    wideSender=new FileChannel({channel:wa,manifest:wideManifest,file:wider,
        onProgress:done=>progress.push(done),
        onComplete:()=>wideSent.resolve(true),onError:error=>{wideErrors.push(error);wideSent.resolve(false);}});
    const [wideDone,wideBlob]=await Promise.all([wideSent.promise,wideReceived.promise]);
    assert.equal(wideDone,true);assert.equal(wideBlob.size,wider.size);
    assert.equal(wideErrors.length,0);
    assert(maxPending>=2&&maxPending<=8,'window remains bounded and pipelines at least two chunks');
    assert.equal(progress.at(-1),wider.size);
    assert(progress.every((bytes,index)=>index===0||bytes>progress[index-1]),
        'out-of-order ACKs cannot double-count progress');
    wideSender.close();wideReceiver.close();

    const [lostA,lostB]=pair(value=>value,frame=>new DataView(frame).getUint32(0)===0?null:frame);
    const lostSent=deferred(),lostReceived=deferred();
    const lostReceiver=new FileChannel({channel:lostB,manifest,onComplete:()=>lostReceived.resolve(true),
        onError:()=>lostReceived.resolve(false)});
    const lostSender=new FileChannel({channel:lostA,manifest,file,ackTimeoutMs:25,
        onComplete:()=>lostSent.resolve(true),onError:()=>lostSent.resolve(false)});
    assert.deepEqual(await Promise.all([lostSent.promise,lostReceived.promise]),[false,false],
        'missing authenticated ACK cannot produce VERIFIED');
    lostSender.close();lostReceiver.close();

    const [dupA,dupB]=pair(),dupSent=deferred(),dupReceived=deferred();
    dupB.send=frame=>{
        const index=new DataView(frame).getUint32(0);
        queueMicrotask(()=>dupA.onmessage?.({data:structuredClone(frame)}));
        if(index===0)queueMicrotask(()=>dupA.onmessage?.({data:structuredClone(frame)}));
    };
    const dupReceiver=new FileChannel({channel:dupB,manifest,onComplete:()=>dupReceived.resolve(true),
        onError:()=>dupReceived.resolve(false)});
    const dupSender=new FileChannel({channel:dupA,manifest,file,onComplete:()=>dupSent.resolve(true),
        onError:()=>dupSent.resolve(false)});
    assert.deepEqual(await Promise.all([dupSent.promise,dupReceived.promise]),[false,false],
        'duplicate ACK is rejected and cannot complete a file');
    dupSender.close();dupReceiver.close();

    const [pressureA,pressureB]=pair(),pressureSent=deferred(),pressureReceived=deferred();
    pressureA.bufferedAmount=200000;
    let firstSendAt=0;const pressureStart=Date.now(),originalPressureSend=pressureA.send;
    pressureA.send=frame=>{firstSendAt=Date.now();originalPressureSend(frame);};
    setTimeout(()=>{pressureA.bufferedAmount=0;},15);
    const pressureReceiver=new FileChannel({channel:pressureB,manifest,
        onComplete:()=>pressureReceived.resolve(true),onError:()=>pressureReceived.resolve(false)});
    const pressureSender=new FileChannel({channel:pressureA,manifest,file,ackTimeoutMs:100,
        onComplete:()=>pressureSent.resolve(true),onError:()=>pressureSent.resolve(false)});
    assert.deepEqual(await Promise.all([pressureSent.promise,pressureReceived.promise]),[true,true]);
    assert(firstSendAt-pressureStart>=10,'bufferedAmount backpressure waits instead of overflowing');
    pressureSender.close();pressureReceiver.close();
    await assert.rejects(describe({size:MAX_SIZE + 1}, 'a'.repeat(64)));
    console.log('file_channel.test.js: integrity, bounded pipeline, out-of-order/lost/duplicate ACK and cancellation passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
