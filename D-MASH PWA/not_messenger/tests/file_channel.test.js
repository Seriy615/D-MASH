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

    // Isolate the product's timer globals so host scheduling/real AES latency
    // cannot consume the 100ms protocol deadline in this pressure scenario.
    // Crypto, file bytes, frame delivery and authenticated ACKs remain genuine.
    const vm=require('node:vm'),fs=require('node:fs'),waiting=deferred(),timers=new Map();
    let clock=0,timerId=0;
    const scope={crypto,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,DataView,Map,Set,
        Blob,structuredClone,atob,btoa,Date:{now:()=>clock},
        setTimeout(fn,delay){const id=++timerId;timers.set(id,{at:clock+delay,fn,delay});if(delay===5)waiting.resolve();return id;},
        clearTimeout(id){timers.delete(id);}};
    vm.createContext(scope);
    vm.runInContext(fs.readFileSync(require.resolve('../js/file_channel.js'),'utf8'),scope);
    const ClockFileChannel=scope.DmashFileChannel.FileChannel;
    const tickPressure=async()=>{
        const [id,job]=[...timers].sort((a,b)=>a[1].at-b[1].at||a[0]-b[0])[0]||[];
        assert(job,'pressure wait must register a timer');
        assert.equal(job.delay,5,'advance the pressure poll, never an ACK deadline');
        timers.delete(id);clock=job.at;job.fn();
        await new Promise(resolve=>setImmediate(resolve));
    };
    const [pressureA,pressureB]=pair(),pressureSent=deferred(),pressureReceived=deferred(),pressureErrors=[];
    pressureA.bufferedAmount=200000;
    const sentIndices=[],ackIndices=[];let finalAck=null,senderComplete=false;
    const originalPressureSend=pressureA.send;
    pressureA.send=frame=>{
        assert.equal(pressureA.bufferedAmount,0,'never send before the buffer is explicitly released');
        sentIndices.push(new DataView(frame).getUint32(0));originalPressureSend(frame);
    };
    pressureB.send=frame=>{
        const index=new DataView(frame).getUint32(0);ackIndices.push(index);
        if(index===Math.ceil(manifest.size/manifest.chunk_bytes)){finalAck=structuredClone(frame);return;}
        queueMicrotask(()=>pressureA.onmessage?.({data:structuredClone(frame)}));
    };
    const pressureReceiver=new ClockFileChannel({channel:pressureB,manifest,
        onComplete:blob=>pressureReceived.resolve(blob),onError:error=>{pressureErrors.push(error);pressureReceived.resolve(null);}});
    const pressureSender=new ClockFileChannel({channel:pressureA,manifest,file,ackTimeoutMs:100,
        onComplete:()=>{senderComplete=true;pressureSent.resolve(true);},onError:error=>{pressureErrors.push(error);pressureSent.resolve(false);}});
    // This real-time watchdog only detects a broken test/event barrier. The
    // product ACK/backpressure clock above advances solely under test control.
    let watchdog;
    const stalled=new Promise((_,reject)=>{watchdog=setTimeout(()=>reject(Error('Pressure fixture stalled')),20000);});
    const bounded=promise=>Promise.race([promise,stalled]);
    try{
        await bounded(waiting.promise);
        assert.deepEqual(sentIndices,[],'sender is waiting while the buffer is full');
        await tickPressure();await tickPressure();
        assert.equal(clock,10);assert.deepEqual(sentIndices,[],'multiple pressure polls cannot send early');
        assert.equal(senderComplete,false);assert.equal(pressureReceiver.index,0);
        pressureA.bufferedAmount=0;await tickPressure();
        const blob=await bounded(pressureReceived.promise);
        assert(blob,'receiver must verify the entire file');
        assert.deepEqual(new Uint8Array(await blob.arrayBuffer()),content);
        assert.equal(senderComplete,false,'verified receiver cannot complete sender before final authenticated ACK');
        assert(pressureSender.pending.has(pressureSender.count));assert(finalAck);
        queueMicrotask(()=>pressureA.onmessage?.({data:finalAck}));
        assert.equal(await bounded(pressureSent.promise),true);
        const expected=Array.from({length:pressureSender.count+1},(_,index)=>index);
        assert.deepEqual(sentIndices,expected,'every data frame and END sent exactly once');
        assert.deepEqual(ackIndices,expected,'every chunk and END authenticated by receiver');
        assert.equal(pressureSender.complete,true);assert.equal(pressureReceiver.complete,true);
        assert.deepEqual(pressureErrors,[]);assert.equal(timers.size,0,'all ACK/pressure timers cleared');
    }finally{clearTimeout(watchdog);pressureSender.close();pressureReceiver.close();}
    await assert.rejects(describe({size:MAX_SIZE + 1}, 'a'.repeat(64)));
    console.log('file_channel.test.js: integrity, bounded pipeline, out-of-order/lost/duplicate ACK and cancellation passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
