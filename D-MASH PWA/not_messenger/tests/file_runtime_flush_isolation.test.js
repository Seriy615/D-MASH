const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto').webcrypto;
const source = fs.readFileSync(require.resolve('../js/file_runtime.js'), 'utf8');
const turn = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve};};
const row = (peer, operationId) => ({peer, operationId, fileId:'f'.repeat(64),
    sha256:'d'.repeat(64), size:1, type:'voip_file_complete', transportId:'e'.repeat(64),
    expiresAt:Math.floor(Date.now()/1000)+300});

function fixture() {
    const account = {generation:0, outcomes:[[]], outbound:[[]]}, sent = [], visits = [], timers = [];
    const core = {accountTransportMode:()=>'node-v4', shmon(){},
        confirmedNodeMediaPeerV4:async peer => {visits.push(peer);return {};},
        sendNodeMediaControlV4:async args => {sent.push(args);return {durable:true};}};
    class Vault {
        constructor() {this.generation = account.generation;}
        capture() {const generation=this.generation;return {check(){
            if (generation !== account.generation) throw Error('Account changed');
        }};}
        async listOutcomes() {return account.outcomes[this.generation];}
        async list() {return account.listHook ? account.listHook(this.generation) : account.outbound[this.generation];}
        async retireOutcome(operationId) {
            if (account.retireHook) await account.retireHook(operationId);
            account.outcomes[this.generation] = account.outcomes[this.generation].filter(x=>x.operationId!==operationId);
        }
    }
    const context = vm.createContext({crypto, TextEncoder, TextDecoder, console, Uint8Array, Date,
        // Retry scheduling is observed separately; it must not make this UNIT wait 30 s.
        setTimeout:callback=>{timers.push(callback);return timers.length;}, clearTimeout(){}, DMashStorage:{}, DmashFileVault:Vault});
    vm.runInContext(source, context, {filename:'file_runtime.js'});
    return {account,core,sent,visits,timers,runtime:context.DmashFileRuntime};
}

async function healthyOutcomesDrain() {
    const f=fixture();
    f.account.outcomes[0]=[row('1'.repeat(64),'3'.repeat(64)),row('2'.repeat(64),'4'.repeat(64))];
    await f.runtime.flush(f.core);
    assert.equal(f.sent.length,2,'fixture supports two healthy enqueues');
    assert.equal(f.account.outcomes[0].length,0,'fixture observes durable retirement');
}

async function failedPeerCannotStarveReadyPeer() {
    const f=fixture(), first='1'.repeat(64), second='2'.repeat(64);
    f.account.outcomes[0]=[row(first,'3'.repeat(64)),row(second,'4'.repeat(64))];
    f.core.confirmedNodeMediaPeerV4=async peer=>{
        f.visits.push(peer);if(peer===first)throw Error('temporary peer authority failure');return {};
    };
    await f.runtime.flush(f.core);
    assert.equal(f.sent.length,1,'first peer failure must not prevent ready later outcome enqueue');
    assert.equal(f.sent[0].peer,second);
    assert.equal(f.account.outcomes[0].length,1,'failed peer intent remains durable');
}

async function switchedAccountCannotWaitForOldOutcome() {
    const f=fixture(), oldPeer='1'.repeat(64), newPeer='2'.repeat(64), gate=deferred();
    f.account.outcomes[0]=[row(oldPeer,'3'.repeat(64))];
    f.account.outcomes[1]=[row(newPeer,'4'.repeat(64))];f.account.outbound[1]=[];
    f.core.confirmedNodeMediaPeerV4=async peer=>{
        f.visits.push(peer);return peer===oldPeer ? gate.promise : {};
    };
    const oldFlush=f.runtime.flush(f.core);await turn();
    f.runtime.cancel(f.core);f.account.generation=1;
    const newFlush=f.runtime.flush(f.core);await turn();
    const visitedNew=f.visits.includes(newPeer);
    gate.resolve({});await Promise.all([oldFlush,newFlush]);
    assert.equal(visitedNew,true,'new Account outcome must progress while old authority await is unresolved');
    assert.equal(f.sent.some(x=>x.peer===oldPeer),false,'old Account callback must remain cancelled');
}

async function switchedAccountCannotWaitForOldOutbound() {
    const f=fixture(), gate=deferred(), newPeer='2'.repeat(64);
    f.account.outbound[1]=[];f.account.outcomes[1]=[row(newPeer,'4'.repeat(64))];
    f.account.listHook=generation=>generation===0 ? gate.promise : [];
    const oldFlush=f.runtime.flush(f.core);await turn();
    f.runtime.cancel(f.core);f.account.generation=1;
    const newFlush=f.runtime.flush(f.core);await turn();
    const visitedNew=f.visits.includes(newPeer);
    gate.resolve([]);await Promise.all([oldFlush,newFlush]);
    assert.equal(visitedNew,true,'new Account flush must progress while old outbound vault read is unresolved');
}

async function failedEnqueueCannotStarveReadyPeer() {
    const f=fixture(), first='1'.repeat(64),second='2'.repeat(64);
    f.account.outcomes[0]=[row(first,'3'.repeat(64)),row(second,'4'.repeat(64))];
    f.core.sendNodeMediaControlV4=async args=>{
        if(args.peer===first)throw Error('uncertain enqueue');f.sent.push(args);return {durable:true};
    };
    await f.runtime.flush(f.core);
    assert.equal(f.sent.length,1);assert.equal(f.sent[0].peer,second);
    assert.equal(f.account.outcomes[0][0].operationId,'3'.repeat(64),'uncertain operation retains exact id');
    assert.equal(f.timers.length,1,'failed intent gets bounded retry');
}

async function failedRetireCannotStarveReadyPeer() {
    const f=fixture();
    f.account.outcomes[0]=[row('1'.repeat(64),'3'.repeat(64)),row('2'.repeat(64),'4'.repeat(64))];
    f.account.retireHook=async id=>{if(id==='3'.repeat(64))throw Error('temporary disk failure');};
    await f.runtime.flush(f.core);
    assert.equal(f.sent.length,2);assert.equal(f.account.outcomes[0].length,1);
}

async function oldCompletionCannotReleaseNewLockOrScheduleRetry() {
    const f=fixture(), oldPeer='1'.repeat(64),newPeer='2'.repeat(64),oldGate=deferred(),newGate=deferred();
    f.account.outcomes[0]=[row(oldPeer,'3'.repeat(64))];
    f.account.outcomes[1]=[row(newPeer,'4'.repeat(64))];f.account.outbound[1]=[];
    f.core.confirmedNodeMediaPeerV4=async peer=>{
        f.visits.push(peer);return peer===oldPeer ? oldGate.promise : newGate.promise;
    };
    const oldFlush=f.runtime.flush(f.core);await turn();
    f.runtime.cancel(f.core);f.account.generation=1;
    const newFlush=f.runtime.flush(f.core);await turn();
    oldGate.resolve({});await oldFlush;
    assert.equal(f.runtime.flush(f.core),newFlush,'old completion cannot clear the current session lock');
    assert.equal(f.timers.length,0,'old Account abort cannot arm a current Account retry timer');
    newGate.resolve({});await newFlush;
    assert.equal(f.sent.length,1);assert.equal(f.sent[0].peer,newPeer);
    assert.equal(f.account.outcomes[0].length,1,'old durable outcome remains untouched');
}

(async()=>{
    let failures=0;
    for(const test of [healthyOutcomesDrain,failedPeerCannotStarveReadyPeer,switchedAccountCannotWaitForOldOutcome,switchedAccountCannotWaitForOldOutbound,failedEnqueueCannotStarveReadyPeer,failedRetireCannotStarveReadyPeer,oldCompletionCannotReleaseNewLockOrScheduleRetry]) {
        try {await test();console.log('PASS',test.name);}
        catch(error) {failures++;console.error('FAIL',test.name,error.message);}
    }
    process.exitCode=failures?1:0;
})();
