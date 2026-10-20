'use strict';
const assert = require('node:assert/strict');
global.nacl = require('../js/vendor/nacl-fast.min.js');
require('../js/secure_session.js');
const Authority = require('../js/device_authority_v3.js');
const fakeProof=(args,tag='test')=>({v:1,type:args.activationType,resource:args.resource instanceof Uint8Array?Buffer.from(args.resource).toString('hex'):args.resource,
    nonce:args.startNonce,expires_at:args.expiresAt,difficulty:args.difficulty,
    digest:require('node:crypto').createHash('sha256').update(JSON.stringify({tag,kind:args.activationType,resource:String(args.resource),expiry:args.expiresAt,nonce:args.startNonce})).digest('hex')});
(async () => {
    const saved = new Map(), calls = [], work = [];
    let registered = false;
    const client = { nodeId: 'aa'.repeat(32), transportPublicKey: 'bb'.repeat(32), resourcePowDifficulty: 22,
        session: { transcriptHash: new Uint8Array(32).fill(3) },
        request: async (op, payload, rid) => {
            calls.push({op, payload: structuredClone(payload), rid});
            if (op === 'REGISTER_DNSS' && !registered && !payload.pow) throw Error('DNSS_NOT_REGISTERED');
            if (op === 'REGISTER_DNSS') registered = true;
            if (op === 'REGISTER_ROUTE' && !payload.pow) throw Error('INVALID_RESOURCE_POW');
            return {type: op + '_RESULT'};
        }
    };
    const options = { deviceRoot: { deviceMaterial: async (name, create) => {
        if (!saved.has(name)) saved.set(name, create()); return saved.get(name);
    } }, mine: async args => { work.push(args); return fakeProof(args); } };
    const authority = new Authority(client, options);
    await Promise.all([authority.bind(), authority.bind()]);
    assert.equal(work.length, 1, 'simultaneous bind shares one work task');
    const original = Buffer.from(authority.dnss).toString('hex');
    authority.close();
    const reconnect = new Authority(client, options);
    await reconnect.bind();
    assert.equal(Buffer.from(reconnect.dnss).toString('hex'), original);
    assert.equal(work.length, 1, 'reconnect must not mine while registration survives');
    registered = false;
    const restart = new Authority(client, options);
    await restart.bind();
    assert.equal(Buffer.from(restart.dnss).toString('hex'), original);
    assert.equal(work.length, 2, 'Node restart repeats work for the same DNSS');
    const signing = nacl.sign.keyPair();
    const route = {kind: 'PRIVATE', routeId: 'private-locator', signing, generation: 1, expiresAt: 2000};
    await restart.route('REGISTER_ROUTE', route);
    const call = calls.at(-1), auth = call.payload.authorization;
    assert.equal('entry_grant' in call.payload, false);
    assert.equal(work.at(-1).activationType, 'PRIVATE_ROUTE');
    const transcript = session => new TextEncoder().encode('D-MASH|ROUTE-AUTH|V3\0' + DmashSecureSession.canonical({
        node_id: client.nodeId, session, dnss: original, operation: call.op, request_id: call.rid,
        kind: auth.kind, route_id: auth.route_id, public_key: auth.public_key,
        generation: auth.generation, expires_at: auth.expires_at
    }));
    assert.ok(nacl.sign.detached.verify(transcript('03'.repeat(32)), DmashSecureSession.unb64(auth.signature), signing.publicKey));
    assert.equal(nacl.sign.detached.verify(transcript('04'.repeat(32)), DmashSecureSession.unb64(auth.signature), signing.publicKey), false);
    await restart.route('START_PROBE', route, {route_locator: 'destination'});
    assert.equal(calls.at(-1).payload.back_route_locator, route.routeId);
    assert.notEqual(calls.at(-1).rid, call.rid);
    client.resourcePowDifficulty = 256;
    await assert.rejects(restart.work('DNSS', restart.dnss), /policy/);
    // Two concurrent REGISTER_ROUTE calls may carry distinct request IDs and
    // signatures, but the exact same in-flight proof challenge should be mined
    // once for this Authority/session/kind/resource/difficulty tuple.
    const signed=[],proofs=[];let releaseMine;
    const miningGate=new Promise(resolve=>{releaseMine=resolve;});
    const simultaneousClient={...client,resourcePowDifficulty:22,
        session:{transcriptHash:new Uint8Array(32).fill(9)},
        request:async(operation,payload,requestId)=>{
            if(operation==='REGISTER_ROUTE'){
                signed.push({requestId,signature:payload.authorization.signature,hasProof:!!payload.pow});
                if(!payload.pow)throw Error('INVALID_RESOURCE_POW');
            }
            return {type:operation+'_RESULT'};
        }};
    const shared=new Authority(simultaneousClient,{deviceRoot:options.deviceRoot,
        mine:async args=>{proofs.push({kind:args.activationType,resource:args.resource,difficulty:args.difficulty});await miningGate;return fakeProof(args,'inflight');}});
    const simultaneousRoute={kind:'PRIVATE',routeId:'same-private-locator',signing,generation:2,expiresAt:3000};
    const first=shared.route('REGISTER_ROUTE',simultaneousRoute),second=shared.route('REGISTER_ROUTE',simultaneousRoute);
    await new Promise(resolve=>setTimeout(resolve,0));releaseMine();await Promise.all([first,second]);
    assert.equal(new Set(signed.filter(call=>call.hasProof).map(call=>call.requestId)).size,2,'coalesced work reused the same signed request ID');
    assert.equal(new Set(signed.filter(call=>call.hasProof).map(call=>call.signature)).size,2,'coalesced work reused the same route signature');
    assert.equal(proofs.length,1,'same-route concurrent REGISTER_ROUTE mined duplicate resource work');
    await shared.route('REGISTER_ROUTE',simultaneousRoute);
    assert.equal(proofs.length,2,'completed work was cached as a hidden successor authorization');
    simultaneousClient.session.transcriptHash=new Uint8Array(32).fill(10);
    await shared.route('REGISTER_ROUTE',simultaneousRoute);
    assert.equal(proofs.length,3,'changed authenticated session reused old resource work');
    simultaneousClient.resourcePowDifficulty=23;
    await shared.route('REGISTER_ROUTE',simultaneousRoute);
    assert.equal(proofs.length,4,'changed resource difficulty reused old work');
    await shared.route('REGISTER_ROUTE',{...simultaneousRoute,routeId:'another-private-locator'});
    assert.equal(proofs.length,5,'different route reused old resource work');
    await shared.route('REGISTER_ROUTE',{...simultaneousRoute,kind:'PUBLIC',entryGrant:{testOnly:true}});
    assert.equal(proofs.length,6,'different activation kind reused old resource work');
    shared.close();
    // Mirror DeviceRegistration.authorize_route: an identical candidate skips
    // consumed PoW, but changed expiry still needs a fresh globally unique digest.
    const backendRows=new Map(),backendUsed=new Set(),backendWork=[],backendRequests=[];let forceReplay=false,injectLocalCollision=false;
    const backendClient={...simultaneousClient,session:{transcriptHash:new Uint8Array(32).fill(14)},
        request:async(operation,payload,requestId)=>{
            if(operation==='REGISTER_ROUTE'){
                backendRequests.push(requestId);
                const auth=payload.authorization,candidate=JSON.stringify({kind:auth.kind,publicKey:auth.public_key,generation:auth.generation,expiresAt:auth.expires_at});
                if(backendRows.get(auth.route_id)!==candidate){
                    if(!payload.pow)throw Error('INVALID_RESOURCE_POW');
                    if(forceReplay){forceReplay=false;throw Error('REPLAYED_RESOURCE_POW');}
                    if(backendUsed.has(payload.pow.digest))throw Error('REPLAYED_RESOURCE_POW');
                    backendUsed.add(payload.pow.digest);backendRows.set(auth.route_id,candidate);
                }
            }
            return {type:operation+'_RESULT'};
        }};
    const backendAuthority=new Authority(backendClient,{deviceRoot:options.deviceRoot,mine:async args=>{
        backendWork.push(args);const nonce=args.startNonce??0,digest=injectLocalCollision?[...backendUsed][0]:require('node:crypto').createHash('sha256').update(JSON.stringify({resource:args.resource,expiresAt:args.expiresAt,nonce})).digest('hex');injectLocalCollision=false;
        return {v:1,type:args.activationType,resource:args.resource,nonce,expires_at:args.expiresAt,difficulty:args.difficulty,
            digest};
    }});
    const savedNow=Date.now;Date.now=()=>1700000000000;
    try{
        const same={...simultaneousRoute,expiresAt:4000};await Promise.all([backendAuthority.route('REGISTER_ROUTE',same),backendAuthority.route('REGISTER_ROUTE',same)]);
        assert.equal(backendWork.length,1,'identical registration candidate mined duplicate work');
        assert.equal(new Set(backendRequests).size,2,'same candidate reused signed request ID');
        const changed={...same,expiresAt:4001},changedAgain={...same,expiresAt:4002};forceReplay=true;await Promise.all([backendAuthority.route('REGISTER_ROUTE',changed),backendAuthority.route('REGISTER_ROUTE',changedAgain)]);
        assert.equal(backendWork.length,4,'different candidates shared work or did not remine after Node replay refusal');
        assert.equal(backendUsed.size,3,'different registration candidates reused consumed proof digest');
        injectLocalCollision=true;await backendAuthority.route('REGISTER_ROUTE',{...same,generation:3,expiresAt:4003});
        assert.equal(backendWork.length,6,'local digest collision did not remine changed generation');
        assert.equal(backendUsed.size,4,'changed generation submitted a consumed proof digest');
    }finally{Date.now=savedNow;backendAuthority.close();}
    const held=[];
    const scopedClient={...simultaneousClient,resourcePowDifficulty:22,
        session:{transcriptHash:new Uint8Array(32).fill(11)}};
    const scoped=new Authority(scopedClient,{deviceRoot:options.deviceRoot,
        mine:args=>new Promise(resolve=>held.push({args,resolve}))});
    const until=async count=>{for(let i=0;i<40&&held.length<count;i++)await new Promise(resolve=>setTimeout(resolve,0));assert.equal(held.length,count,'route work did not enter mine gate');};
    const oldSession=scoped.route('REGISTER_ROUTE',simultaneousRoute);await until(1);
    scopedClient.session.transcriptHash=new Uint8Array(32).fill(12);
    const newSession=scoped.route('REGISTER_ROUTE',simultaneousRoute);await until(2);
    assert.notEqual(held[0].args,held[1].args,'in-flight work was shared across authenticated sessions');
    held[0].resolve(fakeProof(held[0].args,'old'));held[1].resolve(fakeProof(held[1].args,'new'));
    await assert.rejects(oldSession,/Route work owner changed/,'old-session proof escaped after session changed');
    await newSession;
    const closing=scoped.route('REGISTER_ROUTE',simultaneousRoute);await until(3);
    scoped.close();held[2].resolve(fakeProof(held[2].args,'after-close'));
    await assert.rejects(closing,/Device authority closed/,'closed Authority sent a stale work proof');
    await assert.rejects(scoped.route('REGISTER_ROUTE',simultaneousRoute),/Device authority closed/,'closed Authority reopened route ownership');
    let enteredRequest,finishRequest;
    const requestStarted=new Promise(resolve=>{enteredRequest=resolve;});
    const requestGate=new Promise(resolve=>{finishRequest=resolve;});
    const lateClient={...simultaneousClient,session:{transcriptHash:new Uint8Array(32).fill(13)},
        request:async operation=>{if(operation==='REGISTER_ROUTE'){enteredRequest();await requestGate;}return {type:operation+'_RESULT'};}};
    const lateAuthority=new Authority(lateClient,{deviceRoot:options.deviceRoot,mine:async()=>assert.fail('successful route request must not mine')});
    const lateResult=lateAuthority.route('REGISTER_ROUTE',simultaneousRoute);
    await requestStarted;lateAuthority.close();finishRequest();
    await assert.rejects(lateResult,/Device authority closed/,'late Node response resolved after owner close');
    console.log('Device v3 authority lifecycle and cryptographic proof tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
