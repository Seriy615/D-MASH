'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
const nacl=global.nacl,discovery=require('../js/route_discovery_v4.js');
const pairing=require('../js/account_pairing_v2.js').createCodec({nacl,discovery});
const {createBindingCodec}=require('../js/account_route_binding_v2.js');
const hex=bytes=>Buffer.from(bytes).toString('hex'),seed=n=>new Uint8Array(32).fill(n);
let now=1800000000;
const api=createBindingCodec({nacl,discovery,pairing,clock:()=>now});
function person(n){return {account:nacl.sign.keyPair.fromSeed(seed(n)),box:nacl.box.keyPair.fromSecretKey(seed(n+1)),route:nacl.sign.keyPair.fromSeed(seed(n+2)),discovery:nacl.sign.keyPair.fromSeed(seed(n+3)),discoveryBox:nacl.box.keyPair.fromSecretKey(seed(n+4)),recipient:nacl.box.keyPair.fromSecretKey(seed(n+5)),n};}
const alice=person(1),bob=person(11),mallory=person(21),people=[alice,bob].sort((a,b)=>hex(a.account.publicKey)<hex(b.account.publicKey)?-1:1);
const expectedParticipants=people.map(p=>hex(p.account.publicKey));
function bundle(p,options={}){
 const generation=options.generation??1,issued_at=1800000000;
 const body={type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:hex(seed(options.id??p.n+30)),generation,issued_at,expires_at:issued_at+600,previous_binding:options.previous??null,intended_peer:options.target??null,contribution:hex(seed(options.contribution??p.n+60)),account_keys:{signing:hex(p.account.publicKey),box:hex(p.box.publicKey),kem_profile:options.profile??'LEGACY_KYBER768_BUNDLE_V1',kem_public:Buffer.alloc(1184,p.n).toString('base64url')},inbound_certificate:discovery.issueCertificate(p.route,p.discovery.publicKey,p.discoveryBox.publicKey,p.recipient.publicKey,{generation,issuedAt:issued_at,expiresAt:issued_at+900})};
 return pairing.sign(body,p.account.secretKey,{now,localAccount:options.target??undefined}).serialized;
}
const context=(committed=null)=>({expectedParticipants,committed});
const throws=(fn,code)=>assert.throws(fn,e=>!code||e.code===code);
const rejects=(fn,code)=>assert.rejects(fn,e=>!code||e.code===code);
const snapshot=c=>({generation:c.binding.generation,binding_digest:c.digest,participants:expectedParticipants});
function receipts(candidate){const accept=api.signReceipt(candidate,'ACCEPT',people[0].account.secretKey),confirm=api.signReceipt(candidate,'CONFIRM',people[1].account.secretKey,accept);return [accept,confirm];}
(async()=>{
 const originalSecrets=people.map(p=>p.account.secretKey.slice()),a=bundle(alice),b=bundle(bob,{target:hex(alice.account.publicKey)});
 const candidate=await api.prepare([a,b],context());
 const profile='ACCOUNT_STATIC_LEGACY_KYBER768_V1',newA=bundle(alice,{profile}),newB=bundle(bob,{profile,target:hex(alice.account.publicKey)});
 await rejects(()=>api.prepare([newA,b],context()),'PROFILE');
 assert.equal((await api.prepare([newA,newB],context())).binding.kem_profile,profile);
 assert.equal(candidate.status,'UNSIGNED_CANDIDATE');assert(Object.isFrozen(candidate.binding.participants[0]));
 const reverse=await api.prepare([b,a],context());assert.equal(reverse.serialized,candidate.serialized);assert.equal(reverse.digest,candidate.digest);
 const signed=receipts(candidate);
 assert.equal(api.verifyReceipts(candidate,signed,{committed:null}).status,'BILATERAL_CANDIDATE');
 assert.deepEqual(api.verifyReceipts(candidate,signed.slice().reverse(),{committed:null}).receipts,signed);
 assert.deepEqual(receipts(candidate),signed,'deterministic exact receipt retry');
 assert.deepEqual(people.map(p=>p.account.secretKey),originalSecrets,'caller keys untouched');
 throws(()=>api.signReceipt({...candidate},'ACCEPT',people[0].account.secretKey),'UNVERIFIED_BINDING');
 throws(()=>api.signReceipt(candidate,'CONFIRM',people[1].account.secretKey),'SIZE');
 throws(()=>api.signReceipt(candidate,'ACCEPT',people[1].account.secretKey),'SIGNER_MISMATCH');
 throws(()=>api.verifyReceipts(candidate,[signed[0]],{committed:null}),'BOTH_RECEIPTS_REQUIRED');
 throws(()=>api.verifyReceipts(candidate,[signed[0],signed[0]],{committed:null}),'BOTH_RECEIPTS_REQUIRED');
 throws(()=>api.verifyReceipts(candidate,signed,{}),'COMMITTED_CONTEXT_REQUIRED');
 throws(()=>api.verifyReceipt(candidate,' '+signed[0]),'NON_CANONICAL');
 throws(()=>api.verifyReceipt(candidate,signed[0].replace('"version":2','"version":2,"version":2')),'NON_CANONICAL');
 throws(()=>api.verifyReceipt(candidate,'x'.repeat(2049)),'SIZE');
 for(const patch of [{binding_digest:'ab'.repeat(32)},{signer:hex(mallory.account.publicKey)},{phase:'CONFIRM'},{extra:1},{version:1},{signature:'01'+'00'.repeat(63)}]){
  throws(()=>api.verifyReceipt(candidate,JSON.stringify({...JSON.parse(signed[0]),...patch})));
 }
 // Malleated valid signature scalar must not create a second canonical receipt.
 const malleated=JSON.parse(signed[0]),sig=Buffer.from(malleated.signature,'hex'),order=Buffer.from('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010','hex');let carry=0;
 for(let i=0;i<32;i++){const sum=sig[i+32]+order[i]+carry;sig[i+32]=sum&255;carry=sum>>>8;}malleated.signature=hex(sig);
 throws(()=>api.verifyReceipt(candidate,JSON.stringify(malleated)),'NON_CANONICAL_SIGNATURE');
 // Correct signatures still cannot move across certificate, peer or offer context.
 const substitute=JSON.parse(a);substitute.inbound_certificate=JSON.parse(b).inbound_certificate;
 await rejects(()=>api.prepare([JSON.stringify(substitute),b],context()));
 await rejects(()=>api.prepare([a,bundle(mallory)],context()),'IDENTITY_MISMATCH');
 await rejects(()=>api.prepare([a,a],context()),'SELF_PAIRING');
 await rejects(()=>api.prepare([a,bundle(bob,{target:hex(mallory.account.publicKey)})],context()),'TARGET_MISMATCH');
 await rejects(()=>api.prepare([a,bundle(bob,{id:alice.n+30})],context()),'DUPLICATE_OFFER');
 await rejects(()=>api.prepare([a,bundle(bob,{contribution:alice.n+60})],context()),'DUPLICATE_OFFER');
 await rejects(()=>api.prepare([a,bundle({...bob,box:alice.box})],context()),'KEY_ROLE_REUSE');
 await rejects(()=>api.prepare([a,b],{expectedParticipants}), 'COMMITTED_CONTEXT_REQUIRED');
 // Crossed fresh OOB offers: deterministic ordering is advisory, no receipt/activation.
 const crossed=await api.prepare([bundle(alice,{id:90,contribution:91}),bundle(bob,{id:92,contribution:93})],context());
 assert.equal(api.compareCandidates(candidate,crossed),-api.compareCandidates(crossed,candidate));
 assert.notEqual(api.compareCandidates(candidate,crossed),0);assert.equal(api.compareCandidates(candidate,reverse),0);
 throws(()=>api.verifyReceipts(crossed,signed,{committed:null}),'RECEIPT_CONTEXT');
 throws(()=>api.signReceipt(crossed,'CONFIRM',people[1].account.secretKey,signed[0]),'RECEIPT_CONTEXT');
 const crossedSigned=receipts(crossed);
 throws(()=>api.verifyReceipts(crossed,crossedSigned,{committed:snapshot(candidate)}),'GENERATION_CONFLICT');
 assert.equal(api.verifyReceipts(candidate,signed,{committed:snapshot(candidate)}).status,'IDEMPOTENT_REPLAY');
 const replay=await api.prepare([a,b],context(snapshot(candidate)));assert.equal(replay.digest,candidate.digest);
 await rejects(()=>api.prepare([bundle(alice,{id:90,contribution:91}),bundle(bob,{id:92,contribution:93})],context(snapshot(candidate))),'GENERATION_CONFLICT');
 const updateBundles=[bundle(alice,{generation:2,target:hex(bob.account.publicKey),previous:candidate.digest}),bundle(bob,{generation:2,previous:candidate.digest,target:hex(alice.account.publicKey)})];
 const update=await api.prepare(updateBundles,context(snapshot(candidate)));const updatedReceipts=receipts(update);
 assert.equal(api.verifyReceipts(update,updatedReceipts,{committed:snapshot(candidate)}).status,'BILATERAL_CANDIDATE');
 throws(()=>api.compareCandidates(candidate,update),'INCOMPARABLE_CANDIDATES');
 throws(()=>api.verifyReceipts(candidate,signed,{committed:snapshot(update)}),'GENERATION_ROLLBACK');
 await rejects(()=>api.prepare(updateBundles,context()),'PREDECESSOR_REQUIRED');
 await rejects(()=>api.prepare([bundle(alice,{generation:2,target:hex(bob.account.publicKey),previous:'ab'.repeat(32)}),bundle(bob,{generation:2,target:hex(alice.account.publicKey),previous:'ab'.repeat(32)})],context(snapshot(candidate))),'PREDECESSOR_MISMATCH');
 await rejects(()=>api.prepare([a,updateBundles[1]],context()),'BINDING_CONTEXT');
 await rejects(()=>api.prepare([bundle(alice,{generation:2,previous:candidate.digest}),updateBundles[1]],context(snapshot(candidate))),'TARGET_REQUIRED');
 const wrongIdentity={...snapshot(candidate),participants:[expectedParticipants[0],hex(mallory.account.publicKey)]};
 throws(()=>api.verifyReceipts(candidate,signed,{committed:wrongIdentity}),'IDENTITY_MISMATCH');
 if(process.env.DMASH_PAIRING_PYNACL==='1'){
  const payload={bundles:[a,b],binding:candidate.serialized,digest:candidate.digest,receipts:signed};
  const py=`import sys,json,hashlib,struct
from nacl.signing import VerifyKey
p=json.load(sys.stdin)
canon=lambda x:json.dumps(x,separators=(',',':'),ensure_ascii=True).encode()
hashhex=lambda x:hashlib.sha256(x).hexdigest()
bundles=sorted([(json.loads(raw),raw) for raw in p['bundles']],key=lambda pair:pair[0]['account_keys']['signing'])
members=[dict(account=b['account_keys']['signing'],bundle_digest=hashhex(raw.encode()),contribution=b['contribution'],certificate_digest=hashhex(canon(b['inbound_certificate']))) for b,raw in bundles]
binding=dict(type='DMASH_ACCOUNT_ROUTE_BINDING_V2',version=2,transport_version=4,kem_profile=bundles[0][0]['account_keys']['kem_profile'],generation=bundles[0][0]['generation'],previous_binding=bundles[0][0]['previous_binding'],participants=members,expires_at=min(b['expires_at'] for b,raw in bundles))
assert canon(binding).decode()==p['binding']
assert hashhex(b'D-MASH|ACCOUNT-ROUTE-BINDING|V2'+bytes([0])+canon(binding))==p['digest']
for i,raw in enumerate(p['receipts']):
 r=json.loads(raw);signature=bytes.fromhex(r.pop('signature'));body=canon(r)
 assert r['binding_digest']==p['digest'] and r['signer']==members[i]['account']
 message=('D-MASH|ACCOUNT-ROUTE-RECEIPT|V2|'+r['phase']).encode()+bytes([0])+struct.pack('>I',len(body))+body
 VerifyKey(bytes.fromhex(r['signer'])).verify(message,signature)
print('Python canonical binding reconstruction + libsodium receipt signatures PASS')`;
  const check=require('node:child_process').spawnSync(require('node:path').resolve(__dirname,'../../../.venv/bin/python'),['-c',py],{input:JSON.stringify(payload),encoding:'utf8'});assert.equal(check.status,0,check.stderr);console.log(check.stdout.trim());
 }
 // Async hashing cannot silently extend validity.
 const expiring=createBindingCodec({nacl,discovery,pairing,clock:()=>now,subtle:{digest:async(...args)=>{const value=await crypto.subtle.digest(...args);now=1800000601;return value;}}});
 await rejects(()=>expiring.prepare([a,b],context()),'EXPIRED');
 throws(()=>api.verifyReceipts(candidate,signed,{committed:null}),'EXPIRED');
 const history=await api.verifyCommitted([a,b],signed,{...context(),verifiedAt:1800000000});assert.equal(history.digest,candidate.digest);
 await rejects(()=>api.verifyCommitted([a,b],signed,{...context(),verifiedAt:now+1}),'COMMIT_EPOCH_FUTURE');
 await rejects(()=>api.verifyCommitted([a,b],signed,{...context(),verifiedAt:now}),'EXPIRED');
 console.log('PASS Account route bilateral binding: canonical real signatures, two phases, identity/certificate pinning, crossed-offer advisory order, replay/generation/predecessor and expiry guards');
 assert.equal(candidate.digest,'df17d9ee42e9a66913242e4f5499393913dbf5802750a63cfde036d95ffec3d7');
 assert.equal(require('node:crypto').createHash('sha256').update(signed.join('\n')).digest('hex'),'656d4f58c7cf0dcf24a282ec76657a2d9cf3aa5eeb0a0e3baff61a18825cda9a');
})().catch(error=>{console.error(error);process.exitCode=1;});
