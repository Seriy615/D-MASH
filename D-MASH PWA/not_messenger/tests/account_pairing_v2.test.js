'use strict';
const assert=require('node:assert/strict');
global.nacl=require('../js/vendor/nacl-fast.min.js');
const nacl=global.nacl,discovery=require('../js/route_discovery_v4.js');
const api=require('../js/account_pairing_v2.js').createCodec({nacl,discovery});
const hex=a=>Buffer.from(a).toString('hex'),seed=n=>new Uint8Array(32).fill(n);
const signer=nacl.sign.keyPair.fromSeed(seed(1)),route=nacl.sign.keyPair.fromSeed(seed(2)),ds=nacl.sign.keyPair.fromSeed(seed(3));
const box=nacl.box.keyPair.fromSecretKey(seed(4)),db=nacl.box.keyPair.fromSecretKey(seed(5)),rb=nacl.box.keyPair.fromSecretKey(seed(6));
const now=1800000000;
// KEM bytes are an opaque parser fixture, not a KEM security/encapsulation test.
const body={type:'DMASH_PAIRING_V2',version:2,transport_version:4,pairing_id:'07'.repeat(32),generation:1,issued_at:now,expires_at:now+100,previous_binding:null,intended_peer:null,contribution:'08'.repeat(32),account_keys:{signing:hex(signer.publicKey),box:hex(box.publicKey),kem_profile:'LEGACY_KYBER768_BUNDLE_V1',kem_public:Buffer.alloc(1184,9).toString('base64url')},inbound_certificate:discovery.issueCertificate(route,ds.publicKey,db.publicKey,rb.publicKey,{generation:1,issuedAt:now,expiresAt:now+200})};
const original=JSON.stringify(body),secret=signer.secretKey.slice();
const result=api.sign(body,signer.secretKey,{now});
assert.equal(JSON.stringify(body),original);assert.deepEqual(signer.secretKey,secret);
assert.equal(result.identityStatus,'UNPINNED_CANDIDATE');
assert.equal(api.parse(result.serialized,{now,expectedPeer:body.account_keys.signing,previousBinding:null,expectedGeneration:1}).identityStatus,'PINNED_CANDIDATE');
assert(Object.isFrozen(result.bundle.account_keys));
const clone=()=>JSON.parse(result.serialized);
const isolatedProfile=api.sign({...body,account_keys:{...body.account_keys,kem_profile:'ACCOUNT_STATIC_LEGACY_KYBER768_V1'}},signer.secretKey,{now});
assert.equal(api.parse(isolatedProfile.serialized,{now}).bundle.account_keys.kem_profile,'ACCOUNT_STATIC_LEGACY_KYBER768_V1');
const downgraded=JSON.parse(isolatedProfile.serialized);downgraded.account_keys.kem_profile='LEGACY_KYBER768_BUNDLE_V1';assert.throws(()=>api.verify(downgraded,{now}),e=>e.code==='ACCOUNT_SIGNATURE');
function rejects(fn,code){assert.throws(fn,e=>!code||e.code===code);}
for(const key of ['pairing_id','contribution']){const b=clone();b[key]='aa'.repeat(32);rejects(()=>api.verify(b,{now}),'ACCOUNT_SIGNATURE');}
for(const key of ['signing','box','kem_public']){const b=clone();b.account_keys[key]=key==='kem_public'?Buffer.alloc(1184,10).toString('base64url'):'ab'.repeat(32);rejects(()=>api.verify(b,{now}),'ACCOUNT_SIGNATURE');}
rejects(()=>api.parse(' '+result.serialized,{now}),'NON_CANONICAL');
rejects(()=>api.parse(result.serialized.replace('"version":2','"version":2,"version":2'),{now}),'NON_CANONICAL');
rejects(()=>api.parse(result.serialized.replace('"generation":1','"generation":1e0'),{now}),'NON_CANONICAL');
rejects(()=>api.parse(' '.repeat(12289)),'SIZE');
rejects(()=>api.parse('{"version":1}'),'UPGRADE_REQUIRED_V2');
for(const [context,code] of [[{now:now+100},'EXPIRED'],[{now:now-61},'EXPIRED'],[{expectedPeer:'aa'.repeat(32)},'IDENTITY_MISMATCH'],[{localAccount:body.account_keys.signing},'SELF_PAIRING'],[{expectedGeneration:2},'GENERATION_MISMATCH'],[{previousBinding:'aa'.repeat(32)},'PREDECESSOR_MISMATCH']])rejects(()=>api.parse(result.serialized,{now,...context}),code);
for(const mutate of [b=>b.extra=1,b=>b.account_keys.extra=1,b=>b.inbound_certificate.extra=1,b=>b.account_keys.kem_profile='ML-KEM-768',b=>b.account_keys.kem_public+='=',b=>b.generation=-0,b=>b.expires_at=now+86401,b=>b.inbound_certificate.generation=2,b=>b.inbound_certificate.expires_at=now+99,b=>b.account_keys.box=b.inbound_certificate.recipient_box]){const b=clone();mutate(b);rejects(()=>api.verify(b,{now}));}
const other=discovery.issueCertificate(nacl.sign.keyPair.fromSeed(seed(11)),ds.publicKey,db.publicKey,rb.publicKey,{generation:1,issuedAt:now,expiresAt:now+200});
const substituted=clone();substituted.inbound_certificate=other;rejects(()=>api.verify(substituted,{now}),'ACCOUNT_SIGNATURE');
const forged={...body,inbound_certificate:{...body.inbound_certificate,signature:'00'.repeat(64)}};rejects(()=>api.sign(forged,signer.secretKey,{now}));
rejects(()=>api.sign(body,route.secretKey,{now}),'SIGNER_MISMATCH');
rejects(()=>api.sign({...body,account_keys:{...body.account_keys,box:'00'.repeat(32)}},signer.secretKey,{now}),'LOW_ORDER_KEY');
const target=hex(nacl.sign.keyPair.fromSeed(seed(12)).publicKey);
const targeted=api.sign({...body,intended_peer:target},signer.secretKey,{now,localAccount:target});
rejects(()=>api.parse(targeted.serialized,{now}),'TARGET_MISMATCH');
assert.equal(api.parse(targeted.serialized,{now,localAccount:target}).bundle.intended_peer,target);
let touched=false;const accessor=clone();Object.defineProperty(accessor,'generation',{get(){touched=true;return 1;}});rejects(()=>api.verify(accessor,{now}),'SCHEMA');assert.equal(touched,false);
const small=['00'.repeat(32),'01'+'00'.repeat(31),'26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05','c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a','ec'+'ff'.repeat(30)+'7f','ed'+'ff'.repeat(30)+'7f','ee'+'ff'.repeat(30)+'7f'];
const invalidPoints=[];
for(const y of small)for(const sign of [0,128]){
 const bytes=Buffer.from(y,'hex');bytes[31]|=sign;const key=bytes.toString('hex');invalidPoints.push(key);
 for(const role of ['account','authority','discovery']){const b=clone();if(role==='account')b.account_keys.signing=key;else b.inbound_certificate[role==='authority'?'route_id':'discovery_sign']=key;rejects(()=>api.verify(b,{now}));}
 const b=clone();b.signature=key+b.signature.slice(64);rejects(()=>api.verify(b,{now}));
}
const identity=Buffer.from('01'+'00'.repeat(31),'hex'),forgery=Buffer.concat([identity,Buffer.alloc(32)]);
assert.equal(nacl.sign.detached.verify(Buffer.from('forged'),forgery,identity),true,'documents inherited vendor weakness');
const forgedAccount=clone();forgedAccount.account_keys.signing=hex(identity);forgedAccount.signature=hex(forgery);rejects(()=>api.verify(forgedAccount,{now}),'SMALL_ORDER_POINT');
const addL=sig=>{const bytes=Buffer.from(sig,'hex'),order=Buffer.from('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010','hex');let carry=0;for(let i=0;i<32;i++){const sum=bytes[i+32]+order[i]+carry;bytes[i+32]=sum&255;carry=sum>>>8;}return bytes.toString('hex');};
const malleated=clone();malleated.signature=addL(malleated.signature);rejects(()=>api.verify(malleated,{now}),'NON_CANONICAL_SIGNATURE');
const badCert=clone();badCert.inbound_certificate.signature=addL(badCert.inbound_certificate.signature);rejects(()=>api.verify(badCert,{now}),'NON_CANONICAL_SIGNATURE');
for(const key of ['ed'+'ff'.repeat(30)+'7f','ff'.repeat(32),(()=>{const bytes=Buffer.from(body.account_keys.box,'hex');bytes[31]|=128;return hex(bytes);})()])rejects(()=>api.sign({...body,account_keys:{...body.account_keys,box:key}},signer.secretKey,{now}),'NON_CANONICAL_POINT');
if(process.env.DMASH_PAIRING_PYNACL==='1'){
 const payload={invalidPoints,validPoint:body.account_keys.signing,message:hex(api.transcript(result.bundle)),signature:result.bundle.signature,malleated:malleated.signature,identity:hex(identity),forgery:hex(forgery)};
 const py=`import sys,json,nacl.bindings as b
p=json.load(sys.stdin)
h=bytes.fromhex
assert b.crypto_core_ed25519_is_valid_point(h(p['validPoint']))
for key in p['invalidPoints']: assert not b.crypto_core_ed25519_is_valid_point(h(key))
assert b.crypto_sign_open(h(p['signature'])+h(p['message']),h(p['validPoint']))==h(p['message'])
for sig,msg,key in [(p['malleated'],p['message'],p['validPoint']),(p['forgery'],b'forged'.hex(),p['identity'])]:
 try: b.crypto_sign_open(h(sig)+h(msg),h(key))
 except Exception: pass
 else: raise AssertionError('libsodium accepted invalid signature')
print('PyNaCl/libsodium differential PASS')`;
 const check=require('node:child_process').spawnSync(require('node:path').resolve(__dirname,'../../../.venv/bin/python'),['-c',py],{input:JSON.stringify(payload),encoding:'utf8'});assert.equal(check.status,0,check.stderr);console.log(check.stdout.trim());
}
// Stable vector binds exact canonical bytes, domain, length prefix and real Ed25519.
const digest=require('node:crypto').createHash('sha256').update(result.serialized).digest('hex');
assert.equal(digest,'44a7fa01501ba685894225d33298a15354eb5c153e0381e486f1de1105b562a9');
console.log('account_pairing_v2 real Ed25519/X25519/certificate tests PASS; vector SHA256',digest);
