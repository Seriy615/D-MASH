#!/usr/bin/env node
'use strict';
// Loads the repository's actual implementation. Never prints keys or contributions.
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const {createHash} = require('node:crypto'), {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../../../..');
const base = path.join(root, 'D-MASH PWA/not_messenger/js');
const files = ['vendor/nacl-fast.min.js','secure_session.js','private_routes_v3.js','device_envelope.js'];
const hashes = Object.fromEntries(files.map(f => [f, createHash('sha256').update(fs.readFileSync(path.join(base,f))).digest('hex')]));
global.nacl = require(path.join(base,files[0]));
require(path.join(base,'secure_session.js'));
const R = require(path.join(base,'private_routes_v3.js')), E = require(path.join(base,'device_envelope.js'));
(async () => {
  const checks = [], pass = (name, condition) => { assert.ok(condition, name); checks.push(name); };
  // Synthetic public test material, with no relationship to any real Account.
  const a = '11'.repeat(32), b = '22'.repeat(32), c = '33'.repeat(32);
  const ab = await R.pair(a,b), ba = await R.pair(b,a), ac = await R.pair(a,c), next = await R.pair(a,b,2);
  const equal = (x,y) => Buffer.from(x).equals(Buffer.from(y));
  for (const [x,y] of [[ab.outgoing,ba.incoming],[ba.outgoing,ab.incoming]]) {
    pass('directional locator symmetry '+checks.length,x.routeId===y.routeId);
    pass('directional authority symmetry '+checks.length,equal(x.signing.secretKey,y.signing.secretKey));
    pass('directional recipient symmetry '+checks.length,equal(x.box.secretKey,y.box.secretKey));
  }
  pass('directions distinct',ab.outgoing.routeId!==ab.incoming.routeId && !equal(ab.outgoing.box.secretKey,ab.incoming.box.secretKey));
  pass('third peer isolated',ab.outgoing.routeId!==ac.outgoing.routeId && !equal(ab.outgoing.box.secretKey,ac.outgoing.box.secretKey));
  pass('generation changes authority and recipient',ab.outgoing.routeId!==next.outgoing.routeId && !equal(ab.outgoing.box.secretKey,next.outgoing.box.secretKey));
  for (const generation of [0,-1,1.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,'2',null]) {
    await assert.rejects(R.pair(a,b,generation));
  }
  pass('invalid generation rejected',true);
  const max = await R.pair(a,b,Number.MAX_SAFE_INTEGER); max.close();
  pass('maximum safe generation accepted',true);
  await assert.rejects(R.pair(a,a)); await assert.rejects(R.pair('invalid',b));
  pass('invalid or identical contributions rejected',true);
  // Dynamic Account context mutation: pair has no Account input or lookup.
  global.Core = {currentAccount:'synthetic-A',keys:{account:'not-used'}};
  const first = await R.pair(a,b);
  global.Core = new Proxy({}, {get(){throw Error('Account access forbidden');}});
  const second = await R.pair(a,b);
  pass('independent of Account context',equal(first.outgoing.signing.secretKey,second.outgoing.signing.secretKey));
  delete global.Core;
  // An observer possessing BOTH contributions reproduces complete capabilities.
  const observer = await R.pair(a,b);
  pass('both captured contributions reproduce route secrets',equal(observer.incoming.box.secretKey,ab.incoming.box.secretKey) && equal(observer.outgoing.signing.secretKey,ab.outgoing.signing.secretKey));
  const envelope = E.create(ab.routeLocator,'MSG','opaque synthetic Account ciphertext');
  const ciphertext = E.seal(ab.outgoing.box.publicKey,envelope);
  assert.deepEqual(E.open(ba.incoming.box.secretKey,ciphertext),envelope);
  pass('actual outer roundtrip',true);
  assert.throws(()=>E.open(ac.outgoing.box.secretKey,ciphertext));
  assert.throws(()=>E.open(next.outgoing.box.secretKey,ciphertext));
  pass('third peer and generation wrong keys reject',true);
  const wire = JSON.parse(Buffer.from(ciphertext,'base64').toString());
  assert.deepEqual(Object.keys(wire).sort(),['c','e','n','v']);
  pass('wire has no static recipient field',!equal(Buffer.from(wire.e,'base64'),ab.outgoing.box.publicKey) && !JSON.stringify(wire).includes(Buffer.from(ab.outgoing.box.publicKey).toString('base64')));
  pass('wire hides semantic fields',![envelope.route_id,envelope.packet_id,envelope.type,envelope.account_payload].some(v=>JSON.stringify(wire).includes(v)));
  // Anyone knowing a public recipient key can create a valid outer box.
  const stranger = E.seal(ab.outgoing.box.publicKey,E.create(ab.routeLocator,'MSG','stranger-supplied opaque bytes'));
  pass('outer encryption alone does not authenticate Account sender',E.open(ba.incoming.box.secretKey,stranger).account_payload==='stranger-supplied opaque bytes');
  for (const pair of [ab,ba,ac,next,first,second,observer]) pair.close();
  console.log(JSON.stringify({kind:'actual-source-crypto',status:'PASS',node:process.version,source_head:execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),source_sha256:hashes,checks,limits:['UNIT actual JS; no browser/network/native acceptance','Account independence checks this route helper only; no claim all runtime paths are independent','Wire shape inspected; no anonymity or traffic-analysis proof','Generation validation is syntactic; monotonicity/replay lifecycle not proven']},null,2));
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
