'use strict';
// Real original WebAssembly instance, not a second native KEM implementation.
// Random synthetic test keys remain only in child pipes and process memory.
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const { createHash, webcrypto } = require('node:crypto');
const executable = process.argv[2], wasmPath = process.argv[3];
const bytes = fs.readFileSync(wasmPath);
assert.equal(createHash('sha256').update(bytes).digest('hex'),
  'e9b316e56f5d1eef1f44f28bca99bec16ec9cff69af4b17d318143512255b009');
let wasm;
function child(args, input) {
  const r = spawnSync(executable, args, { input, encoding: 'utf8', maxBuffer: 32768 });
  assert.equal(r.status, 0, 'native compatibility operation failed: ' + r.stderr);
  return r.stdout;
}
(async () => {
  const result = await WebAssembly.instantiate(bytes, { a: {
    a() { throw Error('Original Emscripten OOM'); },
    b(code, signature, args) {
      assert.equal(code, 1476);
      const heap = new Uint8Array(wasm.c.buffer), view = new DataView(wasm.c.buffer);
      assert.deepEqual(Array.from(heap.subarray(signature, signature + 3)), [112, 105, 0]);
      const offset = view.getUint32(args, true), size = view.getUint32(args + 4, true);
      webcrypto.getRandomValues(heap.subarray(offset, offset + size));
      return 0;
    }
  }});
  wasm = result.instance.exports; wasm.d();
  const native = JSON.parse(child(['--fixture']));
  const alloc = n => { const p = wasm.h(n); assert.ok(p); return p; };
  const heap = new Uint8Array(wasm.c.buffer);
  const pk = alloc(1184), sk = alloc(2400), ct = alloc(1088), ss = alloc(32);
  // Existing native key+capsule decrypt through the untouched JS/WebAssembly engine.
  heap.set(Buffer.from(native.sk, 'base64'), sk); heap.set(Buffer.from(native.ct, 'base64'), ct);
  assert.equal(wasm.g(ss, ct, sk), 0);
  assert.equal(Buffer.from(heap.subarray(ss, ss + 32)).toString('base64'), native.ss);
  // Original WASM encapsulates to native public key; native opens SAME existing secret.
  heap.set(Buffer.from(native.pk, 'base64'), pk); assert.equal(wasm.f(ct, ss, pk), 0);
  let opened = child(['--decap'], JSON.stringify({ sk: native.sk,
    ct: Buffer.from(heap.subarray(ct, ct + 1088)).toString('base64') }) + '\n');
  assert.equal(opened, Buffer.from(heap.subarray(ss, ss + 32)).toString('base64'));
  // Original WASM keys and encapsulation are accepted by the native translated artifact.
  assert.equal(wasm.e(pk, sk), 0); assert.equal(wasm.f(ct, ss, pk), 0);
  opened = child(['--decap'], JSON.stringify({
    sk: Buffer.from(heap.subarray(sk, sk + 2400)).toString('base64'),
    ct: Buffer.from(heap.subarray(ct, ct + 1088)).toString('base64') }) + '\n');
  assert.equal(opened, Buffer.from(heap.subarray(ss, ss + 32)).toString('base64'));
  heap.fill(0); native.sk = native.ss = opened = '';
  console.log('PASS original existing JS/WASM ↔ native legacy Kyber cross-decapsulation (both key origins); identity algorithm unchanged');
})().catch(e => { console.error(e); process.exitCode = 1; });
