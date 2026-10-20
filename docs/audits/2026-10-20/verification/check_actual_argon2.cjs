#!/usr/bin/env node
'use strict';
// Browser-like VM loads the actual vendor JS and actual repository WASM.
// Only synthetic public test inputs; no Account, PIN, root, or derived bytes printed.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const root=path.resolve(__dirname,'../../../..');
const base=path.join(root,'D-MASH PWA/not_messenger/js');
const js=fs.readFileSync(path.join(base,'vendor/argon2-bundled.min.js'),'utf8');
const wasm=fs.readFileSync(path.join(base,'vendor/argon2.wasm'));
const context={console,TextEncoder,TextDecoder,WebAssembly,Uint8Array,ArrayBuffer,Promise,setTimeout,clearTimeout,atob,btoa,
 loadArgon2WasmBinary:async()=>new Uint8Array(wasm),location:{href:'https://synthetic.invalid/js/vendor/argon2-bundled.min.js'},
 document:{currentScript:{src:'https://synthetic.invalid/js/vendor/argon2-bundled.min.js'}}};
context.self=context;context.window=context;
vm.runInNewContext(js,context,{filename:'actual-argon2-bundled.min.js'});
(async()=>{
 const a=context.argon2;
 assert.equal(a.argon2id,undefined);
 assert.equal(a.ArgonType.Argon2id,2);
 const options={pass:'public-test-passphrase',salt:'public-test-salt',time:1,mem:1024,parallelism:1,hashLen:32};
 const actual=await a.hash({...options,type:a.argon2id});
 const d=await a.hash({...options,type:a.ArgonType.Argon2d});
 const id=await a.hash({...options,type:a.ArgonType.Argon2id});
 assert.equal(actual.hashHex,d.hashHex); assert.notEqual(actual.hashHex,id.hashHex);
 assert.match(actual.encoded,/^\$argon2d\$/); assert.match(id.encoded,/^\$argon2id\$/);
 const aliases=[];
 function walk(p){for(const e of fs.readdirSync(p,{withFileTypes:true})){const f=path.join(p,e.name);if(e.isDirectory())walk(f);else if(e.name.endsWith('.js')&&!e.name.endsWith('.min.js')){const s=fs.readFileSync(f,'utf8');if(/argon2\.argon2id\s*=/.test(s))aliases.push(path.relative(root,f));}}}
 walk(base);assert.deepEqual(aliases,[]);
 const sources=['vendor/argon2-bundled.min.js','vendor/argon2.wasm','device_root.js','core_engine.js','ui_logic.js','acceptance_v51.js'];
 console.log(JSON.stringify({kind:'actual vendor JS/WASM execution',status:'PASS (confirmed KDF type mismatch)',node:process.version,
 source_head:require('node:child_process').execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),
 source_sha256:Object.fromEntries(sources.map(f=>[f,createHash('sha256').update(fs.readFileSync(path.join(base,f))).digest('hex')])),
 checks:['vendor exports ArgonType.Argon2id=2; top-level argon2id undefined','actual undefined-type invocation equals explicit Argon2d','actual undefined-type invocation differs from explicit Argon2id','encoded result independently identifies argon2d','no top-level enum alias assignment in non-minified product JS'],
 limits:['Synthetic public vector uses reduced time/memory; type dispatch is actual vendor code/WASM','Not a real Account/root unlock or browser loading acceptance','Do not silently fix type for existing Account derivation: it changes keys; wrap migration must preserve existing root']},null,2));
})().catch(e=>{console.error(e);process.exitCode=1;});
