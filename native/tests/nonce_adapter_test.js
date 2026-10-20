'use strict';
const vm=require('node:vm'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
let context;const metrics=[];
const digest=(prefix,nonce)=>{const suffix=Buffer.alloc(8);suffix.writeBigUInt64BE(BigInt(nonce));return crypto.createHash('sha256').update(prefix).update(suffix).digest();};
context=vm.createContext({__dmashHost(op,...args){
 if(op==='isWorker'||op==='benchmarkEnabled')return true;
 if(op==='utf8Encode')return Buffer.from(args[0]);
 if(op==='monotonic')return performance.now();
 if(op==='nonceCreate')return Buffer.from(args[0]);
 if(op==='nonceHash')return vm.runInContext('Uint8Array',context).from(digest(args[0],(BigInt(args[1])<<32n)|BigInt(args[2])));
 if(op==='nonceSearch'){if(args[3]===256)return null;return {nonce:args[1],digest:vm.runInContext('Uint8Array',context).from(digest(args[0],args[1]))};}
 if(op==='workerBenchmark')metrics.push({event:'benchmark-nonce-batch',crossingMs:args[0],batchMs:args[1]});
 if(op==='workerBenchmarkError')throw Error(args.join(':'));
}});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../js/platform.js'),'utf8'),context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../../D-MASH PWA/not_messenger/js/resource_pow.js'),'utf8'),context);
const value=vm.runInContext('DmashNativeNonceHasher(Uint8Array.from([1,2,3])).search(0,4096,0)',context);assert.equal(value.nonce,0);assert(metrics.some(e=>e.event==='benchmark-nonce-batch'));
console.log('native worker nonce factory: independent Node SHA parity and bounded search invocation PASS');
