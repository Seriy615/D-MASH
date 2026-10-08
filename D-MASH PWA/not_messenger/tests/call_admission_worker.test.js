const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../js/call_admission_worker.js'),'utf8');
const pow=fs.readFileSync(path.join(__dirname,'../js/resource_pow.js'),'utf8');
async function run(data){let resolve;const result=new Promise(r=>resolve=r),scope={crypto,TextEncoder,Uint8Array,Date,Number,Error};scope.self=scope;scope.postMessage=resolve;const context=vm.createContext(scope);scope.importScripts=file=>{assert.equal(file,'resource_pow.js');vm.runInContext(pow,context);};vm.runInContext(source,context);await scope.onmessage({data});return result;}
(async()=>{
 for(const transcript of [
  {nonce:'1'.repeat(64),callId:'2'.repeat(64),verifier:'3'.repeat(64),difficulty:8},
  {nonce:'a'.repeat(64),callId:'b'.repeat(64),verifier:'c'.repeat(64),difficulty:10},
  {nonce:'f'.repeat(64),callId:'0'.repeat(64),verifier:'e'.repeat(64),difficulty:12}
 ]){
  const {counter}=await run(transcript);assert(Number.isSafeInteger(counter));
  for(let candidate=0;candidate<=counter;candidate++){
   const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(`${transcript.nonce}:${transcript.callId}:${transcript.verifier}:${candidate}`)));
   let bits=transcript.difficulty,valid=true;for(const byte of hash){const take=Math.min(bits,8);if(byte>>>(8-take)){valid=false;break;}bits-=take;if(!bits)break;}
   assert.equal(valid,candidate===counter,'Worker must return the first valid counter for unchanged transcript/difficulty');
  }
 }
 const transcript={nonce:'1'.repeat(64),callId:'2'.repeat(64),verifier:'3'.repeat(64),difficulty:8};
 for(const difficulty of [0,21,1.5])assert((await run({...transcript,difficulty})).error);
 assert((await run({...transcript,nonce:'oops'})).error);
 console.log('PASS synchronous SHA worker matches WebCrypto first proof at 8/10/12 bits and refuses malformed challenges');
})().catch(e=>{console.error(e);process.exitCode=1;});
