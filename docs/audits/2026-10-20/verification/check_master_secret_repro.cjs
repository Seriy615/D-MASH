'use strict';
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),assert=require('node:assert/strict');
const {webcrypto,createHash}=require('node:crypto');
// Review-only reproducer. Uses synthetic data and VM storage; never opens user DBs.
// Usage: node check_master_secret_repro.cjs [--repo /path/to/repo] [--output result.json]
const args=process.argv.slice(2), options={};
for(let i=0;i<args.length;i+=2){
 if(!['--repo','--output'].includes(args[i])||!args[i+1])throw Error('Usage: check_master_secret_repro.cjs [--repo PATH] [--output JSON]');
 options[args[i]]=args[i+1];
}
const repo=path.resolve(options['--repo']||path.join(__dirname,'../../../..'));
const base=path.join(repo,'D-MASH PWA/not_messenger');
const {execFileSync}=require('node:child_process');
const actualCommit=execFileSync('git',['-C',repo,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
const sha=s=>createHash('sha256').update(s).digest('hex');
(async()=>{
 const c={WebAssembly,TextEncoder,TextDecoder,Uint8Array,Int8Array,Uint16Array,Int16Array,Uint32Array,Int32Array,Float32Array,Float64Array,ArrayBuffer,Promise,Math,Date,console,atob,btoa,setTimeout,clearTimeout};c.window=c;c.self=c;vm.createContext(c);
 vm.runInContext(fs.readFileSync(path.join(base,'js/vendor/argon2-bundled.min.js'),'utf8'),c);
 const argon=c.argon2, opts={pass:'synthetic-only-master',salt:Buffer.alloc(16,3).toString('base64'),time:3,mem:65536,hashLen:32};
 const implicit=await argon.hash({...opts,type:argon.argon2id}),d=await argon.hash({...opts,type:argon.ArgonType.Argon2d}),id=await argon.hash({...opts,type:argon.ArgonType.Argon2id});
 assert.equal(implicit.hashHex,d.hashHex);assert.notEqual(implicit.hashHex,id.hashHex);
 if(!global.crypto)global.crypto=webcrypto;global.argon2=argon;const {DeviceRoot}=require(path.join(base,'js/device_root.js'));const wrapped=await DeviceRoot._encryptRoot(new Uint8Array(32).fill(7),opts.pass,new Uint8Array(16).fill(3));const dk=await webcrypto.subtle.importKey('raw',d.hash,{name:'AES-GCM'},false,['decrypt']);const opened=await webcrypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(wrapped.iv,'base64'),additionalData:new TextEncoder().encode('dmash/device-root-wrap/v1')},dk,Buffer.from(wrapped.wrappedRoot,'base64'));assert.deepEqual([...new Uint8Array(opened)],[...new Uint8Array(32).fill(7)]);
 const lookupTarget=sha('4690');let recovered=null;for(let n=1000;n<=9999;n++){if(sha(String(n))===lookupTarget){recovered=String(n);break;}}assert.equal(recovered,'4690');
 const values=new Map([['sys_configured','true'],['sys_m',sha('4690')],['sys_w',sha('6789')]]);let failWrite=false,rootRewrapped=false;
 const uiCtx={crypto:webcrypto,TextEncoder,setTimeout:()=>0,clearTimeout,console,localStorage:{getItem:k=>values.get(k)||null,setItem:(k,v)=>{if(failWrite&&k==='sys_m')throw Error('synthetic quota failure');values.set(k,String(v));},clear:()=>values.clear()},sessionStorage:{clear(){}},document:{getElementById:()=>null,querySelector:()=>null,body:{style:{}}},window:{addEventListener(){},NodeManager:null},Core:{changeDeviceMasterSecret:async()=>{rootRewrapped=true;}}};
 vm.createContext(uiCtx);vm.runInContext(fs.readFileSync(path.join(base,'js/ui_logic.js'),'utf8'),uiCtx);const ui=vm.runInContext('ui',uiCtx);
 ui.mode=3;ui.curr='4690';await ui.eval();ui.curr='2345';await ui.eval();failWrite=true;ui.curr='6789';await ui.eval();assert(rootRewrapped);assert.equal(values.get('sys_m'),sha('4690'));assert.match(ui.hist,/ОШИБКА/);
 let dangerousCalls=0;uiCtx.indexedDB={deleteDatabase(){dangerousCalls++;throw Error('should not delete');}};uiCtx.caches={keys:async()=>[]};uiCtx.navigator={};uiCtx.window=Object.assign(uiCtx.window,{ui,crypto:webcrypto,setInterval:()=>0,clearInterval(){},setTimeout:()=>0,Core:uiCtx.Core});uiCtx.setInterval=()=>0;uiCtx.clearInterval=()=>{};
 vm.runInContext(fs.readFileSync(path.join(base,'js/acceptance_v54.js'),'utf8'),uiCtx);vm.runInContext(fs.readFileSync(path.join(base,'js/acceptance_v55.js'),'utf8'),uiCtx);ui.mode=0;ui._emergencyWipeSequence='00101234';await ui.eval();assert.equal(dangerousCalls,0);assert.match(ui.hist,/ОШИБКА/);
 const sourceFiles=['js/vendor/argon2-bundled.min.js','js/device_root.js','js/ui_logic.js','js/acceptance_v54.js','js/acceptance_v55.js','js/release.js'];
 const sourceHashes=Object.fromEntries(sourceFiles.map(name=>[name,sha(fs.readFileSync(path.join(base,name)))]));
 const report={runner_sha256:sha(fs.readFileSync(__filename)),actual_source_commit:actualCommit,source_files_sha256:sourceHashes,scope:'source VM and real bundled Argon2 WASM; synthetic fixtures only; not browser/device acceptance',node:process.version,synthetic_vectors:{input:opts,implicit:{hash:implicit.hashHex,encoded:implicit.encoded},explicit_d:{hash:d.hashHex,encoded:d.encoded},explicit_id:{hash:id.hashHex,encoded:id.encoded},production_encryptRoot_label:wrapped.wrap},source_sha:'9446c22f27309131456942870971d477f6f2358f',checks:{production_encryptRoot_opens_with_Argon2d_key:true,bundled_export_argon2id_missing:argon.argon2id===undefined,implicit_type_matches_Argon2d:implicit.hashHex===d.hashHex,explicit_Argon2id_differs:implicit.hashHex!==id.hashHex,synthetic_four_digit_master_recovered_from_fast_hash:recovered==='4690',rewrap_then_UI_write_failure_leaves_old_verifier:rootRewrapped&&values.get('sys_m')===sha('4690'),loaded_v54_v55_wrong_emergency_suffix_does_not_delete:dangerousCalls===0},limitations:['UI rewrap dependency is a spy to expose cross-store ordering; not real persistence crash injection','No correct-code destructive wipe executed','No real user storage/keys read','No browser, Android, desktop app or physical phone lifecycle acceptance']};
 if(options['--output'])fs.writeFileSync(path.resolve(options['--output']),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
})().catch(e=>{console.error(e);process.exitCode=1;});
