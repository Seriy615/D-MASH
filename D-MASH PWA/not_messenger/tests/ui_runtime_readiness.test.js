'use strict';
// Lifecycle regression: executes actual installers, not copies of their wrappers.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),cp=require('node:child_process');
const dir=path.join(__dirname,'../js');
const source=n=>process.env.DMASH_UI_READINESS_SOURCE_REF?cp.execFileSync('git',['show',`${process.env.DMASH_UI_READINESS_SOURCE_REF}:D-MASH PWA/not_messenger/js/${n}`],{encoding:'utf8'}):fs.readFileSync(path.join(dir,n),'utf8');
function fixture(brokenRoot=false){
 let now=0,seq=0;const timers=new Map(),errors=[];
 const noop=()=>{};const stub=()=>new Proxy({}, {get(t,k){if(k in t)return t[k];if(typeof k==='string'&&(k.startsWith('__')||k==='dmashAcceptanceFixesV1'))return undefined;return noop;}});
 const element={addEventListener:noop,style:{setProperty:noop},querySelector:()=>null,querySelectorAll:()=>[],classList:{add:noop,remove:noop},appendChild:noop};
 const c={console:{log:noop,warn:noop,error:(...a)=>errors.push(a)},TextEncoder,TextDecoder,URL,AbortController,Uint8Array,Map,Set,WeakMap,Promise,queueMicrotask,CustomEvent:class{},crypto:require('node:crypto').webcrypto,
 localStorage:{getItem:()=>null,setItem:noop,removeItem:noop},document:{createElement:()=>({...element}),head:element,readyState:'loading',getElementById:()=>element,querySelector:()=>null,querySelectorAll:()=>[],scripts:[]},location:{hash:'',pathname:'/',search:''},addEventListener:noop,dispatchEvent:noop,
 setInterval(fn,ms){const id=++seq;timers.set(id,{fn,ms,next:now+ms,repeat:true});return id;},setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms,next:now+ms});return id;},clearInterval:id=>timers.delete(id),clearTimeout:id=>timers.delete(id)};
 c.window=c;c.globalThis=c;vm.createContext(c);
 function run(n){vm.runInContext(source(n),c,{filename:n});}
 c.ui=stub();Object.assign(c.ui,{show_gate:noop,handleBiometricHold:noop,eval:noop,num:noop,cmd:noop});
 c.sys={ensureCredentials:async()=>({}),loadAllLibs:async()=>false,loadScript:async src=>{if(src.includes('core_engine'))foundation();}};
 function foundation(){if(c.Core)return;c.Core=stub();c.DeviceRoot=stub();Object.assign(c.DeviceRoot,{state:null,rewrapMasterPin:noop,prepareWebAuthnUnlock:brokenRoot?null:noop});c.Storage=stub();c.DMashStorage=c.Storage;c.NodeManager=stub();c.NodeManager.loadOriginList=async()=>{};c.DeviceRoutes={};c.ContactPayloads={};c.ContactTransport={};c.DmashResourcePow={};c.KyberModule={HEAPU8:new Uint8Array(1),_malloc:noop,_free:noop,_wasm_keypair:noop,_wasm_encapsulate:noop,_wasm_decapsulate:noop};}
 run('release.js');for(const n of ['ui_global_bridge','runtime_fixes','public_contact_runtime','acceptance_fixes','acceptance_v50','acceptance_v51','acceptance_v52','acceptance_v54','acceptance_v55','node_account_ui_v4'])run(n+'.js');
 c.DmashRuntimeReadiness?.supportLoaded();
 function advance(ms){const end=now+ms;while(true){const next=[...timers].filter(([,t])=>t.next<=end).sort((a,b)=>a[1].next-b[1].next)[0];if(!next)break;now=next[1].next;const [id,t]=next;if(t.repeat)t.next+=t.ms;else timers.delete(id);t.fn();}now=end;}
 return {c,advance,errors,timers};
}
(async()=>{
 for(const delay of [180000,1000]){
  const {c,advance,timers,errors}=fixture();await Promise.resolve();advance(delay);assert.equal(c.Core,undefined);
  const loaded=await c.sys.loadAllLibs();if(!loaded)console.error(errors);assert.equal(loaded,true,'lazy foundation must compose after installer deadlines');advance(300);
  for(const flag of ['__dmashFunctionalRepairV2','__dmashPublicContactRuntimeV1','dmashAcceptanceFixesV1','__dmashAcceptanceV50','__dmashAcceptanceV51','__nodeAccountUiV4'])assert.equal(c.Core[flag],true,`${flag} after ${delay}ms`);
  assert.equal(typeof c.Core.beginKeyExchange,'function');assert.match(String(c.Core.beginKeyExchange),/Pairing QR/);
  const refs=[c.Core.openSettings,c.Core.beginKeyExchange,c.Core.sendMessage,c.DeviceRoot.rewrapMasterPin,c.ui.eval];
  for(let i=0;i<5;i++)await c.DmashRuntimeReadiness.compose();assert.deepEqual([c.Core.openSettings,c.Core.beginKeyExchange,c.Core.sendMessage,c.DeviceRoot.rewrapMasterPin,c.ui.eval],refs,'recomposition must not wrap twice');assert.equal(timers.size,0,'release registry installs without polling timers');
 }
 const broken=fixture(true);await Promise.resolve();broken.advance(180000);
 assert.equal(await broken.c.sys.loadAllLibs(),false,'unsupported DeviceRoot must fail foundation');
 assert.equal(broken.c.Core.__dmashAcceptanceV50,undefined);broken.c.DeviceRoot.prepareWebAuthnUnlock=()=>{};
 assert.equal(await broken.c.sys.loadAllLibs(),true,'actual foundation retries after dependency repair');
 const {c}=fixture();await Promise.resolve();let failed=true,installed=false;
 c.DmashRuntimeReadiness.register('failure-fixture',100,()=>{if(failed)throw Error('expected failure');installed=true;},()=>installed);
 await assert.rejects(c.DmashRuntimeReadiness.compose(),/UI_RUNTIME_NOT_READY/);failed=false;
 // Other stages remain pending until real lazy dependencies become available.
 assert.equal(await c.sys.loadAllLibs(),true);await c.DmashRuntimeReadiness.compose();assert.equal(installed,true);
 let predicateFails=true,done=false;
 c.DmashRuntimeReadiness.register('predicate-fixture',101,()=>{done=true;},()=>{if(predicateFails)throw Error('predicate fixture');return done;});
 await assert.rejects(c.DmashRuntimeReadiness.compose(),error=>error.cause?.message==='predicate fixture');predicateFails=false;await c.DmashRuntimeReadiness.compose();
 c.DmashRuntimeReadiness.supportFailed(Error('support fixture'));await assert.rejects(c.DmashRuntimeReadiness.compose(),/support fixture/);c.DmashRuntimeReadiness.supportLoaded();await c.DmashRuntimeReadiness.compose();
 console.log('UI runtime readiness regression: PASS (early, late, ordering, idempotence, failure/retry)');
})().catch(e=>{console.error(e);process.exitCode=1;});
