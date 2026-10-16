'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),{createCore}=require('./fixtures/core_vm.cjs');
const source=fs.readFileSync(require.resolve('../js/node_account_ui_v4.js'),'utf8');
const flush=async()=>{for(let i=0;i<30;i++)await Promise.resolve();};
async function fixture({ready=true,rehydrateReady=true,profile='managed-v4'}={}){
 const f=await createCore(),{core,ctx,storage}=f,locks=new Set(),timers=new Map();let next=0,releaseRoot,releaseRehydrate;
 const root={state:{root:new Uint8Array(32)},onLock(fn){locks.add(fn);return()=>locks.delete(fn);}},rootGate=ready?Promise.resolve():new Promise(resolve=>releaseRoot=resolve),hydrateGate=rehydrateReady?Promise.resolve():new Promise(resolve=>releaseRehydrate=resolve);
 const counts={opened:0,rehydrated:0,polled:0,rendered:0,loaded:0},capture={current:()=>!!root.state};
 const adapter={async rehydrate(){counts.rehydrated++;await hydrateGate;return {restored:1,pending:[]};},async pollSessions(){counts.polled++;return {processed:1,statuses:[]};},close(){}};
 storage.db={};storage.masterKey={};core.blindSalt=new Uint8Array(32);core.activeIdentity='synthetic';core._accountBootAttempt={};core.__dmashAcceptanceV50=true;core.activePeerId='local:saved-messages:v1';core.renderPeers=async()=>{counts.rendered++;};core.loadChat=async()=>{counts.loaded++;};core.openPublicAccountNodeV4=async()=>{counts.opened++;return adapter;};
 ctx.AbortController=AbortController;ctx.DMASH_NODE_PROFILE=profile;ctx.DeviceRoot=root;ctx.DmashManagedNodeCatalogV4={coordinator:()=>({})};ctx.DmashNodeRootLifecycleV4={attach:()=>({start:async()=>{await rootGate;return capture;}})};
 ctx.setInterval=fn=>{const id=++next;timers.set(id,fn);return id;};ctx.clearInterval=id=>timers.delete(id);ctx.setTimeout=fn=>{const id=++next;timers.set(id,fn);return id;};ctx.clearTimeout=id=>timers.delete(id);
 vm.runInContext(source,ctx);
 return {...f,root,locks,timers,counts,adapter,releaseRoot,releaseRehydrate,publish:()=>core._publishAccountSessionV4(),lock(){root.state=null;for(const fn of [...locks])fn();}};
}
(async()=>{
 const {core}=await createCore();assert.equal(typeof core.subscribeAccountSessionV4,'function','Core must expose Account lifecycle subscription');
 const f=await fixture({ready:false}),seen=[];const off=f.core.subscribeAccountSessionV4(s=>seen.push(s));f.core.subscribeAccountSessionV4(()=>{throw Error('isolated observer');});
 const first=f.publish();assert.equal(seen.length,1);assert.equal(f.counts.opened,0,'login publication must not wait for Node');
 let late;const stopLate=f.core.subscribeAccountSessionV4(s=>late=s);assert.equal(late,first,'late subscriber sees committed Account');stopLate();off();
 f.releaseRoot();await flush();assert.equal(f.counts.rehydrated,1,'startup restores without opening any peer');assert(f.counts.polled>=1,'startup immediately drains with Saved selected');assert(f.counts.rendered>=1,'inbound processing refreshes unread sidebar');assert.equal(f.core.activePeerId,'local:saved-messages:v1');
 const before=f.counts.polled;f.core._invalidateAccountSessionV4('TEST_LOGOUT');for(const tick of [...f.timers.values()])await tick();assert.equal(f.counts.polled,before,'logout stops old receiver');assert.equal(f.root.state,first.rootState,'logout preserves Node root');
 const race=await fixture({ready:false});const old=race.publish();race.core._invalidateAccountSessionV4('SWITCH');race.core.activeIdentity='second';const current=race.publish();race.releaseRoot();await flush();assert(old.signal.aborted);current.assertCurrent();assert.equal(race.counts.opened,1,'late old root-ready completion cannot start old Account');assert.equal(race.counts.rehydrated,1);assert.equal(race.timers.size,1,'one watcher survives for current Account');
 race.core._invalidateAccountSessionV4();
 const during=await fixture({rehydrateReady:false});during.publish();await flush();assert.equal(during.counts.rehydrated,1);during.lock();during.releaseRehydrate();await flush();assert.equal(during.counts.polled,0,'root abort during rehydrate cannot start receiver');assert.equal(during.timers.size,0);
 const legacy=await fixture({profile:'legacy-migration'});legacy.publish();await flush();assert.equal(legacy.counts.opened,0,'startup is managed-v4 only');legacy.core._invalidateAccountSessionV4();
 console.log('PASS actual Core+Node UI component startup with Saved selected, immediate drain/unread refresh, late subscription, nonblocking publication, logout/root abort, stale completion and managed-only isolation; lifecycle/adapter stubs, not browser');
})().catch(e=>{console.error(e);process.exitCode=1;});
