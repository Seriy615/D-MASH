'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../js/core_engine.js'),'utf8');
const start=source.indexOf('    deleteChatFlow: function(id, name) {'),end=source.indexOf('    // Core.deleteMessageFlow',start);
assert(start>=0&&end>start,'actual Core deleteChatFlow source required');
const body=source.slice(start,end).trim().replace(/,\s*$/,'');
async function scenario({deleteFails=false,mediaFails=false,nodeFails=false}={}){
 const calls=[],alerts=[];let pending;
 const Core={activePeerId:'a'.repeat(64),recordedNoteTurn:{forgetPeer:()=>calls.push('note')},recordedMedia:{forgetPeer:async()=>{calls.push('media');if(mediaFails)throw Error('media disk');}},customConfirm:(_title,_body,callback)=>{pending=callback;},customAlert:(title,body)=>alerts.push({title,body}),closeChat:()=>calls.push('close'),renderPeers:async()=>calls.push('render')};
 const Storage={deleteChatGamma:async()=>{calls.push('vault');if(deleteFails)throw Error('corrupt owner');}};
 const NodeManager={transportMode:'mesh',removeMeshRoute:async()=>{calls.push('route');if(nodeFails)throw Error('entry offline');return {nodeRemoved:true};}};
 const context={Core,Storage,window:{NodeManager},console};
 const fn=vm.runInNewContext('({'+body+'}).deleteChatFlow',context);
 const owner={shmon:(_level,message)=>calls.push('warn:'+message)};
 fn.call(owner,'a'.repeat(64),'synthetic');await pending();return {calls,alerts};
}
(async()=>{
 const blocked=await scenario({deleteFails:true});
 assert.deepEqual(blocked.calls.map(x=>x.split(':')[0]),['vault','warn']);
 assert.equal(blocked.alerts[0].title,'УДАЛЕНИЕ НЕ ВЫПОЛНЕНО');
 const normal=await scenario();assert.deepEqual(normal.calls,['vault','note','media','route','close','render']);assert.equal(normal.alerts.at(-1).title,'ГОТОВО');
 const media=await scenario({mediaFails:true});assert.deepEqual(media.calls.map(x=>x.split(':')[0]),['vault','note','media','warn','route','close','render']);assert.equal(media.alerts.at(-1).title,'ЧАТ УДАЛЁН');
 const offline=await scenario({nodeFails:true});assert.deepEqual(offline.calls.map(x=>x.split(':')[0]),['vault','note','media','route','warn','close','render']);assert.equal(offline.alerts.at(-1).title,'ЗАЧИСТКА');
 console.log('PASS actual Core deletion callback: vault preflight precedes every side effect; failed preflight preserves media/route; partial media and node cleanup are visible');
})().catch(error=>{console.error(error);process.exitCode=1;});
