'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const pin='3e4a0e3f796f8d594e5473249f49460c769bfdd293b4788cdaf78bc314f12b17',old='wss://stage-api-ems.d-mash.ru/dmash-client/v1',url='wss://proxy.d-mash.ru/dmash-client/v1';
function fixture(items,active=old,{failActiveWrite=false}={}){
 const data=new Map([['dmash_node_endpoints_v1',JSON.stringify(items)],['dmash_active_node_v1',active],['identity-sentinel','unchanged']]),storage={getItem:k=>data.get(k)??null,setItem:(k,v)=>{if(failActiveWrite&&k==='dmash_active_node_v1'&&v===url)throw Error('STORAGE_WRITE_FAILED');data.set(k,String(v));},removeItem:k=>data.delete(k)};
 const context={URL,Map,Set,Object,Array,Error,Promise,console,localStorage:storage,sessionStorage:storage,window:{location:{href:'https://messenger.d-mash.ru/'},dispatchEvent(){}},document:{getElementById:()=>null},CustomEvent:class{}};
 vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../js/node_manager.js'),'utf8'),context);
 return {manager:context.window.NodeManager,data};
}
const oldRow={url:old,nodeId:pin,label:'My Node',public:true,autoConnect:true,notificationEnabled:true,capabilities:['PULL'],customPreference:'retain'};
const other={url:'wss://custom.invalid/dmp-c/v3',nodeId:'a'.repeat(64),label:'custom'};
let f=fixture([oldRow,other]);
assert.equal(f.manager.active.url,url);assert.equal(f.manager.endpoints[0].dmpcEndpoint,'wss://proxy.d-mash.ru/dmp-c/v3');
assert.deepEqual(JSON.parse(f.data.get('dmash_node_endpoints_v1')),[{...oldRow,url,dmpcEndpoint:'wss://proxy.d-mash.ru/dmp-c/v3'},other]);
assert.equal(f.data.get('identity-sentinel'),'unchanged');const saved=f.data.get('dmash_node_endpoints_v1');f.manager.load();assert.equal(f.data.get('dmash_node_endpoints_v1'),saved);
for(const row of [{...oldRow,nodeId:'b'.repeat(64)},{...oldRow,url:old+'?custom=1'},{...oldRow,dmpcEndpoint:'wss://custom.invalid/dmp-c/v3'},{...oldRow,url:'wss://stage-api-ems.d-mash.ru/custom'}]){
 f=fixture([row]);assert.deepEqual(JSON.parse(f.data.get('dmash_node_endpoints_v1')),[row]);
}
const canonical={...oldRow,url,dmpcEndpoint:'wss://proxy.d-mash.ru/dmp-c/v3'};
for(const path of ['/dmash-client/v1','/dmash-client/v3','/dmp-c/v3']){
 const previous='wss://stage-api-ems.d-mash.ru'+path;
 f=fixture([{...oldRow,url:previous,dmpcEndpoint:previous}],previous);
 assert.equal(f.manager.active.url,url);assert.equal(f.manager.active.nodeId,pin);
}
f=fixture([canonical],old);assert.equal(f.manager.active.url,url,'repair interrupted list/selection write');
f=fixture([oldRow,other],old,{failActiveWrite:true});
assert.equal(f.manager.error,'STORAGE_WRITE_FAILED');assert.equal(f.manager.active,null);
assert.equal(f.data.get('dmash_node_endpoints_v1'),JSON.stringify([oldRow,other]),'failed selection write restores exact list');
assert.equal(f.data.get('dmash_active_node_v1'),old);assert.equal(f.data.get('identity-sentinel'),'unchanged');
f=fixture([{...oldRow,nodeId:'d'.repeat(64)},canonical]);assert.equal(f.manager.active.url,old,'never redirect active wrong-pin entry to a different node');
f=fixture([oldRow,canonical]);assert.equal(f.manager.endpoints.length,1);assert.equal(f.manager.active.url,url);
for(const conflict of [{...canonical,nodeId:'c'.repeat(64)},{...canonical,notificationEnabled:false}]){
 f=fixture([oldRow,conflict]);assert.equal(f.manager.endpoints.length,0);assert.equal(f.manager.error,'EMS_ENDPOINT_MIGRATION_CONFLICT');assert.equal(f.manager.active,null);assert.deepEqual(JSON.parse(f.data.get('dmash_node_endpoints_v1')),[oldRow,conflict]);
}
for(const [left,right] of [[{foo:1},{foo:2}],[{items:[1,2]},{items:[2,1]}],[{foo:null},{}],[{outer:{foo:1}},{outer:{foo:2}}]]){
 const oldNested={...oldRow,customPreference:left},newNested={...canonical,customPreference:right};
 f=fixture([oldNested,newNested]);assert.equal(f.manager.error,'EMS_ENDPOINT_MIGRATION_CONFLICT','nested preferences must never be silently discarded');assert.equal(f.manager.endpoints.length,0);assert.deepEqual(JSON.parse(f.data.get('dmash_node_endpoints_v1')),[oldNested,newNested]);
}
// Equal JSON objects may reorder keys; arrays retain their actual order.
f=fixture([{...oldRow,customPreference:{outer:{a:1,b:2},list:[1,null]}},{...canonical,customPreference:{list:[1,null],outer:{b:2,a:1}}}]);assert.equal(f.manager.endpoints.length,1);assert.equal(f.manager.active.url,url);
const collision=[{...oldRow,customPreference:{foo:1}},{...canonical,customPreference:{foo:2}},other];
f=fixture(collision,other.url);assert.equal(f.manager.error,'EMS_ENDPOINT_MIGRATION_CONFLICT');assert.equal(f.manager.endpoints.length,1);assert.equal(f.manager.endpoints[0].url,other.url);assert.equal(f.manager.active.url,other.url);assert.equal(f.data.get('dmash_node_endpoints_v1'),JSON.stringify(collision),'conflict leaves exact persisted bytes intact');assert.equal(f.data.get('identity-sentinel'),'unchanged');
f=fixture(collision);assert.equal(f.manager.active,null);assert.equal(f.manager.endpoints.length,1);assert(!f.manager.endpoints.some(item=>item.url===old||item.url===url),'quarantined EMS never falls back to retired host');
console.log('PASS preexisting pinned EMS URL migration preserves preferences/selection/identity; custom and wrong-pin untouched; conflicts fail closed without storage reset');
