'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const memory=()=>{const m=new Map();return{getItem:k=>m.get(k)||null,setItem:(k,v)=>m.set(k,String(v)),removeItem:k=>m.delete(k)};};
const url='wss://node.example.test/dmash-client/v1',pin='ab'.repeat(32);let catalog=[{url,label:'Catalog Node',nodeId:pin,capabilities:['can_route'],dmpcEndpoint:'wss://node.example.test/dmp-c/v3'}];
const context={URL,JSON,Map,Set,Object,Array,Error,Promise,console,localStorage:memory(),sessionStorage:memory(),window:{location:{href:'https://app.example.test/'},dispatchEvent(){}},document:{getElementById(){return null}},CustomEvent:class{},fetch:async()=>({ok:true,json:async()=>({nodes:catalog})})};
vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../js/node_manager.js'),'utf8'),context);const manager=context.window.NodeManager;
(async()=>{
 const list=await manager.loadOriginList();const first=manager.addCatalogNode(list[0]);assert.equal(first.nodeId,pin);assert.equal(first.dmpcEndpoint,catalog[0].dmpcEndpoint);assert.deepEqual(Array.from(first.capabilities),['can_route']);
 first.autoConnect=false;const same=manager.add(url,'Manual edit');assert.equal(same,first);assert.equal(same.nodeId,pin);assert.equal(same.autoConnect,false);assert.equal(manager.endpoints.length,1);
 assert.throws(()=>manager.add(url,'Conflicting catalog',{nodeId:'cd'.repeat(32),autoConnect:true}),/conflicts/);assert.equal(first.nodeId,pin);assert.equal(first.autoConnect,false);assert.equal(manager.endpoints.length,1);
 assert.equal(JSON.parse(context.localStorage.getItem(manager.storageKey))[0].nodeId,pin);
 catalog=[{url,nodeId:'not-a-pin'}];await assert.rejects(manager.loadOriginList(),/32-byte hex/);
 const original=manager.originNodes;assert.equal(original[0].nodeId,pin,'failed catalog cannot replace last validated catalog');
 const saved=[{url:'wss://first.example.test/v3',nodeId:pin},{url:'wss://bad.example.test/v3',nodeId:'legacy-malformed',autoConnect:true},{url:'wss://last.example.test/v3',nodeId:'ef'.repeat(32)}];
 context.localStorage.setItem(manager.storageKey,JSON.stringify(saved));manager.load();assert.equal(manager.endpoints.length,3);assert.equal(manager.endpoints[1].nodeId,'legacy-malformed');assert.throws(()=>manager.connectEndpoint(manager.endpoints[1]),/explicit repair/);assert.equal(manager.connections.size,0);
 manager.addCatalogNode(list[0]);const retained=JSON.parse(context.localStorage.getItem(manager.storageKey));assert.equal(retained.length,4);assert.equal(retained[0].nodeId,pin);assert.equal(retained[1].nodeId,'legacy-malformed');assert.equal(retained[2].nodeId,'ef'.repeat(32));
 console.log('Node catalog identity: validated metadata, preserved existing pin/policy, no duplicate, conflicting pin fails closed');
})().catch(e=>{console.error(e);process.exitCode=1});
