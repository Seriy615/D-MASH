'use strict';
const assert=require('node:assert/strict');let starts=0,connects=0,closes=0,options,rootValue,fail=false;
global.DmashNodeRuntimeCoordinatorV4=class{constructor(root,config){rootValue=root;options=config;}status(){return {state:'READY'};}async start(){starts++;if(fail)throw Error('Pinned endpoint unavailable');return this.host;}host={};capture(){return {host:this.host,current:()=>true};}peers(){return [{token:this}];}async connect(token){assert.equal(token,this);connects++;}close(){closes++;}};
const catalog=require('../js/managed_node_catalog_v4.js');
class Element{constructor(doc){this.ownerDocument=doc;this.dataset={};this.listeners={};this.children=[];}append(...items){this.children.push(...items);}setAttribute(k,v){this[k]=v;}addEventListener(k,v){this.listeners[k]=v;}removeEventListener(k){delete this.listeners[k];}remove(){this.removed=true;}}
(async()=>{
 const root={onLock(){}},doc={createElement:()=>new Element(doc)},container=new Element(doc);let ready=0;
 const panel=catalog.mount(container,{deviceRoot:root,onReady:()=>{ready++;}});assert.equal(starts,0,'opening panel never changes live Account or connects');const button=container.children[0].children[2];await button.listeners.click();assert.equal(ready,1);assert.equal(connects,1);assert.equal(rootValue,root);assert.equal(options.localOwnership,'managed');assert.equal(options.bootstrapProfile,'public-v1');assert.equal(options.trustedDescriptors[0].url,'wss://proxy.d-mash.ru/mesh/v4');assert.equal(options.trustedDescriptors[0].nodeId.length,64);assert(Object.isFrozen(catalog.entries()[0]));assert.equal(catalog.coordinator(root),catalog.coordinator(root));
 panel.close();assert.equal(closes,0,'closing panel preserves root transit');assert.equal(container.children[0].removed,true);
 fail=true;const other=new Element(doc);catalog.mount(other,{deviceRoot:root,onReady:()=>{throw Error('must not fallback');}});await other.children[0].children[2].listeners.click();assert.match(other.children[0].children[1].textContent,/Pinned endpoint unavailable/);assert.equal(connects,1);assert.equal(ready,1);
 console.log('PASS managed catalog/component: explicit SSH pin, no eager Account cutover, root coordinator reuse, click/connect, failed endpoint no fallback, closing UI preserves Node; DOM/Host stubs, not browser acceptance');
})().catch(e=>{console.error(e);process.exitCode=1;});
