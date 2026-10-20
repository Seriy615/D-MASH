'use strict';
// Real panel handlers; minimal DOM/Playwright boundary, no browser/crypto/network.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {privatePairingStep}=require('../../../tools/qa_private_pairing_step.cjs');
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
const settle=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};
class Element {
 constructor(tag,doc){Object.assign(this,{tag,ownerDocument:doc,children:[],attributes:{},listeners:{},dataset:{},disabled:false,textContent:'',value:''});}
 append(...nodes){this.children.push(...nodes);} replaceChildren(...nodes){this.children=nodes;}
 setAttribute(k,v){this.attributes[k]=v;} addEventListener(k,v){this.listeners[k]=v;}
 querySelectorAll(){return this.children.flatMap(n=>[...(n.tag==='button'?[n]:[]),...n.querySelectorAll()]);} querySelector(){return null;}
}
async function fixture(){
 const document={createElement(tag){return new Element(tag,this);},querySelector(s){return s==='[data-node-account-panel]'?this.panel:this.close;}};
 const gate=deferred(),dispatched=deferred();let mounted,pending=Promise.resolve(),advances=0,reads=0;
 const request={direction:'OUTBOUND',targetBundle:JSON.stringify({account_keys:{signing:'a'.repeat(64)}}),state:'PENDING',exchangeId:'exchange',requestDigest:'digest'};
 const adapter={async privateOffers(){reads++;dispatched.resolve();await gate.promise;return [{id:'offer',requests:[request]}];},async advancePrivate(){advances++;return {ready:false};}};
 const core={keys:{sign:{}},openModal(){document.panel=document.createElement('div');document.close=document.createElement('button');},async openPublicAccountNodeV4(){return adapter;}};
 const context={document,DMASH_NODE_PROFILE:'managed-v4',DeviceRoot:{},setInterval(){},crypto:require('node:crypto').webcrypto,
 DmashManagedNodeCatalogV4:{mount(_panel,options){mounted=options;return {close(){}};}}};
 vm.runInNewContext(fs.readFileSync(require.resolve('../js/node_account_ui_v4.js'),'utf8'),context);
 context.DmashNodeAccountUiV4.open(core);await mounted.onReady({host:{publicRoutes:async()=>[]},coordinator:{}});
 const find=name=>document.panel.querySelectorAll().find(n=>n.textContent===name);
 const page={getByRole(_role,{name}){return {first(){return this;},async isVisible(){return !!find(name);},async isEnabled(){return !!find(name)&&!find(name).disabled;},async click(){const node=find(name);assert(node&&!node.disabled,'Click must reach enabled actual control');pending=node.listeners.click();await settle();}};},
 async waitForTimeout(){await settle();},locator(selector){return {async waitFor({state}){if(selector==='[data-node-account-panel]'){assert.equal(state,'visible');return;}assert.equal(selector,'[data-node-account-panel][aria-busy="true"]');assert.equal(state,'hidden');await pending;assert.notEqual(document.panel.attributes['aria-busy'],'true');}};}};
 return {page,gate,dispatched,document,get advances(){return advances;},get reads(){return reads;}};
}
(async()=>{
 const f=await fixture(),events=[];
 const step=privatePairingStep(f.page,{deadline:Date.now()+5000,onAction:event=>events.push(event)});
 await f.dispatched.promise;await new Promise(setImmediate);
 assert.equal(f.document.panel.attributes['aria-busy'],'true','Real refresh remains busy beyond the old fixed pause');
 f.gate.resolve();await step;
 assert.equal(f.advances,1,'Delayed refresh must still dispatch the explicit Confirm; a completed refresh is not a confirmed contact');
 assert.equal(f.reads,1,'Do not refresh again before the explicit Confirm');
 assert.equal(f.document.panel.children[0].textContent,'Ожидание подтверждения второго участника','Pending result must not claim a contact/key success');
 assert.deepEqual(events.map(e=>e.action+':'+e.phase),['refresh:started','refresh:completed','confirm:started','confirm:completed']);
 await assert.rejects(()=>privatePairingStep(f.page,{deadline:Date.now()-1}),/deadline/,'Expired budget cannot start another UI action');
 assert.equal(f.reads,1);
 console.log('PASS PRIVATE QA step: actual delayed panel refresh cannot starve Confirm, explicit pending preserved, action timings observable, original deadline enforced; no browser/network acceptance');
})().catch(e=>{console.error(e);process.exitCode=1;});
