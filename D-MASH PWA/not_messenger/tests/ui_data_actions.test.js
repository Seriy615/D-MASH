"use strict";
// Production renderers and command binder; a minimal DOM decodes attributes
// and dispatches real registered listener functions. Real Chromium is separate.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const decode = x => x.replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
let delegated;
function container() {
  return {style:{},html:'',buttons:[],set innerHTML(value){this.html=value;this.buttons=[];for(const match of value.matchAll(/<button\b([^>]*)>/g)){const attributes={};for(const m of match[1].matchAll(/([\w-]+)="([^"]*)"/g))attributes[m[1]]=decode(m[2]);this.buttons.push({attributes,dataset:{uiAction:attributes['data-ui-action'],uiArgs:attributes['data-ui-args'],nodeAction:attributes['data-node-action'],nodeIndex:attributes['data-node-index']},listeners:[],addEventListener(type,fn){assert.equal(type,'click');this.listeners.push(fn)},closest(){return this},click(){for(const fn of this.listeners)fn();delegated?.({target:this})}})}},get innerHTML(){return this.html},querySelectorAll(selector){return this.buttons.filter(b=>selector==='[data-ui-action]'?b.dataset.uiAction:b.dataset.nodeAction)}};
}
const modal=container(),gate=container();
const window={addEventListener(){},ui:{}};
const document={getElementById:()=>modal,querySelector:()=>gate,addEventListener(type,fn){assert.equal(type,"click");assert.equal(delegated,undefined,"one delegated DOM listener");delegated=fn}};
const context={window,document,btoa,atob,console,TextEncoder,TextDecoder,Uint8Array,localStorage:{getItem(){return null}},setInterval(){},clearInterval(){}};
vm.runInNewContext(fs.readFileSync(require.resolve('../js/core_engine.js'),'utf8'),context);
const Core=window.Core;
const hostile="x'-globalThis.SENTINEL=1-'\"><img src=x onerror=globalThis.SENTINEL=2>\n&é";
let calls=[];Core.removeQuickName=id=>calls.push(id);
Core.openModal(hostile,'<button id="intentional-body-control">body</button>');
assert.ok(!modal.innerHTML.includes('<h4>'+hostile),'title cannot insert markup');
assert.ok(modal.innerHTML.includes('&lt;img'),'hostile title markup rendered as text');
assert.ok(modal.innerHTML.includes('<button id="intentional-body-control">'),'intentional body HTML contract preserved');
assert.equal(modal.buttons.length,1,'title does not create controls');
assert.equal(context.SENTINEL,undefined);
Core.openModal('synthetic',`<button ${Core.dataActionAttributes('removeQuickName',[hostile])}>remove</button>`);
assert.equal(modal.buttons.length,1);assert.equal(modal.buttons[0].attributes.onclick,undefined);
modal.buttons[0].click();assert.deepEqual(calls,[hostile]);assert.equal(context.SENTINEL,undefined);
Core.openModal('synthetic',`<button ${Core.dataActionAttributes('constructor',[])}>invalid</button>`);
const beforeInvalid=calls.length;modal.buttons[0].click();assert.equal(calls.length,beforeInvalid,'unknown/inherited commands cannot dispatch');
// Every supported string argument preserves quotes, markup, Unicode and newline.
for(const action of ['readPendingContactRequest','startAcceptPendingContactRequest','rejectPendingContactRequest','acceptPendingContactRequest','removeAccountFlow','removeAccountBiometric','accountBiometricLogin','choosePublicContactQuickName','copyPeerId','startCircleRecording','decryptMediaEncoded','cancelStoredFile','openStoredFileEncoded','deleteMessageFlow']){
 Core[action]=(...args)=>calls.push(args);
 Core.openModal('test',`<button ${Core.dataActionAttributes(action,[hostile,hostile])}>go</button>`);
 modal.buttons[0].click();assert.deepEqual(calls.at(-1),[hostile,hostile]);
}
const source=fs.readFileSync(require.resolve('../js/acceptance_fixes.js'),'utf8');
const body=source.split('ui.renderGlobalNodes = async function repairedGlobalNodes() {')[1].split('\n        };')[0];
const url="wss://example.invalid/x'-console.log(987654321)-'";
const ui={};for(const action of ['toggleGlobalNodeConnection','selectGlobalNode','removeGlobalNode'])ui[action]=x=>calls.push([action,x]);
const manager={originNodes:[{}],endpoints:[{url,label:hostile}],active:{url}};
const render=vm.runInNewContext('(async function(){'+body+'})',{document,global:{NodeManager:manager},nodeState:()=>({state:'idle',capabilities:[]}),esc:x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),URL});
(async()=>{await render.call(ui);assert.equal(gate.buttons.filter(b=>b.dataset.nodeAction).length,3);for(const button of gate.buttons.filter(b=>b.dataset.nodeAction)){assert.equal(button.attributes.onclick,undefined);button.click();assert.equal(calls.at(-1)[1],url)}assert.ok(!gate.innerHTML.includes('<img'));assert.equal(context.SENTINEL,undefined);
assert.doesNotMatch(Core.renderStub({type:'image',name:hostile,data:'synthetic'},hostile),/onclick=/,'media ID is data');
assert.ok(Core.renderStub({type:'image',name:hostile,data:'synthetic'},hostile).includes('data-ui-action="decryptMediaEncoded"'));
for(const name of ['core_engine','ui_logic','acceptance_v50','acceptance_v51','acceptance_fixes']){const text=fs.readFileSync(require.resolve('../js/'+name+'.js'),'utf8');assert.doesNotMatch(text,/onclick="[^"\n]*decodeURIComponent\(/,name+' has no URI-decoded data in JavaScript attributes');}
for (const name of ['../index.html','../js/release.js','../js/acceptance_v51.js']) {
 const text=fs.readFileSync(require.resolve(name),'utf8');
 assert.doesNotMatch(text,/(?:src=["']|["'`])(?:js\/)?(?:stability_fixes|acceptance_v53)\.js/,'historical unsafe wrappers cannot return to effective loaders');
}
console.log('DOM data actions: hostile data preserved, no JavaScript interpolation, Node connect/select/remove dispatch PASS');})().catch(e=>{console.error(e);process.exitCode=1});
