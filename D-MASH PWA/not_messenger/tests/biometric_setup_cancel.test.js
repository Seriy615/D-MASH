'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../js/ui_logic.js'),'utf8').replace("ui.init();", "/* isolated UI fixture: bootstrap covered separately */");
function fixture(){
 const nodes=new Map(),values=new Map([['sys_configured','true'],['cfg_biometric_trigger','3']]),writes=[];let enrollmentCalls=0,settingsCalls=0,resolveEnrollment;
 const listeners=new Map(),timers=new Map();let nextTimer=0;
 function element(id){return {id,dataset:{},style:{setProperty(k,v){this[k]=v;}},addEventListener(type,fn){listeners.set(id+':'+type,fn);},appendChild(node){nodes.set(node.id,node);},remove(){nodes.delete(this.id);}};}
 for(const id of ['app-container','settings-layer','current','history','keypad'])nodes.set(id,element(id));
 const state={root:new Uint8Array(32)};
 const c={console,TextEncoder,TextDecoder,Uint8Array,Promise,localStorage:{getItem:k=>values.get(k)||null,setItem(k,v){writes.push([k,v]);values.set(k,v);}},
 document:{getElementById:id=>nodes.get(id)||null,createElement:()=>element(''),querySelector:()=>null},addEventListener(){},
 setTimeout(fn){const id=++nextTimer;timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id),
 DeviceRoot:{state},Core:{deviceState:state,setupDeviceBiometrics(){enrollmentCalls++;return new Promise(r=>{resolveEnrollment=r;});}},window:null};c.window=c;vm.createContext(c);vm.runInContext(source,c);const ui=vm.runInContext('ui',c);ui.bindCalculatorBiometricTrigger();ui.renderGlobalSettings=()=>{settingsCalls++;};
 return {c,ui,nodes,values,writes,listeners,timers,get calls(){return enrollmentCalls;},get settingsCalls(){return settingsCalls;},resolve:value=>resolveEnrollment(value)};
}
(async()=>{
 const f=fixture();f.ui.beginBiometricTriggerSetup();const fail=f.ui.handleBiometricHold('7');f.resolve(false);await fail;
 assert.equal(f.ui.mode,0,'failed enrollment exits mode6');assert.equal(f.ui.consumeLongPress('7'),true,'immediate refusal preserves suppression of the release click');assert.equal(f.settingsCalls,1);assert.equal(f.values.get('cfg_biometric_trigger'),'3');assert.deepEqual(f.writes,[]);
 const thrown=fixture();thrown.c.Core.setupDeviceBiometrics=async()=>{throw Error('synthetic enrollment refusal');};thrown.ui.beginBiometricTriggerSetup();await thrown.ui.handleBiometricHold('7');assert.equal(thrown.ui.mode,0);assert.deepEqual(thrown.writes,[],'throwing enrollment preserves trigger');
 const cancel=fixture();cancel.ui.beginBiometricTriggerSetup();assert.ok(cancel.nodes.get('biometric-setup-cancel'),'explicit accessible cancel is shown');assert.equal(cancel.nodes.get('biometric-setup-cancel').type,'button');cancel.nodes.get('biometric-setup-cancel').onclick();assert.equal(cancel.ui.mode,0);assert.equal(cancel.calls,0);assert.equal(cancel.settingsCalls,1);assert.equal(cancel.nodes.has('biometric-setup-cancel'),false);
 const late=fixture();late.ui.beginBiometricTriggerSetup();const pending=late.ui.handleBiometricHold('8');await late.ui.handleBiometricHold('9');assert.equal(late.calls,1,'no parallel enrollment');late.ui.cancelBiometricTriggerSetup();late.ui.beginBiometricTriggerSetup();late.resolve(true);await pending;assert.equal(late.values.get('cfg_biometric_trigger'),'3','cancelled completion cannot configure a trigger in a newer flow');assert.equal(late.ui.mode,6);assert.deepEqual(late.writes,[]);
 const changed=fixture();changed.ui.beginBiometricTriggerSetup();const stale=changed.ui.handleBiometricHold('8');changed.c.DeviceRoot.state=null;changed.c.Core.deviceState=null;changed.resolve(true);await stale;assert.deepEqual(changed.writes,[],'locked/replaced DeviceRoot cannot commit trigger');
 const valid=fixture();valid.ui.biometricHoldMs=1000;valid.ui.beginBiometricTriggerSetup();assert.match(valid.ui.hist,/1 СЕК/);for(const token of ['AC','±','='])await valid.ui.handleBiometricHold(token);assert.equal(valid.calls,0);const success=valid.ui.handleBiometricHold('5');valid.resolve(true);await success;assert.equal(valid.values.get('cfg_biometric_trigger'),'5');assert.equal(valid.ui.mode,0);assert.equal(valid.nodes.has('biometric-setup-cancel'),false);
 const hold=fixture();hold.ui.beginBiometricTriggerSetup();const target={closest:()=>({dataset:{calcToken:'7'}})};hold.listeners.get('keypad:pointerdown')({target,button:0});assert.equal(hold.timers.size,1);hold.ui.cancelBiometricTriggerSetup();assert.equal(hold.timers.size,0,'cancel clears an unqualified hold timer');assert.equal(hold.ui._heldToken,null);assert.equal(hold.calls,0);
 console.log('PASS biometric setup cancel/failure/valid token/instruction/duplicate request/late completion/root change/hold cancellation');
})().catch(error=>{console.error(error);process.exitCode=1;});
