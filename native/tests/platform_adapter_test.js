'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
(async()=>{
 const calls=[],timers=new Map();
 const context=vm.createContext({__dmashHost(op,...args){calls.push([op,...args]);if(op==='isWorker')return false;if(op==='timerStart')timers.set(args[0],args[1]);if(op==='timerStop')timers.delete(args[0]);},console});
 vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../js/platform.js'),'utf8'),context);
 for(const [input,expected] of [[0,0],[-1,0],[12.75,12],[NaN,0],[Infinity,2147483647]]){
  const id=context.setTimeout(()=>{},input);assert.equal(timers.get(id),expected);context.clearTimeout(id);assert(!timers.has(id));
 }
 let called=0;const cancelled=context.setTimeout(()=>called++,0);context.clearTimeout(cancelled);context.__nativeEvent('timer',cancelled,'');assert.equal(called,0);
 let interval;interval=context.setInterval(()=>{called++;context.clearInterval(interval);},1.9);timers.delete(interval);context.__nativeEvent('timer',interval,'');assert.equal(called,1);assert(!timers.has(interval));
 const next=context.setTimeout(()=>context.setTimeout(()=>called++,0),0);timers.delete(next);context.__nativeEvent('timer',next,'');assert(timers.size>=1);
 context.NativePlatform.close();assert.equal(timers.size,0);
 await assert.rejects(context.crypto.subtle.importKey('raw',vm.runInContext('new Uint8Array(32)',context),'HKDF',true,['deriveBits']),{name:'SyntaxError'});
 assert.equal(context.__dmashHost,undefined);
 console.log('platform timers normalization/cancel/reentrant interval/close and nonextractableHKDF PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
