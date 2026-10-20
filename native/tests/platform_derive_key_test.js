'use strict';
// Exercise the actual platform facade against independent Node/WebCrypto bytes.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const {webcrypto,hkdfSync,createCipheriv}=require('node:crypto');
const handles=new Map();let sequence=0;
const context={__dmashHost(op,...args){
 if(op==='isWorker')return false;
 if(op==='keyImport'){const handle=++sequence;handles.set(handle,{bytes:Buffer.from(args[0]),algorithm:args[1],usages:args[2].split(',')});return handle;}
 if(op==='hkdfKey'){const key=handles.get(args[0]);assert.equal(key.algorithm,'HKDF');assert(key.usages.includes('deriveKey'));return new Uint8Array(hkdfSync('sha256',key.bytes,args[1],args[2],args[3])).buffer;}
 if(op==='encrypt'){const key=handles.get(args[0]);assert(key.usages.includes('encrypt'));const cipher=createCipheriv('aes-'+key.bytes.length*8+'-gcm',key.bytes,args[1]);cipher.setAAD(args[2]);return Uint8Array.from(Buffer.concat([cipher.update(args[3]),cipher.final(),cipher.getAuthTag()])).buffer;}
 throw Error('Unexpected native port '+op);
}};vm.createContext(context);vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../js/platform.js'),'utf8'),context);
(async()=>{
 const parameters={name:'HKDF',hash:'SHA-256',salt:Uint8Array.from([1,2,3]),info:Uint8Array.from([4,5])},source=new Uint8Array(32).fill(7),iv=new Uint8Array(12).fill(8),plain=Uint8Array.from([9,10]),aad=Uint8Array.from([11]);
 // Construct inputs in the platform realm, as actual compiled Account JS does.
 context.input=JSON.stringify({parameters:{...parameters,salt:[1,2,3],info:[4,5]},source:Array.from(source),iv:Array.from(iv),plain:Array.from(plain),aad:Array.from(aad)});
 const actual=await vm.runInContext(`(async()=>{const v=JSON.parse(input),parameters={...v.parameters,salt:Uint8Array.from(v.parameters.salt),info:Uint8Array.from(v.parameters.info)},key=await crypto.subtle.importKey('raw',Uint8Array.from(v.source),'HKDF',false,['deriveKey']),derived=await crypto.subtle.deriveKey(parameters,key,{name:'AES-GCM',length:256},false,['encrypt']);let denied=false;try{await crypto.subtle.deriveBits(parameters,key,256);}catch(e){denied=e.name==='InvalidAccessError';}return {denied,usages:derived.usages,extractable:derived.extractable,cipher:Array.from(new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:Uint8Array.from(v.iv),additionalData:Uint8Array.from(v.aad)},derived,Uint8Array.from(v.plain))))};})()`,context);
 const reference=await webcrypto.subtle.importKey('raw',source,'HKDF',false,['deriveKey']),derived=await webcrypto.subtle.deriveKey(parameters,reference,{name:'AES-GCM',length:256},false,['encrypt']);
 const expected=await webcrypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},derived,plain);
 assert(actual.denied);assert.equal(actual.extractable,false);assert.deepEqual(Array.from(actual.usages),['encrypt']);assert.deepEqual(Array.from(actual.cipher),Array.from(new Uint8Array(expected)));
 console.log('native HKDF deriveKey → AES-GCM matches independent WebCrypto; deriveKey-only usage cannot deriveBits PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
