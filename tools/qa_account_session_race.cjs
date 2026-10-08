'use strict';
// Supplemental runtime instrumentation inside an actual UI-created synthetic Account.
// This does not invent an active-Account login control or replace UI acceptance.
module.exports=async(page,{account,password})=>page.evaluate(async({account,password})=>{
 const check=(condition,label)=>{if(!condition)throw Error(label);};
 const c=Core.captureAccountSessionV4(),root=DeviceRoot.state,host=Core.nodeTransportV4?.host||null;
 const originalHash=argon2.hash,originalInit=Storage.initGamma,originalErase=DeviceRoot.eraseForExplicitWipe;let eraseCalls=0;
 DeviceRoot.eraseForExplicitWipe=async()=>{eraseCalls++;throw Error('Unexpected identity erase');};
 let releaseHash,enteredHash;const entered=new Promise(r=>enteredHash=r),gate=new Promise(r=>releaseHash=r);
 argon2.hash=async(...args)=>{enteredHash();await gate;return originalHash.apply(argon2,args);};
 let releaseWrite;const writeGate=new Promise(r=>releaseWrite=r);
 const write=(async()=>{await writeGate;c.assertCurrent();const iv=crypto.getRandomValues(new Uint8Array(12)),plain=new TextEncoder().encode('synthetic captured write');
  const blob=await crypto.subtle.encrypt({name:'AES-GCM',iv},c.masterKey,plain);c.assertCurrent();
  await new Promise((resolve,reject)=>{const tx=c.db.transaction('pairing_material','readwrite');
   const abort=()=>{try{tx.abort();}catch(_){}};c.signal.addEventListener('abort',abort,{once:true});
   tx.oncomplete=()=>{c.signal.removeEventListener('abort',abort);try{c.assertCurrent();resolve();}catch(e){reject(e);}};
   tx.onabort=()=>{c.signal.removeEventListener('abort',abort);reject(Error('captured write aborted'));};
   c.assertCurrent();tx.objectStore('pairing_material').put({alias:'synthetic-session-race',blob:Array.from(new Uint8Array(blob)),iv:Array.from(iv)});
  });return {blob,iv};})();
 try{
  const wrong=Core.boot(account,'Wrong-Synthetic-session-key').then(()=>{throw Error('wrong key accepted');},error=>{check(error.message.includes('Неверный ключ'),'wrong key unexpected error');});
  await entered;check(c.isCurrent(),'pending login revoked authenticated session');releaseWrite();const sealed=await write;
  releaseHash();await wrong;c.assertCurrent();check(Storage.masterKey===c.masterKey&&Storage.db===c.db,'wrong key replaced vault');
  check(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:sealed.iv},c.masterKey,sealed.blob))==='synthetic captured write','captured write unreadable');
  argon2.hash=originalHash;
  let recoveryRefused=false;try{await Core.recoverDeviceAfterConfirmedMaster('wrong-root-secret');}catch(_){recoveryRefused=true;}
  check(recoveryRefused&&eraseCalls===0&&DeviceRoot.state===root&&Storage.db===c.db&&Storage.masterKey===c.masterKey,'recovery replaced root/vault');
  let beforeReplacement=false;
  Storage.initGamma=async function(...args){check(c.signal.aborted&&!c.isCurrent(),'switch did not revoke before opening vault');check(Storage.db===c.db&&Storage.masterKey===c.masterKey,'vault changed before revoke observation');beforeReplacement=true;return originalInit.apply(this,args);};
  await Core.boot(account,password);check(beforeReplacement,'vault replacement not observed');check(Core.captureAccountSessionV4().generation>c.generation,'generation reused');
  check(DeviceRoot.state===root,'successful switch replaced root');
  if(host)check(Core.nodeTransportV4?.host===host&&!host.closed,'Account login replaced Node Host');
  return {pendingWrongKeyCapturedWrite:true,wrongKeyPreviousSessionUsable:true,revokeBeforeVaultReplacement:true,rootRecoveryFailclosed:true,nodeHost:host?'SAME_HOST':'NOT_RUN: ordinary Node v4 not wired'};
 }finally{argon2.hash=originalHash;Storage.initGamma=originalInit;DeviceRoot.eraseForExplicitWipe=originalErase;releaseHash?.();releaseWrite?.();}
},{account,password});
