const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.DMASH_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 try {
  const context=await browser.newContext({serviceWorkers:'block'});
  const page=await context.newPage(); const base=String(process.argv[2]).replace(/\/+$/,''); await page.goto(base,{waitUntil:'domcontentloaded'});
  for(const name of ['vendor/nacl-fast.min.js','storage.js','chat_cipher.js','chat_password.js','saved_messages.js']) await page.addScriptTag({url:base+'/js/'+name});
  const result=await page.evaluate(async()=>{
   const check=(condition,label)=>{if(!condition) throw Error(label);};
   window.Core={blindSalt:new Uint8Array(32).fill(3),fastHash:async data=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',data instanceof Uint8Array?data:new TextEncoder().encode(data))),x=>x.toString(16).padStart(2,'0')).join(''),historyPrefetch:new Map()};
   const store=window.DMashStorage, lock=window.DmashChatPassword, cipher=window.DmashChatCipher;
   await store.initGamma(new Uint8Array(32).fill(7)); lock.install(store);
   const id='a'.repeat(64), other='b'.repeat(64), alias=await store.getAlias(id,'L1');
   await store.savePeerGamma(id,'Chat'); await store.savePeerGamma(other,'Other');
   await store.saveMessageGamma(id,'private older text',false,true);
   await store.saveMessageGamma(other,'other text',false,true);
   const oldL3=await store.getAlias(alias+'1','L3');
   await lock.change(store,id,'first-password',null);
   let record=(await store.getBox('blind_peers',alias)).chatLock;
   const secret=await cipher.unwrap(store.masterKey,'first-password',record,alias);
   const firstL3=await store.getAlias(alias+'1','L3');
   check(firstL3!==oldL3,'L3 rotates');
   const firstL2=await lock.location(store,alias,'L2',record);check(firstL2!==alias,'L2 rotates'); check(await store.getBox('blind_messages',oldL3)===null,'old row removed');
   check((await store.getBox('blind_messages',firstL3)).text.chatCipher===1,'history is encrypted');
   check(cipher.open((await store.getBox('blind_messages',firstL3)).text,secret)==='private older text','history preserved');
   await store.saveMessageGamma(id,'incoming while locked',true,false);
   let rejected=false;try{await store.loadMessagesGamma(id,50,0);}catch(_){rejected=true;}check(rejected,'locked reads fail');
   rejected=false;try{await cipher.unwrap(store.masterKey,'wrong',record,alias);}catch(_){rejected=true;}check(rejected,'wrong password rejected');
   const wrongMaster=await crypto.subtle.importKey('raw',new Uint8Array(32).fill(8),'AES-GCM',false,['encrypt','decrypt']);
   rejected=false;try{await cipher.unwrap(wrongMaster,'first-password',record,alias);}catch(_){rejected=true;}check(rejected,'master binding');
   rejected=false;try{await cipher.unwrap(store.masterKey,'first-password',record,'wrong-alias');}catch(_){rejected=true;}check(rejected,'chat binding');
   // A preparation failure must leave all old aliases and history intact.
   const encrypt=store.encryptBox;store.encryptBox=async()=>{throw Error('injected write preparation failure');};
   rejected=false;try{await lock.change(store,id,'failed-password','first-password');}catch(_){rejected=true;}store.encryptBox=encrypt;
   check(rejected,'migration failure');check(await store.getBox('blind_messages',firstL3),'failed migration preserved row');
   const transaction=store.db.transaction.bind(store.db);
   store.db.transaction=function(names,mode){const tx=transaction(names,mode);if(Array.isArray(names)&&names.length===4)queueMicrotask(()=>tx.abort());return tx;};
   rejected=false;try{await lock.change(store,id,'aborted-password','first-password');}catch(_){rejected=true;}
   store.db.transaction=transaction;check(rejected,'native transaction abort');
   check((await store.getBox('blind_peers',alias)).chatLock.wrapped===record.wrapped,'abort preserves descriptor');
   check(await store.getBox('blind_messages',firstL3),'abort preserves history');
   await lock.change(store,id,'second-password','first-password');
   record=(await store.getBox('blind_peers',alias)).chatLock;
   const secondL3=await store.getAlias(alias+'1','L3');check(secondL3!==firstL3,'password change rotates aliases');
   check(await store.getBox('blind_messages',firstL3)===null,'prior protected aliases removed');
   const secondSecret=await cipher.unwrap(store.masterKey,'second-password',record,alias);
   check(cipher.open((await store.getBox('blind_messages',secondL3)).text,secondSecret)==='private older text','rekey preserves text');
   const l3new=await store.getAlias(alias+'2','L3');check(cipher.open((await store.getBox('blind_messages',l3new)).text,secondSecret)==='incoming while locked','locked writes preserved');
   check(await lock.location(store,alias,'L2',record)!==firstL2,'L2 changes with password');
   lock.clear(); store.db.close(); await store.initGamma(new Uint8Array(32).fill(7));
   let callback;const fakeCore={activePeerId:null,customPrompt:(_,__,cb)=>{callback=cb;},customAlert:()=>{throw Error('unlock failed');},selectPeer:async target=>{if(await lock.allow(fakeCore,store,target)) fakeCore.activePeerId=target;}};
   check(await lock.allow(fakeCore,store,id)===false,'reopen requires password');await callback('second-password');
   check((await store.loadMessagesGamma(id,50,0))[0].text==='private older text','password unlock after database reopen');
   lock.clear();rejected=false;try{await store.loadMessagesGamma(id,50,0);}catch(_){rejected=true;}check(rejected,'relock erases decryption grant');
   await lock.change(store,id,'','second-password');check((await store.loadMessagesGamma(id,50,0)).length===2,'remove password preserves history');
   check((await store.loadMessagesGamma(other,50,0))[0].text==='other text','other chat unaffected');
   const saved=window.DmashSavedMessages;await saved.ensure(store);await store.savePeerGamma(saved.ID,'My notes');
   check(saved.peers(await store.loadPeersGamma())[0].name==='My notes','saved rename persists');
   await store.saveMessageGamma(saved.ID,'local note',false,true,'LOCAL');
   check((await store.loadMessagesGamma(saved.ID,50,0))[0].transportState==='LOCAL','no transport status');
   secret.fill(0);secondSecret.fill(0);lock.clear();store.db.close();
   return {passed:true,tests:'real IndexedDB migration, composite key, alias rotation, locked incoming, failure retention, per-chat isolation, saved rename'};
  }); console.log(JSON.stringify(result));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
