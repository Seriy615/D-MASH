'use strict';
// Separate encrypted local control journal. Caller supplies the genuine local
// Ownership registry and a separately domain-keyed NodeInbox storage instance.
(function(g){
 const text=x=>new TextEncoder().encode(x),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
 class Dispatcher{
  #tail=Promise.resolve();
  constructor({ownership,inbox,codec,clock=()=>Math.floor(Date.now()/1000)}){this.ownership=ownership;this.inbox=inbox;this.codec=codec;this.clock=clock;this.closed=false;}
  check(token,options){if(this.closed)throw Error('Bootstrap closed');this.inbox.check();return this.ownership.owner(token,options);}
  run(fn){const task=this.#tail.then(fn);this.#tail=task.catch(()=>{});return task;}
  async key(kind,owner,id=''){return this.inbox.alias('bootstrap-v4|'+kind+'|'+owner.ownerSlot+'|'+owner.routeId+'|'+id);}
  async load(key){const row=await this.inbox.store.read(key);return row?{row,value:await this.inbox.decrypt(row)}:null;}
  async save(token,key,previous,value){const encrypted=await this.inbox.encrypt(key,value);this.check(token);if(!await this.inbox.store.cas(key,previous?.row.revision??null,encrypted,{guard:()=>{this.check(token);return true;}}))throw Error('Bootstrap journal conflict');}
  register(token,localBundle){return this.run(async()=>{const owner=this.check(token);await this.codec.localOffer(localBundle,owner);
   const key=await this.key('config',owner),old=await this.load(key);if(old){if(old.value.localBundle!==localBundle)throw Error('Bootstrap renewal requires explicit migration');return true;}
   await this.save(token,key,null,{kind:'bootstrap-config',ownerSlot:owner.ownerSlot,routeId:owner.routeId,localBundle});return true;});}
  request(token,serialized,{targetBundle=null,outbound=false}={}){return this.run(async()=>{const owner=this.check(token),config=await this.load(await this.key('config',owner));if(!config)throw Error('Bootstrap not provisioned');
   if(outbound&&JSON.parse(serialized).bundle!==config.value.localBundle)throw Error('Outbound request not owned by local bundle');
   if(!outbound&&targetBundle!==null)throw Error('Unexpected target override');
   const target=outbound?targetBundle:config.value.localBundle;
   const verified=await this.codec.inspect(target,serialized),key=await this.key('request',owner,verified.exchangeId),old=await this.load(key);
   if(old){if(old.value.requestDigest!==verified.requestDigest)throw Error('Conflicting bootstrap replay');this.check(token);return {state:old.value.state,duplicate:true,requestDigest:verified.requestDigest};}
   let count=0,localCount=0,bytes=0;
   for(const row of await this.inbox.store.all()){
    let value;try{value=await this.inbox.decrypt(row);}catch(_){this.check(token);continue;}if(value.kind!=='bootstrap-request')continue;
    if(value.expiresAt<=this.clock()&&value.state!=='SELECTED'){this.check(token);await this.inbox.store.cas(row.key,row.revision,null,{guard:()=>{this.check(token);return true;}});continue;}
    count++;if(value.ownerSlot===owner.ownerSlot)localCount++;bytes+=text(value.serialized||'').length;
   }
   if(count>=32||localCount>=8||bytes+text(serialized).length>128*1024)throw Error('Bootstrap pending quota');
   const initial=JSON.parse(serialized).accept_receipt;
   await this.save(token,key,null,{kind:'bootstrap-request',ownerSlot:owner.ownerSlot,routeId:owner.routeId,exchangeId:verified.exchangeId,requestDigest:verified.requestDigest,bindingDigest:verified.bindingDigest,remoteAccount:verified.remoteAccount,expiresAt:verified.expiresAt,state:outbound?'SELECTED':'PENDING',direction:outbound?'OUTBOUND':'INBOUND',targetBundle:outbound?target:null,serialized,receipts:initial?{ACCEPT:initial}:{}});
   return {state:outbound?'SELECTED':'PENDING',duplicate:false,requestDigest:verified.requestDigest};});}
  select(token,exchangeId,requestDigest,{deny=false}={}){return this.run(async()=>{const owner=this.check(token),key=await this.key('request',owner,exchangeId),old=await this.load(key);if(!old||old.value.requestDigest!==requestDigest||old.value.expiresAt<=this.clock())throw Error('Bootstrap selection mismatch');
   if(old.value.state==='DENIED')throw Error('Bootstrap request denied');
   await this.save(token,key,old,{...old.value,state:deny?'DENIED':'SELECTED',...(deny?{serialized:null,receipts:{}}:{})});return {state:deny?'DENIED':'SELECTED'};});}
  receipt(token,exchangeId,serialized){return this.run(async()=>{const owner=this.check(token),key=await this.key('request',owner,exchangeId),old=await this.load(key);if(!old||old.value.state!=='SELECTED'||old.value.expiresAt<=this.clock())throw Error('Explicit bootstrap selection required');
   const config=await this.load(await this.key('config',owner)),candidate=await this.codec.inspect(old.value.targetBundle||config.value.localBundle,old.value.serialized),verified=this.codec.receipt(candidate,serialized),phase=verified.phase;
   const previous=old.value.receipts[phase];if(previous){if(previous!==serialized)throw Error('Conflicting receipt replay');return {stored:true,duplicate:true};}
   if(phase==='CONFIRM'&&!old.value.receipts.ACCEPT)throw Error('ACCEPT receipt required first');
   const receipts={...old.value.receipts,[phase]:serialized};if(Object.keys(receipts).length>2||Object.values(receipts).reduce((n,v)=>n+text(v).length,0)>8192)throw Error('Bootstrap control quota');
   await this.save(token,key,old,{...old.value,receipts});return {stored:true,duplicate:false,receiptsComplete:!!receipts.ACCEPT&&!!receipts.CONFIRM};});}
  list(token){return this.run(async()=>{const owner=this.check(token,{archiveAllowed:true}),values=[];for(const row of await this.inbox.store.all()){let value;try{value=await this.inbox.decrypt(row);}catch(_){this.check(token,{archiveAllowed:true});continue;}if(value.kind==='bootstrap-request'&&value.ownerSlot===owner.ownerSlot&&value.routeId===owner.routeId&&(value.expiresAt>this.clock()||value.state==='SELECTED'))values.push(value.expiresAt<=this.clock()?{...value,state:'EXPIRED_SELECTED'}:value);}this.check(token,{archiveAllowed:true});return values;});}
  close(){this.closed=true;this.inbox.close();}
 }
 g.DmashNodeBootstrapDispatcherV4=Dispatcher;if(typeof module!=='undefined')module.exports=Dispatcher;
})(globalThis);
