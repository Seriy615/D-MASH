'use strict';
(function(global){
 const sessions=new WeakMap();
 const sessionToken=value=>{if(!sessions.has(value))sessions.set(value,{});return sessions.get(value);};
 class AccountNodeInboxV4{
  constructor(host,core){
   if(!host?.inboxList||!host?.acknowledgeInbox||!core?.receiveAccountNodeRecordV4)throw Error('Local Account delivery unavailable');
   this.host=host;this.core=core;this.task=null;this.cursor=null;this.session=null;this.closed=false;
  }
  drain(){
   if(this.task)return this.task;
   const core=this.core,keys=core.keys,salt=core.blindSalt,slot=core.activeIdentity;
   const current=()=>!this.closed&&!this.host.closed&&!core._accountTransitioning&&core.keys===keys&&
    core.blindSalt===salt&&core.activeIdentity===slot&&!!keys?.sign&&!!salt&&typeof slot==='string'&&!!slot;
   if(!current()){this.cursor=null;this.session=null;return Promise.resolve({processed:0,deferred:0,failed:0});}
   const keyToken=sessionToken(keys),saltToken=sessionToken(salt);
   if(this.session?.keyToken!==keyToken||this.session?.saltToken!==saltToken||this.session?.slot!==slot){this.cursor=null;this.session={keyToken,saltToken,slot};}
   const task=this.run(slot,current);this.task=task;
   return task.finally(()=>{if(this.task===task)this.task=null;});
  }
  async run(slot,current){
   const result={processed:0,deferred:0,failed:0};
   // Bound each sync pass. The cursor survives between passes so a full page
   // of rejected/incomplete packets cannot starve a later valid packet.
   for(let batch=0;batch<4&&current();batch++){
    const page=await this.host.inboxList(slot,32,this.cursor);
    if(!current())break;
    if(!page.records.length){this.cursor=null;break;}
    for(const record of page.records){
     if(!current())return result;
     this.cursor={receivedAt:record.receivedAt,handle:record.handle};
     try{
      const persisted=await this.core.receiveAccountNodeRecordV4(record,slot);
      if(!current())return result;
      if(persisted===true){
       if(await this.host.acknowledgeInbox(record.handle,slot))result.processed++;else result.deferred++;
      }else result.deferred++;
     }catch(error){if(!current())return result;result.failed++;}
    }
    if(page.records.length<32){this.cursor=null;break;}
   }
   return result;
  }
  close(){this.closed=true;this.cursor=null;this.session=null;}
 }
 global.DmashAccountNodeInboxV4=AccountNodeInboxV4;
 if(typeof module!=='undefined')module.exports=AccountNodeInboxV4;
})(typeof window!=='undefined'?window:globalThis);
