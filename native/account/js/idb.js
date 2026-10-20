'use strict';
// Narrow actual SQLite-backed IDB contract used by existing Account modules.
// Requests retain normal async success/complete/abort ordering; SQLite commits
// all stores in one transaction before oncomplete. No snapshot rewrite races.
(function(g){
 const host=NativePlatform.host,queued=[];let active=null;
 const soon=fn=>Promise.resolve().then(fn);
 const fail=c=>Object.assign(Error(c),{code:c});
 function pump(){if(active||!queued.length)return;const tx=active=queued.shift();
  try{host('idbBegin',tx.db.name,tx.names,tx.mode==='readwrite');tx.started=true;step(tx);}catch(e){abort(tx,e);}}
 function release(tx){tx.db.transactions.delete(tx);if(active===tx)active=null;else{const i=queued.indexOf(tx);if(i>=0)queued.splice(i,1);}soon(pump);}
 function abort(tx,e=fail('ACCOUNT_TX_ABORTED')){if(tx.done)return;tx.done=true;tx.error=e;if(tx.started)host('idbAbort');release(tx);soon(()=>tx.onabort?.({target:tx}));}
 function step(tx){soon(()=>{if(tx.done)return;if(!tx.operations.length){try{host('idbCommit');tx.done=true;release(tx);tx.oncomplete?.({target:tx});}catch(e){abort(tx,e);}return;}
  const {request,op,args}=tx.operations.shift();try{const result=host(op,...args);request.result=result===null?undefined:result;request.onsuccess?.({target:request});}catch(e){request.error=e;try{request.onerror?.({target:request});}finally{abort(tx,e);}return;}step(tx);});}
 class Transaction{
  constructor(db,names,mode){this.db=db;this.names=typeof names==='string'?[names]:Array.from(names);if(!this.names.length||this.names.some(n=>!db.objectStoreNames.contains(n)))throw fail('ACCOUNT_STORE_MISSING');if(!['readonly','readwrite'].includes(mode))throw fail('ACCOUNT_TRANSACTION_MODE');this.mode=mode;this.operations=[];this.done=false;this.started=false;db.transactions.add(this);queued.push(this);soon(pump);}
  objectStore(name){if(!this.names.includes(name)||this.done)throw fail('ACCOUNT_TRANSACTION_SCOPE');const tx=this;
   const request=(op,args)=>{if(tx.done)throw fail('ACCOUNT_TX_CLOSED');const r={result:undefined,error:null};tx.operations.push({request:r,op,args});return r;};
   return {get:key=>request('idbGet',[name,key]),getAll:()=>request('idbGetAll',[name]),
    put:row=>{if(tx.mode!=='readwrite')throw fail('ACCOUNT_READONLY');return request('idbPut',[name,row.alias??row.id,row]);},
    delete:key=>{if(tx.mode!=='readwrite')throw fail('ACCOUNT_READONLY');return request('idbDelete',[name,key]);}};
  }
  abort(){abort(this);}
 }
 g.NativeAccountDatabase=class{
  constructor(name){this.name=name;this.names=host('idbStores',name);this.objectStoreNames={contains:n=>this.names.includes(n)};this.transactions=new Set();}
  transaction(names,mode='readonly'){return new Transaction(this,names,mode);}
  close(){for(const tx of this.transactions)if(!tx.done)tx.abort();this.transactions.clear();}
 };
})(globalThis);
