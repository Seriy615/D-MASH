'use strict';
const assert=require('node:assert/strict');
const Relationships=require('../js/node_relationships_v4.js');
class AtomicBackend {
 constructor(rows=new Map()){this.rows=rows;this.closed=false;}
 async read(key){assert(!this.closed);return structuredClone(this.rows.get(key)||null);}
 async cas(key,revision,row,{binding,maxRelationships,guard}){
  assert(!this.closed);guard();const old=this.rows.get(key);
  if((old?.revision??null)!==revision)return false;
  if(!old&&((binding&&this.rows.size!==0)||(!binding&&this.rows.size>=maxRelationships+1)))throw Error('binding/quota');
  this.rows.set(key,structuredClone({...row,key,revision:(revision??0)+1}));return true;
 }
 close(){this.closed=true;}
}
(async()=>{
 Object.defineProperty(global,'indexedDB',{configurable:true,get(){throw Error('Injected backend unexpectedly used IndexedDB');}});
 const key=crypto.getRandomValues(new Uint8Array(32)),local='a'.repeat(64),peer='b'.repeat(64),rows=new Map();
 let backend=new AtomicBackend(rows),store=await Relationships.open(key,local,{store:backend,maxRelationships:1});
 const first=await store.relationship(peer);assert.match(first.outbound,/^[0-9a-f]{32}$/);assert.equal(first.inbound,null);
 assert.equal(rows.size,2);assert.equal(JSON.stringify([...rows.values()]).includes(local),false);
 const incoming='c'.repeat(32);assert.deepEqual(await store.relationship(peer,{inbound:incoming}),{outbound:first.outbound,inbound:incoming});
 await assert.rejects(store.relationship('d'.repeat(64)),/binding\/quota/);assert.equal(rows.size,2);
 store.close();assert.equal(backend.closed,true);
 backend=new AtomicBackend(rows);store=await Relationships.open(key,local,{store:backend,maxRelationships:1});assert.deepEqual(await store.relationship(peer),{outbound:first.outbound,inbound:incoming});
 await assert.rejects(store.relationship(peer,{inbound:'e'.repeat(32)}),/changed/);store.close();
 const wrong=new AtomicBackend(rows);await assert.rejects(Relationships.open(crypto.getRandomValues(new Uint8Array(32)),local,{store:wrong}),/unreadable/);assert(wrong.closed);
 const identity=new AtomicBackend(rows);await assert.rejects(Relationships.open(key,'f'.repeat(64),{store:identity}),/identity changed/);assert(identity.closed);
 const orphan=new AtomicBackend(new Map([['a'.repeat(64),{key:'a'.repeat(64),revision:1}]]));await assert.rejects(Relationships.open(key,local,{store:orphan}),/binding\/quota/);assert(orphan.closed);
 const delayed=new AtomicBackend(rows);store=await Relationships.open(key,local,{store:delayed});let finish;delayed.read=()=>new Promise(resolve=>{finish=resolve;});const pending=store.read('binding');store.close();finish(rows.get('binding'));await assert.rejects(pending,/session changed/);
 const throwing=new AtomicBackend(rows);store=await Relationships.open(key,local,{store:throwing});throwing.close=()=>{throw Error("close failed");};assert.throws(()=>store.close(),/close failed/);assert.equal(store.aliasKey,null);assert.equal(store.encryptionKey,null);assert.equal(store.backend,null);
 delete global.indexedDB;
 console.log('PASS encrypted relationship backend: binding/quota, stable reopen, identity/key rejection and close fencing');
})().catch(error=>{console.error(error);process.exitCode=1;});
