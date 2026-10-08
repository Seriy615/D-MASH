'use strict';
(function(global){
 const fail=code=>{throw Object.assign(Error(code),{code});};
 const hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
 const key=s=>{if(typeof s!=='string'||!/^[a-f0-9]{64}$/.test(s))fail('IDENTITY');return s;};
 const MAX_PEERS=128;
 // Trusted integration facade; no mutable Storage helpers, Node identity, selected
 // chat, legacy Core.encrypt or automatic legacy fallback enters this module.
 class AccountSessionRuntimeV4 {
  #peers=new Map();#closed=false;#timer=null;
  constructor({core,transport,profile=global.DmashAccountHandshakeV4,Session=global.DmashAccountSessionV4,Store=global.DmashAccountSessionStoreV4,nacl=global.nacl,kem=global.DmashKyberWasm,discovery=global.DmashRouteDiscoveryV4,crypto=global.crypto,clock=()=>Math.floor(Date.now()/1000),onStatus=()=>{}}){
   if(!core?.captureAccountSessionV4||!transport?.readRouteSnapshot||!transport?.prepareAndSubmitIntent||!profile||!Session||!Store||!nacl||!kem||!discovery||typeof onStatus!=='function')fail('DEPENDENCY');
   this.capture=core.captureAccountSessionV4();this.capture.assertCurrent();if(!this.capture.signal||!this.capture.keys?.sign||!this.capture.blindSalt||!this.capture.masterKey||!this.capture.db)fail('SESSION_REQUIRED');
   this.transport=transport;this.profile=profile;this.Session=Session;this.Store=Store;this.nacl=nacl;this.kem=kem;this.crypto=crypto;this.clock=clock;this.onStatus=onStatus;this.local=key(hex(this.capture.keys.sign.publicKey));
   this.codec=profile.createCodec({nacl,discovery,crypto,clock});this.abort=()=>this.close();this.capture.signal.addEventListener('abort',this.abort,{once:true});this.check();
  }
  check(){if(this.#closed||this.capture.signal.aborted)fail('SESSION_CHANGED');this.capture.assertCurrent();}
  async wait(promise){this.check();const result=await promise;this.check();return result;}
  async _snapshot(peer,allowExpired=false){key(peer);if(peer===this.local)fail('SELF');const s=await this.wait(this.transport.readRouteSnapshot(peer));if(s?.readiness==='ROUTE_EXPIRED'&&!allowExpired)fail('ROUTE_EXPIRED');if(s?.readiness==='COMMIT_EPOCH_UPGRADE_REQUIRED')fail('COMMIT_EPOCH_UPGRADE_REQUIRED');if(!s||s.peer!==peer||s.localAccountKeys?.signing!==this.local||s.remoteAccountKeys?.signing!==peer||!Number.isSafeInteger(s.generation)||s.generation<1)fail('AUTHENTICATED_ROUTE_REQUIRED');key(s.digest);key(s.localCertificate?.route_id);key(s.remoteCertificate?.route_id);return s;}
  async openPeer(peer,{requiredSuite,allowArchived=false}={}){
   this.check();key(peer);if(requiredSuite!==this.profile.SUITE)fail('SUITE_REQUIRED');const existing=this.#peers.get(peer);if(existing){if(existing.suite!==requiredSuite)fail('SUITE_REQUIRED');await this.wait(existing.ready);await this._currentRoute(existing,allowArchived);return existing.status;}
   if(this.#peers.size>=MAX_PEERS)fail('SESSION_QUOTA');const entry={peer,suite:requiredSuite,closed:false,store:null,session:null,snapshot:null,status:null,ready:null};this.#peers.set(peer,entry);
   entry.ready=(async()=>{const snapshot=await this._snapshot(peer,allowArchived);if(entry.closed)fail('SESSION_CHANGED');entry.snapshot=Object.freeze({peer,digest:snapshot.digest,generation:snapshot.generation,localRouteId:snapshot.localCertificate.route_id,remoteRouteId:snapshot.remoteCertificate.route_id});
    const context=Object.freeze({local:this.local,peer,bindingDigest:snapshot.digest,bindingGeneration:snapshot.generation,requiredSuite});
    const owner={context:()=>context,assertCurrent:()=>{this.check();if(entry.closed)fail('SESSION_CHANGED');},signingKey:()=>{this.check();if(entry.closed)fail('SESSION_CHANGED');return this.capture.keys.sign.secretKey;}};
    const salt=this.capture.blindSalt.slice();let blindKey;try{blindKey=await this.wait(this.crypto.subtle.importKey('raw',salt,{name:'HMAC',hash:'SHA-256'},false,['sign']));}finally{salt.fill(0);}
    entry.store=await this.Store.open({db:this.capture.db,dataKey:this.capture.masterKey,blindKey,owner,signal:this.capture.signal,crypto:this.crypto});this.check();if(entry.closed)fail('SESSION_CHANGED');
    entry.session=new this.Session({codec:this.codec,profile:this.profile,nacl:this.nacl,kem:this.kem,store:entry.store,owner,clock:this.clock});await this._currentRoute(entry,allowArchived);entry.status=await this.wait(entry.session.status());return entry.status;
   })();
   try{return await this.wait(entry.ready);}catch(error){entry.closed=true;entry.store?.close();if(this.#peers.get(peer)===entry)this.#peers.delete(peer);throw error;}
  }
  async _currentRoute(entry,allowExpired=false){this.check();if(entry.closed||!entry.snapshot)fail('SESSION_CHANGED');const snapshot=await this._snapshot(entry.peer,allowExpired),s=entry.snapshot;if(snapshot.digest!==s.digest||snapshot.generation!==s.generation||snapshot.localCertificate.route_id!==s.localRouteId||snapshot.remoteCertificate.route_id!==s.remoteRouteId){entry.closed=true;entry.store?.close();fail('BINDING_MIGRATION_REQUIRED');}return snapshot;}
  async _entry(peer,allowExpired=false){this.check();const e=this.#peers.get(key(peer));if(!e)fail('SESSION_NOT_OPEN');await this.wait(e.ready);await this._currentRoute(e,allowExpired);return e;}
  async _notify(e,allowExpired=false){const sessionStatus=await this.wait(e.session.status()),snapshot=await this._currentRoute(e,allowExpired),status=Object.freeze({...sessionStatus,routeReadiness:snapshot.readiness});e.status=status;try{this.onStatus(e.peer,status);}catch(_){/* A view callback must not roll back or suppress durable protocol work. */}return status;}
  async initiate(peer,options={}){const e=await this._entry(peer);const result=await this.wait(e.session.initiate(options));await this._notify(e);await this.flush(peer);return result;}
  async receive({peer,frame,localRouteId,bindingDigest,generation}){const e=await this._entry(peer,true);if(bindingDigest!==undefined&&(bindingDigest!==e.snapshot.digest||generation!==e.snapshot.generation))fail('DELIVERY_BINDING_MISMATCH');if(key(localRouteId)!==e.snapshot.localRouteId)fail('DELIVERY_ROUTE_MISMATCH');if(typeof frame!=='string'||new TextEncoder().encode(frame).length>12288)fail('FRAME_SIZE');const result=await this.wait(e.session.receive(frame));await this._notify(e,true);
   // The incoming frame is durably processed even if the outbound route is now
   // unavailable. Its response remains an intent and retry must not depend on UI.
   let queued=true;try{await this.flush(peer);}catch(error){this.check();queued=false;}
   return Object.freeze({persisted:true,phase:result.phase,outboundReady:queued});
  }
  async flush(peer){const e=await this._entry(peer);return this.wait(e.session.flush({submitIntent:async intent=>{await this._currentRoute(e);const result=await this.wait(this.transport.prepareAndSubmitIntent(intent));await this._currentRoute(e);if(result?.queued!==true)fail('LOCAL_NODE_REFUSED');return result;}}));}
  async status(peer){return this._notify(await this._entry(peer,true),true);}
  async resume(){this.check();const results=[];for(const peer of this.#peers.keys()){try{await this.flush(peer);results.push({peer,status:await this.status(peer)});}catch(error){this.check();results.push({peer,error:error.code||'SESSION_RETRY_FAILED'});}}return results;}
  startRetries(){this.check();if(this.#timer!==null)return;const tick=async()=>{this.#timer=null;if(this.#closed)return;try{await this.resume();}catch(_){/* Closed/invalidated owner is checked before any subsequent work. */}if(!this.#closed&&!this.capture.signal.aborted)this.#timer=setTimeout(tick,5000);};this.#timer=setTimeout(tick,5000);}
  close(){if(this.#closed)return;this.#closed=true;if(this.#timer!==null)clearTimeout(this.#timer);this.#timer=null;this.capture.signal.removeEventListener('abort',this.abort);for(const e of this.#peers.values()){e.closed=true;e.store?.close();}this.#peers.clear();}
 }
 global.DmashAccountSessionRuntimeV4=AccountSessionRuntimeV4;if(typeof module!=='undefined')module.exports=AccountSessionRuntimeV4;
})(typeof window!=='undefined'?window:globalThis);
