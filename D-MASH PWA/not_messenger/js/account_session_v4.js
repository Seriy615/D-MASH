'use strict';
(function(global){
 const fail=code=>{throw Object.assign(Error(code),{code});};
 const clone=o=>structuredClone(o);
 // Store contract: load() -> {revision,value}; commit(revision,value,guard)
 // atomically CAS-publishes the entire encrypted record and invokes guard inside
 // the transaction before writes AND completion. Never implement as sequential puts.
 class AccountSessionV4 {
  constructor({codec,profile,nacl,kem,store,owner,clock=()=>Math.floor(Date.now()/1000)}){
   if(!codec||!profile||!nacl||!kem?.generateKeys||!store?.commit||!owner?.assertCurrent)fail('DEPENDENCY');
   this.codec=codec;this.profile=profile;this.nacl=nacl;this.kem=kem;this.store=store;this.owner=owner;this.clock=clock;this.tail=Promise.resolve();
   const c=owner.context();if(c.requiredSuite!==profile.SUITE)fail('SUITE_REQUIRED');
  }
  _run(fn){const task=this.tail.catch(()=>{}).then(async()=>{this.owner.assertCurrent();const snapshot=await this.store.load();this.owner.assertCurrent();const s=clone(snapshot.value||{version:4,ledger:null,confirmed:null,pending:null,recovery:null,retired:[],intents:[],superseded:[]});this._validate(s);const before=JSON.stringify(s);this._expire(s);const result=await fn(s);this.owner.assertCurrent();if(JSON.stringify(s)!==before)await this.store.commit(snapshot.revision,s,()=>this.owner.assertCurrent());this.owner.assertCurrent();return result;});this.tail=task;return task;}
  _validate(s){if(!s||s.version!==4||!Array.isArray(s.retired)||s.retired.length>32||!Array.isArray(s.superseded)||s.superseded.length>32||!Array.isArray(s.intents)||s.intents.length>8)fail('CORRUPT_SESSION');if(s.ledger&&(!Number.isSafeInteger(s.ledger.generation)||s.ledger.generation<1||!/^[a-f0-9]{64}$/.test(s.ledger.session_id)))fail('CORRUPT_SESSION');if(s.pending&&(!['INIT_PREPARED','RESPONDER_PENDING','INITIATOR_CONFIRM_PENDING','EXPIRED','REFUSED'].includes(s.pending.phase)||typeof s.pending.init!=='string'||typeof s.pending.outbound!=='string'))fail('CORRUPT_SESSION');for(const i of s.intents)if(typeof i.raw!=='string'||!Number.isSafeInteger(i.attempts)||i.attempts<0||!Number.isSafeInteger(i.next_at)||!Number.isSafeInteger(i.expires_at))fail('CORRUPT_SESSION');}
  _expire(s){const p=s.pending;if(!p||p.phase==='EXPIRED')return;const now=this.clock(),active=s.intents.filter(i=>JSON.parse(i.raw).attempt_id===p.attempt),challenge=s.recovery?.challenge;if(JSON.parse(p.init).expires_at<=now||active.some(i=>i.attempts>=32&&i.next_at<=now)|| (challenge&&JSON.parse(challenge).expires_at<=now&&!s.recovery.consumed)){p.phase='EXPIRED';p.expired_at=now;p.retry_after=now+5;s.superseded.push(p.initDigest);s.superseded=s.superseded.slice(-32);delete p.keys;delete p.xSecret;delete p.kemSecret;this._retireIntents(s,p.attempt);}}
  _random(){return this.profile.hex(this.nacl.randomBytes(32));}
  _context(){const c=this.owner.context();if(c.requiredSuite!==this.profile.SUITE)fail('SUITE_REQUIRED');return c;}
  _frame(kind,attempt,generation,previous,body,expiry=86400){const c=this._context(),now=this.clock();return this.codec.sign({type:'ACCOUNT_HANDSHAKE',version:4,suite:c.requiredSuite,kind,binding_digest:c.bindingDigest,binding_generation:c.bindingGeneration,session_generation:generation,attempt_id:attempt,sender:c.local,recipient:c.peer,issued_at:now,expires_at:now+expiry,previous_session:previous,body},this.owner.signingKey());}
  _queue(s,raw){s.intents=s.intents.filter(i=>i.expires_at>this.clock());if(s.intents.some(x=>x.raw===raw))return;if(s.intents.length>=8)fail('INTENT_QUOTA');s.intents.push({raw,attempts:0,next_at:this.clock(),expires_at:JSON.parse(raw).expires_at});}
  _retireIntents(s,attempt){s.intents=s.intents.filter(x=>JSON.parse(x.raw).attempt_id!==attempt);}
  async _digest(raw){const d=await this.codec.frameDigest(raw);this.owner.assertCurrent();return d;}
  _keys(k){return Object.fromEntries(Object.entries(k).map(([name,value])=>[name,this.profile.hex(value)]));}
  _key(p,name){return this.profile.unhex(p.keys[name]);}
  _authority(s,f){const generation=s.ledger?s.ledger.generation+1:1,previous=s.ledger?.session_id??null;if(f.session_generation!==generation||f.previous_session!==previous)fail('PREDECESSOR_MISMATCH');}
  async initiate({recover=false,retry=false}={}){return this._run(async s=>{
   if(s.pending?.phase==='EXPIRED'){if(!retry||this.clock()<s.pending.retry_after)return {phase:'EXPIRED',retryAfter:s.pending.retry_after};s.pending=null;s.recovery=null;}
   if(s.pending?.phase==='REFUSED'){if(!retry||!['RECOVERY_REQUIRED','EXPIRED'].includes(s.pending.refusal)||this.clock()<s.pending.retry_after)return {phase:'REFUSED',reason:s.pending.refusal,retryAfter:s.pending.retry_after};s.superseded.push(s.pending.initDigest);s.superseded=s.superseded.slice(-32);s.pending=null;s.recovery=null;recover=true;}
   if(s.pending){this._queue(s,s.pending.outbound);return {phase:s.pending.phase};}
   if(s.confirmed&&!recover)return {phase:'ESTABLISHED'};
   if(s.ledger&&!recover)fail('RECOVERY_REQUIRED');
   const x=this.nacl.box.keyPair(),k=this.kem.generateKeys();if(!k.success||k.pk.length!==1184||k.sk.length!==2400)fail('KEM_FAILURE');
   const attempt=this._random(),generation=s.ledger?s.ledger.generation+1:1,previous=s.ledger?.session_id??null;
   const raw=this._frame('INIT',attempt,generation,previous,{suites:[this.profile.SUITE],ephemeral:this.profile.hex(x.publicKey),kem_public:this.profile.hex(k.pk),nonce:this._random(),authorization:null});
   const p={phase:'INIT_PREPARED',role:'initiator',attempt,generation,previous,init:raw,initDigest:await this._digest(raw),xSecret:this.profile.hex(x.secretKey),kemSecret:this.profile.hex(k.sk),outbound:raw};x.secretKey.fill(0);k.sk.fill(0);s.pending=p;this._queue(s,raw);
   if(recover){const request=this._frame('RECOVERY_REQUEST',attempt,generation,previous,{init_digest:p.initDigest,request_nonce:this._random()});s.recovery={role:'requester',request,initDigest:p.initDigest,proof:null};this._queue(s,request);}
   return {phase:recover?'RECOVERY_PENDING':p.phase};
  });}
  async receive(raw){return this._run(async s=>{
   const f=this.codec.verify(raw,this._context()),digest=await this._digest(raw);
   if(f.kind==='INIT'&&f.body.authorization!==null)return this._authorizedInit(s,f,raw,digest);
   if(f.kind==='INIT')return this._init(s,f,raw,digest,false);
   if(f.kind.startsWith('RECOVERY_'))return this._recovery(s,f,raw,digest);
   if(f.kind==='REFUSE'){const p=s.pending;if(!p||p.phase==='EXPIRED'||p.attempt!==f.attempt_id||p.generation!==f.session_generation||p.previous!==f.previous_session||!(await Promise.all(s.intents.filter(i=>JSON.parse(i.raw).attempt_id===p.attempt).map(i=>this._digest(i.raw)))).includes(f.body.reference_digest))fail('REFUSAL_CONTEXT');p.refusal=f.body.reason;p.phase='REFUSED';p.retry_after=this.clock()+5;this._retireIntents(s,p.attempt);return {phase:'REFUSED',reason:f.body.reason};}
   const p=s.pending;if(['EXPIRED','REFUSED'].includes(p?.phase))fail(p.phase);if(!p||p.attempt!==f.attempt_id||p.generation!==f.session_generation||p.previous!==f.previous_session) {
    if(s.confirmed?.attempt===f.attempt_id&&f.kind==='CONFIRM'&&s.confirmed.confirmDigest===digest){this._queue(s,s.confirmed.ack);return {phase:'ESTABLISHED'};}
    if(s.confirmed?.attempt===f.attempt_id&&f.kind==='CONFIRM_ACK'&&s.confirmed.ackDigest===digest)return {phase:'ESTABLISHED'};
    fail('ATTEMPT_MISMATCH');
   }
   if(f.kind==='FINAL'){
    if(p.role!=='initiator'||f.body.init_digest!==p.initDigest)fail('TRANSCRIPT');
    if(p.finalDigest){if(p.finalDigest!==digest)fail('CONFLICTING_FINAL');this._queue(s,p.outbound);return {phase:p.phase};}
    const core={init_digest:f.body.init_digest,ephemeral:f.body.ephemeral,capsule:f.body.capsule,nonce:f.body.nonce};const sid=await this.codec.sessionTranscript(p.init,core);this.owner.assertCurrent();if(f.body.session_id!==sid)fail('TRANSCRIPT');if(f.body.ephemeral===JSON.parse(p.init).body.ephemeral)fail('KEY_ROLE_REUSE');
    const x=this.nacl.scalarMult(this.profile.unhex(p.xSecret),this.profile.unhex(f.body.ephemeral)),k=this.kem.decapsulate(this.profile.unhex(f.body.capsule,1088),this.profile.unhex(p.kemSecret,2400));
    if(!k.success||k.ss.length!==32)fail('KEM_FAILURE');const keys=await this.codec.derive(x,k.ss,sid);x.fill(0);k.ss.fill(0);this.owner.assertCurrent();await this.codec.verifyMac(keys.final,'FINAL',f.body.mac,sid,p.initDigest);this.owner.assertCurrent();
    if(s.recovery?.role==='requester')s.recovery.consumed=true;p.keys=this._keys(keys);p.sessionId=sid;p.final=raw;p.finalDigest=digest;p.phase='INITIATOR_CONFIRM_PENDING';
    const tag=await this.codec.mac(keys.confirm,'CONFIRM',sid,p.initDigest,digest);this.owner.assertCurrent();const confirm=this._frame('CONFIRM',p.attempt,p.generation,p.previous,{init_digest:p.initDigest,final_digest:digest,session_id:sid,mac:tag});p.confirmDigest=await this._digest(confirm);p.outbound=confirm;delete p.xSecret;delete p.kemSecret;for(const key of Object.values(keys))key.fill(0);this._retireIntents(s,p.attempt);this._queue(s,confirm);return {phase:p.phase};
   }
   if(f.kind==='CONFIRM'){
    if(p.role!=='responder'||f.body.init_digest!==p.initDigest||f.body.final_digest!==p.finalDigest||f.body.session_id!==p.sessionId)fail('TRANSCRIPT');
    await this.codec.verifyMac(this._key(p,'confirm'),'CONFIRM',f.body.mac,p.sessionId,p.initDigest,p.finalDigest);this.owner.assertCurrent();
    const tag=await this.codec.mac(this._key(p,'ack'),'CONFIRM_ACK',p.sessionId,p.initDigest,p.finalDigest,digest);this.owner.assertCurrent();const ack=this._frame('CONFIRM_ACK',p.attempt,p.generation,p.previous,{init_digest:p.initDigest,final_digest:p.finalDigest,confirm_digest:digest,session_id:p.sessionId,mac:tag});
    this._establish(s,p,{confirmDigest:digest,ack,ackDigest:await this._digest(ack)});this._queue(s,ack);return {phase:'ESTABLISHED'};
   }
   if(f.kind==='CONFIRM_ACK'){
    if(p.role!=='initiator'||p.phase!=='INITIATOR_CONFIRM_PENDING'||f.body.init_digest!==p.initDigest||f.body.final_digest!==p.finalDigest||f.body.confirm_digest!==p.confirmDigest||f.body.session_id!==p.sessionId)fail('TRANSCRIPT');
    await this.codec.verifyMac(this._key(p,'ack'),'CONFIRM_ACK',f.body.mac,p.sessionId,p.initDigest,p.finalDigest,p.confirmDigest);this.owner.assertCurrent();this._establish(s,p,{ackDigest:digest});return {phase:'ESTABLISHED'};
   }
   fail('KIND');
  });}
  _establish(s,p,extra){if(s.ledger&&s.ledger.session_id!==p.sessionId){s.retired.push(s.ledger.session_id);s.retired=s.retired.slice(-32);}s.ledger={session_id:p.sessionId,generation:p.generation};s.confirmed={session_id:p.sessionId,generation:p.generation,root:p.keys.root,attempt:p.attempt,...extra};s.pending=null;s.recovery=null;s.intents=[];}
  async _init(s,f,raw,digest,authorized){
   const p=s.pending;if(!authorized&&['EXPIRED','REFUSED'].includes(p?.phase)&&p.initDigest===digest)fail(p.phase);
   if(p?.initDigest===digest&&p.role==='responder'){this._queue(s,p.outbound);return {phase:p.phase};}
   if((s.ledger||(p&&(p.role==='responder'||['EXPIRED','REFUSED'].includes(p.phase))&&p.initDigest!==digest))&&!authorized){
    if(s.recovery?.role==='authority'&&s.recovery.challenge&&(!s.recovery.consumed||s.pending)&&JSON.parse(s.recovery.challenge).expires_at>this.clock()&&s.recovery.initDigest!==digest)fail('RECOVERY_BUSY');
    s.recovery={...(s.recovery||{}),role:s.recovery?.role||'authority',remoteInit:raw,remoteInitDigest:digest,...(s.recovery?.role==='requester'?{}:{initDigest:digest})};return {phase:'RECOVERY_REQUIRED'};
   }
   this._authority(s,f);
   if(p&&p.initDigest!==digest){
    if(p.phase!=='INIT_PREPARED'&&!authorized)fail('PENDING_CONFLICT');const current=JSON.parse(p.init),localOrder=current.sender+current.attempt_id,remoteOrder=f.sender+f.attempt_id;
    if(!authorized&&localOrder<remoteOrder){this._queue(s,p.outbound);return {phase:p.phase};}
    s.superseded.push(p.initDigest);s.superseded=s.superseded.slice(-32);this._retireIntents(s,p.attempt);
   }
   if(s.superseded.includes(digest))fail('SUPERSEDED');
   const x=this.nacl.box.keyPair(),k=this.kem.encapsulate(this.profile.unhex(f.body.kem_public,1184));if(!k.success||k.ct.length!==1088||k.ss.length!==32)fail('KEM_FAILURE');
   const core={init_digest:digest,ephemeral:this.profile.hex(x.publicKey),capsule:this.profile.hex(k.ct),nonce:this._random()},sid=await this.codec.sessionTranscript(raw,core);this.owner.assertCurrent();
   const shared=this.nacl.scalarMult(x.secretKey,this.profile.unhex(f.body.ephemeral)),keys=await this.codec.derive(shared,k.ss,sid);shared.fill(0);x.secretKey.fill(0);k.ss.fill(0);this.owner.assertCurrent();
   const tag=await this.codec.mac(keys.final,'FINAL',sid,digest);this.owner.assertCurrent();const final=this._frame('FINAL',f.attempt_id,f.session_generation,f.previous_session,{...core,session_id:sid,mac:tag});
   s.pending={phase:'RESPONDER_PENDING',role:'responder',attempt:f.attempt_id,generation:f.session_generation,previous:f.previous_session,init:raw,initDigest:digest,sessionId:sid,keys:this._keys(keys),final,finalDigest:await this._digest(final),outbound:final};for(const key of Object.values(keys))key.fill(0);this._queue(s,final);return {phase:'RESPONDER_PENDING'};
  }
  async _authorizedInit(s,f,raw,digest){const r=s.recovery;if(r?.role!=='authority'||!r.challenge||r.challengeDigest!==f.body.authorization)fail('RECOVERY_CONTEXT');const challenge=JSON.parse(r.challenge),proposal=JSON.parse(r.remoteInit);if(challenge.expires_at<=this.clock()&&!r.consumed)fail('CHALLENGE_EXPIRED');if(f.attempt_id!==proposal.attempt_id||f.previous_session!==challenge.body.confirmed_session||f.session_generation!==challenge.body.next_generation)fail('RECOVERY_CONTEXT');for(const key of ['ephemeral','kem_public','nonce'])if(f.body[key]!==proposal.body[key])fail('RECOVERY_CONTRIBUTION');if(r.authorizedDigest&&r.authorizedDigest!==digest)fail('RECOVERY_CONFLICT');r.authorizedInit=raw;r.authorizedDigest=digest;return {phase:'RECOVERY_PROOF_REQUIRED'};}
  async _recovery(s,f,raw,digest){
   if(f.kind==='RECOVERY_REQUEST'){
    let r=s.recovery;if(r?.role==='requester'){const localGeneration=JSON.parse(r.request).session_generation;if(localGeneration<f.session_generation||(localGeneration===f.session_generation&&this._context().local<f.sender)){this._queue(s,r.request);return {phase:'RECOVERY_PENDING'};}if(!r.remoteInit||r.remoteInitDigest!==f.body.init_digest)fail('INIT_REQUIRED');this._retireIntents(s,s.pending.attempt);r={role:'authority',remoteInit:r.remoteInit,initDigest:r.remoteInitDigest};s.recovery=r;}if(r?.role==='authority'&&r.requestDigest===digest&&r.challenge){if(JSON.parse(r.challenge).expires_at<=this.clock())fail('CHALLENGE_EXPIRED');this._queue(s,r.challenge);return {phase:'RECOVERY_CHALLENGE'};}
    if(r?.challenge&&(!r.consumed||s.pending)&&JSON.parse(r.challenge).expires_at>this.clock())fail('RECOVERY_BUSY');if(r?.nextChallengeAt>this.clock())fail('RECOVERY_BACKOFF');
    if(!r?.remoteInit||r.initDigest!==f.body.init_digest)fail('INIT_REQUIRED');const proposal=JSON.parse(r.remoteInit);if(proposal.attempt_id!==f.attempt_id||proposal.session_generation!==f.session_generation||proposal.previous_session!==f.previous_session)fail('RECOVERY_CONTEXT');
    const challenge=this._frame('RECOVERY_CHALLENGE',f.attempt_id,(s.ledger?.generation??0)+1,s.ledger?.session_id??null,{request_digest:digest,init_digest:r.initDigest,request_nonce:f.body.request_nonce,challenge_nonce:this._random(),ticket:this._random(),confirmed_session:s.ledger?.session_id??null,confirmed_generation:s.ledger?.generation??0,next_generation:(s.ledger?.generation??0)+1},600);
    s.recovery={...r,requestDigest:digest,challenge,challengeDigest:await this._digest(challenge),consumed:false,lostRefusal:null,nextChallengeAt:0,authorizedInit:null,authorizedDigest:null,proofDigest:null};this._queue(s,challenge);return {phase:'RECOVERY_CHALLENGE'};
   }
   if(f.kind==='RECOVERY_CHALLENGE'){
    const r=s.recovery,p=s.pending;if(r?.role!=='requester'||!p||p.phase==='EXPIRED'||p.attempt!==f.attempt_id||f.body.request_digest!==await this._digest(r.request)||f.body.init_digest!==r.initDigest||f.body.request_nonce!==JSON.parse(r.request).body.request_nonce||f.body.confirmed_session!==f.previous_session||f.body.next_generation!==f.session_generation||f.body.next_generation<((s.ledger?.generation??0)+1))fail('RECOVERY_CONTEXT');
    if(r.proof){if(r.challengeDigest!==digest)fail('CHALLENGE_CONFLICT');this._queue(s,p.init);this._queue(s,r.proof);return {phase:'RECOVERY_PROOF'};}
    const proposal=JSON.parse(p.init),authorized=this._frame('INIT',p.attempt,f.body.next_generation,f.body.confirmed_session,{...proposal.body,authorization:digest});
    p.proposal=p.init;p.init=authorized;p.initDigest=await this._digest(authorized);p.generation=f.body.next_generation;p.previous=f.body.confirmed_session;p.outbound=authorized;
    const proof=this._frame('RECOVERY_PROOF',p.attempt,p.generation,p.previous,{request_digest:f.body.request_digest,challenge_digest:digest,init_digest:p.initDigest,ticket:f.body.ticket},Math.min(600,f.expires_at-this.clock()));r.proof=proof;r.challengeDigest=digest;r.challenge=raw;this._retireIntents(s,p.attempt);this._queue(s,authorized);this._queue(s,proof);return {phase:'RECOVERY_PROOF'};
   }
   if(f.kind==='RECOVERY_PROOF'){
    const r=s.recovery;if(r?.role!=='authority'||!r.challenge||r.requestDigest!==f.body.request_digest||r.challengeDigest!==f.body.challenge_digest||r.authorizedDigest!==f.body.init_digest||JSON.parse(r.challenge).body.ticket!==f.body.ticket)fail('RECOVERY_CONTEXT');
    if(r.consumed){if(r.proofDigest!==digest)fail('TICKET_USED');if(s.pending&&!['EXPIRED','REFUSED'].includes(s.pending.phase)){this._queue(s,s.pending.outbound);return {phase:s.pending.phase};}if(!r.lostRefusal){r.lostRefusal=this._frame('REFUSE',f.attempt_id,f.session_generation,f.previous_session,{reference_digest:digest,reason:'RECOVERY_REQUIRED',supported_version:4,supported_suites:[this.profile.SUITE]});r.nextChallengeAt=this.clock()+5;}this._queue(s,r.lostRefusal);return {phase:'RECOVERY_STATE_LOST'};}
    if(JSON.parse(r.challenge).expires_at<=this.clock())fail('CHALLENGE_EXPIRED');this._authority(s,f);
    const init=this.codec.verify(r.authorizedInit,this._context());if(init.attempt_id!==f.attempt_id)fail('RECOVERY_CONTEXT');r.consumed=true;r.proofDigest=digest;
    this._retireIntents(s,f.attempt_id);return this._init(s,init,r.authorizedInit,r.authorizedDigest,true);
   }
   fail('KIND');
  }
  // Reserve retry metadata durably before calling transport. Success is only
  // queue acceptance; no intent is removed until authenticated peer transition.
  async flush({submitIntent}={}){if(typeof submitIntent!=='function')fail('DURABLE_SUBMIT_REQUIRED');const frames=await this._run(async s=>{const now=this.clock(),out=[];for(const i of s.intents){if(i.next_at>now||i.expires_at<=now||i.attempts>=32)continue;i.attempts++;i.next_at=now+Math.min(300,5*2**Math.min(i.attempts-1,6));out.push(i.raw);}return out;});for(const raw of frames){this.owner.assertCurrent();const operationId=await this._digest(raw),c=this._context();await submitIntent(Object.freeze({operationId,frame:raw,peer:c.peer,bindingDigest:c.bindingDigest,generation:c.bindingGeneration}));this.owner.assertCurrent();}return frames.length;}
  async status(){return this._run(async s=>({phase:s.pending?.phase|| (s.confirmed?'ESTABLISHED':'NO_SESSION'),sessionId:s.confirmed?.session_id||null,generation:s.confirmed?.generation||null,retryAfter:s.pending?.retry_after??null,reason:s.pending?.refusal??null,confirmationAckPending:!!s.confirmed?.ack&&s.intents.some(i=>i.raw===s.confirmed.ack&&i.expires_at>this.clock()&&i.attempts<32)}));}
 }
 global.DmashAccountSessionV4=AccountSessionV4;if(typeof module!=='undefined')module.exports=AccountSessionV4;
})(typeof window!=='undefined'?window:globalThis);
