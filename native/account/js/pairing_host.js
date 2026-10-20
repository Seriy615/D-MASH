'use strict';
// Account-owned typed adapter for the existing signed private pairing protocol.
// Only scoped route material and Account public proofs cross to the Node.
(function(g){
 const hex=b=>Array.from(b,v=>v.toString(16).padStart(2,'0')).join('');
 const fail=code=>{throw Object.assign(Error(code),{code});};
 g.DmashNativePairingHost=Object.freeze({create({session,isCurrent,transport,preparations,tupleOf,verifyPreparation}){
  const owners=new WeakMap(),challenges=new Map(),rows=new Set();let verifier=null;
  const check=()=>{session.assertCurrent();if(!isCurrent())fail('ACCOUNT_SESSION_CHANGED');};
  const owner=cap=>{check();const row=owners.get(cap);if(!row||row.signal.aborted||!row.isAccountCurrent())fail('ACCOUNT_OWNER_CHANGED');return row;};
  const call=(cap,method,params)=>{const row=owner(cap),value=transport(row.route,method,params);owner(cap);return value;};
  const release=row=>{if(!rows.delete(row))return;try{transport(row.route,'owner.release',{});}catch(_){};};
  const api={localOwnership:'managed',identity:Object.freeze({bootstrapProfile:'private-v1'}),
   setCommitVerifier(value){if(value!==null)check();verifier=value;},
   async challengeLocalOwner(accountPublic,certificate){check();if(accountPublic!==hex(session.keys.sign.publicKey))fail('ACCOUNT_OWNER_CONTEXT');const route=certificate.route_id,value=transport(route,'owner.challenge',{accountPublic,certificate,archive:false}),proof=JSON.parse(value.transcript);check();if(proof.domain!=='D-MASH|LOCAL-OWNER|V4'||proof.accountPublic!==accountPublic||proof.routeId!==route||proof.challenge!==value.challenge)fail('ACCOUNT_OWNER_CHALLENGE');challenges.set(value.challenge,{route,certificate,accountPublic});return value;},
   async registerLocalOwner(challenge,signature,{accountPublic,isAccountCurrent,signal}){check();const prior=challenges.get(challenge);challenges.delete(challenge);if(!prior||prior.accountPublic!==accountPublic||typeof isAccountCurrent!=='function'||!isAccountCurrent()||!signal||signal.aborted||!(signature instanceof Uint8Array)||signature.length!==64)fail('ACCOUNT_OWNER_CONTEXT');const result=transport(prior.route,'owner.register',{challenge,signature:hex(signature)});check();if(result.accountPublic!==accountPublic)fail('ACCOUNT_OWNER_CONTEXT');const cap=Object.freeze({}),row={...prior,isAccountCurrent,signal};owners.set(cap,row);rows.add(row);signal.addEventListener('abort',()=>release(row),{once:true});return cap;},
   async provisionBootstrap(cap,data){const material=[data.discoverySeed,data.discoveryBox,...data.recipientKeys];try{return call(cap,'bootstrap.provision',{localBundle:data.localBundle,discoverySeed:hex(data.discoverySeed),discoveryBox:hex(data.discoveryBox),recipientKeys:data.recipientKeys.map(hex)});}finally{for(const bytes of material)bytes.fill(0);}},
   async bootstrapList(cap){return call(cap,'bootstrap.list',{}).requests;},
   async selectBootstrap(cap,exchangeId,requestDigest,{deny=false}={}){return call(cap,'bootstrap.select',{exchangeId,requestDigest,deny});},
   async bootstrapSubmit(cap,handle,control){return call(cap,'bootstrap.submit',{handle,control});},
   async ownerDiscover(cap,certificate){return call(cap,'owner.discover',{certificate});},
   async ownerReleaseGrant(cap,handle){return call(cap,'owner.releaseGrant',{handle});},
   async prepareLocalBinding(cap,data){const row=owner(cap),material=[data.discoverySeed,data.discoveryBox,...data.recipientKeys];try{const value=call(cap,'owner.prepare',{...data,discoverySeed:hex(data.discoverySeed),discoveryBox:hex(data.discoveryBox),recipientKeys:data.recipientKeys.map(hex)}),handle=Object.freeze({});preparations.set(handle,{route:row.route,tuple:tupleOf(value),cap});return handle;}finally{for(const bytes of material)bytes.fill(0);}},
   async queryLocalBinding(cap,migrationId){const row=owner(cap),value=call(cap,'owner.query',{migrationId});if(!value?.state)return null;const handle=Object.freeze({});preparations.set(handle,{route:row.route,tuple:tupleOf(value),cap});return {handle,...value};},
   verifyPreparation,
   async activateLocalBinding(cap,handle,receipt){owner(cap);const row=preparations.get(handle);if(!row||row.cap!==cap||!verifier)fail('ACCOUNT_COMMIT_RECEIPT_REQUIRED');const tuple=await verifyPreparation(handle);if(!await verifier(receipt,tupleOf(tuple)))fail('ACCOUNT_COMMIT_RECEIPT_REQUIRED');owner(cap);return call(cap,'owner.activate',{tuple:tupleOf(tuple)});},
   close(){for(const row of [...rows])release(row);challenges.clear();verifier=null;}
  };return Object.freeze(api);
 }});
})(globalThis);
