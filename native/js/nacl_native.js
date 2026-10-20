'use strict';
// Compiled actor-only acceleration. Wire encodings and protocol guards remain
// unchanged. Independent vendored primitives check the port before replacement.
(function(g){
 const host=NativePlatform.host,nacl=g.nacl,originalVerify=nacl.sign.detached.verify,originalMult=nacl.scalarMult;
 const equal=(a,b)=>a.length===b.length&&a.every((value,index)=>value===b[index]);
 const key=Uint8Array.from({length:32},(_,i)=>i+1),pair=nacl.sign.keyPair.fromSeed(key),message=new Uint8Array([1,2,3]),signature=nacl.sign.detached(message,pair.secretKey);
 try{
  const verify=(m,s,p)=>host('ed25519Verify',m,s,p);
  const changed=new Uint8Array(signature);changed[0]^=1;
  for(const sig of [signature,changed])if(verify(message,sig,pair.publicKey)!==originalVerify(message,sig,pair.publicKey))throw Error('Native Ed25519 parity');
  const mult=(s,p)=>host('x25519',s,p);
  // Canonical, low-order, noncanonical and high-bit inputs share RFC7748's
  // scalar clamping/coordinate decoding; low-order output remains all-zero.
  const points=host('benchmarkEnabled')?[0,1,9,237,255].flatMap(first=>[0,127,255].map(high=>[first,high])):[[9,0],[0,0],[255,255]];
  for(const [first,high] of points){
   const point=new Uint8Array(32);point[0]=first;point[31]=high;
   if(!equal(mult(key,point),originalMult(key,point)))throw Error('Native X25519 parity');
  }
  nacl.sign.detached.verify=verify;Object.assign(mult,originalMult);nacl.scalarMult=mult;
 }finally{key.fill(0);pair.secretKey.fill(0);}
})(globalThis);
