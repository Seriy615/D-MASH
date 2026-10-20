'use strict';
// Read-only observer for this test's published Root=07x32 synthetic fixture.
// Authenticates existing native rows; emits only opaque packet hashes/expiry.
// This is never a product storage adapter or an arbitrary profile recovery API.
const fs=require('node:fs'),path=require('node:path'),{webcrypto,createHash,hkdfSync}=require('node:crypto');
const repo=path.resolve(__dirname,'../../..');
global.nacl=require(path.join(repo,'D-MASH PWA/not_messenger/js/vendor/nacl-fast.min.js'));
const {DeviceRoot}=require(path.join(repo,'D-MASH PWA/not_messenger/js/device_root.js'));
(async()=>{
 const input=JSON.parse(fs.readFileSync(0,'utf8'));if(input.synthetic!==true)throw Error('Synthetic rows required');
 const storage=await DeviceRoot.derive(new Uint8Array(32).fill(7),'dmash/node-storage',4,'directional-relationships');
 const raw=Buffer.from(hkdfSync('sha256',storage,Buffer.from(input.nodeId),Buffer.from('D-MASH|NATIVE-JOB-LEDGER|V1|encryption'),32));storage.fill(0);
 const key=await webcrypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);raw.fill(0);
 const frame=fields=>Buffer.concat(fields.map(s=>{const b=Buffer.from(s),n=Buffer.alloc(4);n.writeUInt32BE(b.length);return Buffer.concat([n,b]);}));
 const result={};
 for(const row of input.rows){
  const bytes=new Uint8Array(await webcrypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(row.iv,'base64'),additionalData:frame(['D-MASH|NATIVE-JOB-LEDGER|V1',input.nodeId,'job',row.id])},key,Buffer.from(row.ciphertext,'base64')));
  try {const job=JSON.parse(new TextDecoder().decode(bytes)),body=Buffer.from(job.body,'base64'),hash=createHash('sha256').update(body).digest('hex');if(job.id!==row.id||createHash('sha256').update(frame([job.destination,body,String(job.expiresAt)])).digest('hex')!==job.digest)throw Error('Authenticated native job mismatch');result[row.id]={expiresAt:job.expiresAt,ciphertextSha256:hash};body.fill(0);}finally{bytes.fill(0);}
 }
 console.log(JSON.stringify(result));
})().catch(error=>{console.error(error.message);process.exitCode=1;});
