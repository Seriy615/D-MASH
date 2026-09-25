'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),{spawn}=require('node:child_process');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..');
const scripts=['vendor/nacl-fast.min.js','vendor/blake3.min.js','secure_session.js','node_identity.js','node_relationships_v4.js','node_admission_v4.js','node_registration_v4.js','resource_pow.js','node_socket_v4.js','node_channel_v4.js'];
const allowed=new Set([...scripts,'vendor/argon2-bundled.min.js'].map(name=>'/js/'+name));
(async()=>{
 const helper=spawn(path.join(root,'.venv/bin/python'),[path.join(__dirname,'node_v4_browser_server.py')],{stdio:['pipe','pipe','pipe']});
 let helperError='';helper.stderr.on('data',data=>helperError+=data);
 const helperExit=new Promise(resolve=>helper.once('exit',resolve));
 const server=http.createServer((request,response)=>{
  if(request.url==='/'){response.setHeader('Content-Type','text/html');response.end(scripts.map(name=>'<script src="/js/'+name+'"></script>').join(''));}
  else if(allowed.has(request.url)){response.setHeader('Content-Type','application/javascript');response.end(fs.readFileSync(path.join(root,'D-MASH PWA/not_messenger',request.url)));}
  else{response.statusCode=404;response.end();}
 });
 let browser;
 try{
  const info=await new Promise((resolve,reject)=>{
   let input='';const timer=setTimeout(()=>reject(Error('Node fixture startup deadline')),180000);
   helper.once('exit',()=>{clearTimeout(timer);reject(Error('Node fixture exited'));});
   helper.stdout.on('data',data=>{input+=data;if(input.includes('\n')){clearTimeout(timer);resolve(JSON.parse(input.split('\n')[0]));}});
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const result=await page.evaluate(async info=>{
   if(window.Core)throw Error('Unexpected Account runtime');
   const seed=await DmashNodeIdentity.mine({timeoutMs:180000});
   const signing=nacl.sign.keyPair.fromSeed(seed);seed.fill(0);
   const localId=Array.from(signing.publicKey,b=>b.toString(16).padStart(2,'0')).join('');
   const storageKey=crypto.getRandomValues(new Uint8Array(32));
   const credential=await DmashNodeAdmissionV4.passwordCredential('browser-loopback-password');
   const passwordGate=new DmashNodeAdmissionV4.PasswordGate(credential);
   let original=null,checks=0;
   try{
    for(let round=0;round<2;round++){
     const store=await DmashNodeRelationshipsV4.open(storageKey,localId);
     let channel,secure;
     try{
      secure=await DmashNodeSocketV4.connect(`ws://127.0.0.1:${info.port}/mesh/v4`,signing,info.nodeId);
      channel=await DmashNodeChannelV4.authorize(secure,store,{difficulty:20,requirePeerPassword:true,passwordGate,
       peerPasswordKey:async(_,challenge)=>DmashNodeAdmissionV4.derivePasswordKey('loopback-test-password',Uint8Array.from(atob(challenge.salt),c=>c.charCodeAt(0)))});
      if(original&&JSON.stringify(channel.relationship)!==JSON.stringify(original))throw Error('DNSS changed on reconnect');
      original={...channel.relationship};
      const ready=await channel.receiveOperation();if(ready.type!=='TEST_READY')throw Error('Not authorized');
      const nonce=nacl.randomBytes(24),key=nacl.randomBytes(32),message=new TextEncoder().encode('Opaque browser payload');
      const box=nacl.secretbox(message,nonce,key),ciphertext=DmashSecureSession.b64(box);
      await channel.sendOperation({type:'TEST_ECHO',ciphertext});
      const response=await channel.receiveOperation();
      if(response.ciphertext!==ciphertext||new TextDecoder().decode(nacl.secretbox.open(DmashSecureSession.unb64(response.ciphertext),nonce,key))!=='Opaque browser payload')throw Error('Payload mismatch');
      key.fill(0);
      const raceGate=new DmashNodeAdmissionV4.PasswordGate(credential);
      try{
       const challenge=raceGate.challenge(secure.session);
       const reverse={...secure.session,localId:secure.session.peerId,peerId:secure.session.localId};
       const proof=await DmashNodeAdmissionV4.passwordProof(credential.key,challenge,reverse);
       const verifying=raceGate.verify(secure.session,proof);
       raceGate.revokeAll();
       if(await verifying)throw Error('In-flight password verification revived revoked admission');
       let denied=false;try{raceGate.require(secure.session);}catch(_){denied=true;}
       if(!denied)throw Error('Revoked gate remained authorized');
      }finally{raceGate.close();}
      passwordGate.revokeAll();let revoked=false;
      try{await channel.sendOperation({type:'TEST_ECHO',ciphertext});}catch(_){revoked=true;}
      if(!revoked)throw Error('Browser password revocation bypass');
      checks++;
     }finally{channel?.close();secure?.close();store.close();}
    }
    const store=await DmashNodeRelationshipsV4.open(storageKey,localId);
    let secure,channel,rejected=false;
    try{
     secure=await DmashNodeSocketV4.connect(`ws://127.0.0.1:${info.port}/mesh/v4`,signing,info.nodeId);
     channel=await DmashNodeChannelV4.authorize(secure,store,{difficulty:20,requirePeerPassword:true,passwordGate,
      peerPasswordKey:async(_,challenge)=>DmashNodeAdmissionV4.derivePasswordKey('loopback-test-password',Uint8Array.from(atob(challenge.salt),c=>c.charCodeAt(0)))});
    }catch(error){if(error.message!=='Node admission rejected')throw error;rejected=true;}
    finally{channel?.close();secure?.close();store.close();}
    return {checks,rejected,independent:original.inbound!==original.outbound};
   }finally{storageKey.fill(0);signing.secretKey.fill(0);credential.key.fill(0);passwordGate.close();}
  },info);
  assert.equal(result.checks,2);assert(result.independent);assert(result.rejected);
  console.log('PASS real browser/Python v4 WebSocket: Node identity PoW, mutual password Worker/HMAC, wrong-password refusal, revocation including in-flight verification, directional resource PoW, durable reconnect, opaque payload exchange, no Account runtime');
 }finally{
  if(browser)await browser.close();
  if(server.listening)await new Promise(resolve=>server.close(resolve));
  helper.stdin.end('stop\n');
  const timer=setTimeout(()=>helper.kill('SIGKILL'),5000);await helperExit;clearTimeout(timer);
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
