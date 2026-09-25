'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {execFileSync}=require('node:child_process');
const {chromium}=require(process.env.DMASH_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..');
(async()=>{
 const allowed=new Set(['/js/node_admission_v4.js','/js/vendor/argon2-bundled.min.js']);
 const server=http.createServer((request,response)=>{
  if(request.url==='/'){response.setHeader('Content-Type','text/html');response.end('<script src="/js/node_admission_v4.js"></script>');}
  else if(allowed.has(request.url)){response.setHeader('Content-Type','application/javascript');response.end(fs.readFileSync(path.join(root,'D-MASH PWA/not_messenger',request.url)));}
  else{response.statusCode=404;response.end();}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({executablePath:process.env.DMASH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const result=await page.evaluate(async()=>{
   const salt=Uint8Array.from({length:16},(_,i)=>i);
   const controller=new AbortController();
   const pending=DmashNodeAdmissionV4.derivePasswordKey('test-only password admission',salt,{signal:controller.signal});
   controller.abort();let cancelled=false;
   try{await pending;}catch(_){cancelled=true;}
   let ticks=0;const timer=setInterval(()=>ticks++,10);
   try{
    const work=DmashNodeAdmissionV4.derivePasswordKey('test-only password admission',salt);
    let bounded=false;
    try{await DmashNodeAdmissionV4.derivePasswordKey('another',salt);}catch(error){bounded=/busy/.test(error.message);}
    const key=await work;
    const output=Array.from(key);key.fill(0);
    const challenge={type:'NODE_PASSWORD_CHALLENGE',version:4,profile:DmashNodeAdmissionV4.PROFILE,
      salt:btoa(String.fromCharCode(...salt)),epoch:'ab'.repeat(16),nonce:'cd'.repeat(32),expires_at:190};
    const transcript=Array.from(DmashNodeAdmissionV4.challengeBytes(challenge,'11'.repeat(32),'22'.repeat(32),new Uint8Array(32).fill(3)));
    return {output,transcript,cancelled,bounded,ticks};
   }finally{clearInterval(timer);}
  });
  assert(result.cancelled);assert(result.bounded);assert(result.ticks>0);
  const expected=JSON.parse(execFileSync(path.join(root,'.venv/bin/python'),['-c',
   'import json; from backend.node_admission_v4 import derive_password_key,proof_bytes,PROFILE; import base64; c=dict(type="NODE_PASSWORD_CHALLENGE",version=4,profile=PROFILE,salt=base64.b64encode(bytes(range(16))).decode(),epoch="ab"*16,nonce="cd"*32,expires_at=190); print(json.dumps(dict(key=list(derive_password_key("test-only password admission",bytes(range(16)))),transcript=list(proof_bytes(c,"11"*32,"22"*32,bytes([3])*32)))))'],{cwd:path.join(root,'D-MASH/client'),encoding:'utf8'}));
  assert.deepEqual(result.output,expected.key);assert.deepEqual(result.transcript,expected.transcript);
  console.log('PASS real browser Argon2id Worker: native Python key/transcript parity, cancellation, single-worker limit, responsive UI');
 }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
