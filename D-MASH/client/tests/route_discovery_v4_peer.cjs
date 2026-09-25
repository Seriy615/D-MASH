'use strict';
const path=require('node:path'),fs=require('node:fs');
const js=path.resolve(__dirname,'../../../D-MASH PWA/not_messenger/js');
global.nacl=require(path.join(js,'vendor/nacl-fast.min.js'));
const api=require(path.join(js,'route_discovery_v4.js'));
const bytes=hex=>new Uint8Array(Buffer.from(hex,'hex'));
(async()=>{
 const input=JSON.parse(fs.readFileSync(0,'utf8')),options={now:input.now};
 if(input.mode==='answer'){
  const sign=nacl.sign.keyPair.fromSeed(bytes(input.sign)),box=nacl.box.keyPair.fromSecretKey(bytes(input.box));
  const reply=await api.answerQuery(input.query,input.certificate,sign,box,options);
  process.stdout.write(JSON.stringify({reply}));
 }else if(input.mode==='query'){
  const {blob,state}=api.createQuery(input.certificate,options);
  process.stdout.write(JSON.stringify({blob,state:{query:state.query,certificate:state.certificate,reply_private:Buffer.from(state.replyPrivate).toString('hex')}}));
 }else if(input.mode==='verify'){
  const state={query:input.state.query,certificate:input.state.certificate,replyPrivate:bytes(input.state.reply_private)};
  process.stdout.write(JSON.stringify({accepted:await api.verifyReply(input.reply,state,options)}));
 }else throw Error('Unknown test mode');
})().catch(()=>{process.stderr.write('Discovery interop failed');process.exitCode=1;});
