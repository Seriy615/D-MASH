'use strict';
// One outgoing browser socket is a bidirectional NODE peer, never a DEVICE.
(function(global){
 const MAX_FRAME=2*1024*1024,MAX_QUEUE=4*1024*1024;
 class NodeSocketV4 {
  static async connect(url,signing,expectedNodeId,{signal}={}){
   const endpoint=new URL(url);
   if(endpoint.username||endpoint.password||endpoint.hash)throw Error('Invalid Node socket URL');
   if(endpoint.protocol!=='wss:'&&!(endpoint.protocol==='ws:'&&['127.0.0.1','localhost','[::1]'].includes(endpoint.hostname)))throw Error('Node peering requires WSS');
   if(!global.DmashNodeIdentity.verify(expectedNodeId))throw Error('Node identity work required');
   const localId=Array.from(signing.publicKey,b=>b.toString(16).padStart(2,'0')).join('');
   if(!global.DmashNodeIdentity.verify(localId)||localId===expectedNodeId)throw Error('Independent Node identity required');
   if(signal?.aborted)throw Error('Node connection cancelled');
   const connection=new NodeSocketV4();
   connection.queue=[];connection.queueBytes=0;connection.closed=false;connection.reader=null;
   connection.abortController=new AbortController();connection.signal=connection.abortController.signal;
   const handshake=new global.DmashSecureSession.Initiator(signing,'NODE',4);
   try{connection.socket=new WebSocket(url);}catch(error){handshake.close();throw error;}
   const cancel=()=>connection.close();
   signal?.addEventListener('abort',cancel,{once:true});
   connection.cleanup=()=>signal?.removeEventListener('abort',cancel);
   connection.socket.onmessage=event=>connection.incoming(event.data);
   connection.socket.onclose=()=>connection.close();
   connection.socket.onerror=()=>connection.close();
   const deadline=setTimeout(()=>connection.close(),15000);
   try{
    await new Promise((resolve,reject)=>{
     connection.openReject=reject;
     connection.socket.onopen=()=>{connection.openReject=null;resolve();};
     if(connection.closed)reject(Error('Node connection closed'));
    });
    connection.sendRaw(handshake.initiate());
    const response=await connection.readRaw();
    const {auth,session}=await handshake.finish(response,expectedNodeId);
    try{connection.check();}catch(error){session.close();throw error;}
    connection.session=session;
    connection.sendRaw(auth);
    return connection;
   }catch(error){connection.close();throw error;}
   finally{clearTimeout(deadline);handshake.close();}
  }
  check(){if(this.closed||this.socket.readyState!==WebSocket.OPEN)throw Error('Node socket closed');}
  incoming(raw){
   if(this.closed)return;
   // Protocol output is canonical ASCII JSON, so character length bounds bytes.
   if(typeof raw!=='string'||raw.length>(this.session?MAX_FRAME:4096)||/[^\x00-\x7f]/.test(raw)){this.close();return;}
   if(this.reader){const reader=this.reader;this.reader=null;reader.resolve(raw);return;}
   if(this.queue.length>=64||this.queueBytes+raw.length>MAX_QUEUE){this.close();return;}
   this.queue.push(raw);this.queueBytes+=raw.length;
  }
  sendRaw(value){
   this.check();
   const raw=JSON.stringify(value);
   if(raw.length>MAX_FRAME||this.socket.bufferedAmount+raw.length>MAX_QUEUE)throw Error('Node send backpressure');
   this.socket.send(raw);
  }
  async readRaw(){
   this.check();
   if(this.reader)throw Error('Concurrent Node socket reader');
   let raw;
   if(this.queue.length){raw=this.queue.shift();this.queueBytes-=raw.length;}
   else raw=await new Promise((resolve,reject)=>{this.reader={resolve,reject};});
   try{return JSON.parse(raw);}catch(error){this.close();throw error;}
  }
  async sendJson(value){
   try{this.sendRaw(this.session.seal(value));}
   catch(error){this.close();throw error;}
  }
  async receiveJson(){
   try{return this.session.open(await this.readRaw());}
   catch(error){this.close();throw error;}
  }
  close(){
   if(this.closed)return;
   this.closed=true;this.abortController?.abort();this.cleanup?.();this.session?.close();
   this.openReject?.(Error('Node socket closed'));this.openReject=null;
   this.reader?.reject(Error('Node socket closed'));this.reader=null;
   this.queue=[];this.queueBytes=0;
   try{this.socket?.close(1000,'Node session ended');}catch(_){}
  }
 }
 global.DmashNodeSocketV4=NodeSocketV4;
 if(typeof module!=='undefined')module.exports=NodeSocketV4;
})(typeof window!=='undefined'?window:globalThis);
