const assert=require('node:assert/strict');
require('../js/call_signaling.js');
const T=globalThis.DmashCallSignaling.WebSocketSignaling;
(async()=>{
 let sockets=[];
 class Socket{constructor(){sockets.push(this);this.readyState=0;}close(){this.readyState=3;}send(v){(this.sent??=[]).push(JSON.parse(v));}}
 let controller=new AbortController();controller.abort();
 await assert.rejects(T.create('wss://example.test/signal',{signal:controller.signal,WebSocket:Socket}),/closed/);assert.equal(sockets.length,0);
 controller=new AbortController();let pending=T.create('wss://example.test/signal',{signal:controller.signal,WebSocket:Socket});controller.abort();await assert.rejects(pending,/closed/);assert.equal(sockets[0].readyState,3);
 controller=new AbortController();const transport=new T({endpoint:'wss://example.test/signal',signal:controller.signal,WebSocket:Socket});pending=transport.connect();transport.socket.onopen();await pending;pending=transport.next();controller.abort();await assert.rejects(pending,/closed/);assert.equal(transport.socket.readyState,3);
 // Abort from within the resolved hash: even a winning proof must not be sent.
 controller=new AbortController();const original=globalThis.crypto;let hashes=0;
 Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues:a=>a.fill(3),subtle:{digest:async()=>{if(++hashes===2)controller.abort();return new Uint8Array(32).buffer;}}}});
 class ChallengeSocket extends Socket{constructor(){super();queueMicrotask(()=>this.onopen());}send(v){super.send(v);if(JSON.parse(v).type==='CREATE')queueMicrotask(()=>this.onmessage({data:JSON.stringify({type:'CHALLENGE',nonce:'a'.repeat(64),difficulty:1})}));}}
 try{await assert.rejects(T.create('wss://example.test/signal',{signal:controller.signal,WebSocket:ChallengeSocket}),/closed/);assert.deepEqual(sockets.at(-1).sent.map(x=>x.type),['CREATE']);assert.equal(sockets.at(-1).readyState,3);}finally{Object.defineProperty(globalThis,'crypto',{configurable:true,value:original});}
 console.log('PASS signaling abort before connection, connecting, awaiting response, winning proof');
})().catch(e=>{console.error(e);process.exitCode=1;});
require('../js/recorded_note_turn.js');
{
 const controller=new AbortController(),task={key:'synthetic',controller,closed:false};
 const runtime=Object.create(globalThis.DmashRecordedNoteTurn.prototype);runtime.tasks=new Map([[task.key,task]]);
 runtime.close();assert.equal(controller.signal.aborted,true);assert.equal(runtime.tasks.size,0);
 console.log('PASS recorded note lifecycle close aborts admission controller synchronously');
}
