'use strict';
// Only this compiled adapter sees the native primitive dispatcher. There is no
// IPC operation for evaluating code, reading files, SQL, or importing modules.
(function(g){
 const host=g.__dmashHost;delete g.__dmashHost;
 const fail=(name,message)=>{const e=new Error(message);e.name=name;return e;};
 const buffer=value=>{
  if(value instanceof ArrayBuffer)return new Uint8Array(value);
  if(ArrayBuffer.isView(value))return new Uint8Array(value.buffer,value.byteOffset,value.byteLength);
  throw TypeError('BufferSource required');
 };
 const copy=value=>new Uint8Array(buffer(value));
 // Installed only in a trusted compute engine. No endpoint/IPC can install a factory.
 if(host('isWorker'))Object.defineProperty(g,'DmashNativeNonceHasher',{value:prefix=>{
  try{
  const input=buffer(prefix),state=host('nonceCreate',input);
  const hash=nonce=>{
   if(typeof nonce==='number'){if(!Number.isSafeInteger(nonce)||nonce<0)throw RangeError('nonce');nonce=BigInt(nonce);}
   if(typeof nonce!=='bigint'||nonce<0n||nonce>0xffffffffffffffffn)throw RangeError('nonce');
   return host('nonceHash',state,Number(nonce>>32n),Number(nonce&0xffffffffn));
  };
  // Fail closed on a host ABI/endianness regression before doing any work.
  // Existing protocol JS provides the independent SHA implementation.
  for(const nonce of [0n,9007199254740991n,0x8000000000000000n,0xffffffffffffffffn]){
   const transcript=new Uint8Array(input.length+8);transcript.set(input);
   for(let i=0;i<8;i++)transcript[input.length+7-i]=Number((nonce>>BigInt(i*8))&255n);
   const expected=g.DmashResourcePow.sha256(transcript),actual=hash(nonce);
   if(actual.length!==32||actual.some((v,i)=>v!==expected[i]))throw Error('Native nonce parity');
  }
  hash.search=(start,count,difficulty)=>{
   if(!Number.isSafeInteger(start)||start<0||!Number.isInteger(count)||count<1||count>4096||start>Number.MAX_SAFE_INTEGER-count+1||!Number.isInteger(difficulty)||difficulty<0||difficulty>256)throw RangeError('nonce search');
   return host('nonceSearch',state,start,count,difficulty);
  };
  if(host('benchmarkEnabled')){
   let began=performance.now();for(let nonce=0;nonce<4096;nonce++)hash(nonce);const crossingMs=performance.now()-began;
   began=performance.now();try{hash.search(0,4096,256);}catch(error){host('workerBenchmarkError','search',error.name,error.message);throw error;}const batchMs=performance.now()-began;
   host('workerBenchmark',crossingMs,batchMs);
  }
  return hash;
  }catch(error){if(host('benchmarkEnabled'))host('workerBenchmarkError','factory',error.name,error.message);throw error;}
 },writable:false,configurable:false});
 const name=alg=>{const value=typeof alg==='string'?alg:alg?.name;return typeof value==='string'?value.toUpperCase():value;};
 class TextEncoder{encode(value=''){return new Uint8Array(host('utf8Encode',String(value)));}}
 class TextDecoder{
  constructor(label='utf-8',options={}){if(!['utf-8','utf8','unicode-1-1-utf-8'].includes(String(label).toLowerCase().trim()))throw RangeError('Unsupported encoding');this.fatal=!!options.fatal;this.ignoreBOM=!!options.ignoreBOM;}
  decode(value=new Uint8Array(),options={}){if(options.stream)throw fail('NotSupportedError','Streaming decoder unavailable');return host('utf8Decode',buffer(value),this.fatal,this.ignoreBOM);}
 }
 class EventTarget{
  constructor(){this._listeners=new Map();}
  addEventListener(type,fn,options={}){if(typeof fn!=='function')return;const rows=this._listeners.get(type)||[];if(!rows.some(x=>x.fn===fn))rows.push({fn,once:!!options?.once});this._listeners.set(type,rows);}
  removeEventListener(type,fn){const rows=this._listeners.get(type)||[];this._listeners.set(type,rows.filter(x=>x.fn!==fn));}
  dispatchEvent(event){event.target=this;for(const row of [...(this._listeners.get(event.type)||[])]){if(row.once)this.removeEventListener(event.type,row.fn);row.fn.call(this,event);}this['on'+event.type]?.call(this,event);return true;}
 }
 class AbortSignal extends EventTarget{constructor(){super();this.aborted=false;this.reason=undefined;}}
 class AbortController{constructor(){this.signal=new AbortSignal();}abort(reason=fail('AbortError','Operation aborted')){if(this.signal.aborted)return;this.signal.aborted=true;this.signal.reason=reason;this.signal.dispatchEvent({type:'abort'});}}
 class URL{constructor(value,base){const row=host('url',String(value),base===undefined?'':String(base));Object.assign(this,row);}toString(){return this.href;}}
 g.TextEncoder=TextEncoder;g.TextDecoder=TextDecoder;g.EventTarget=EventTarget;g.AbortController=AbortController;g.AbortSignal=AbortSignal;g.URL=URL;g.self=g;
 g.btoa=value=>{const s=String(value),out=new Uint8Array(s.length);for(let i=0;i<s.length;i++){const n=s.charCodeAt(i);if(n>255)throw fail('InvalidCharacterError','Latin1 required');out[i]=n;}return host('base64Encode',out);};
 g.atob=value=>host('base64Decode',String(value));
 g.performance=Object.freeze({now:()=>host('monotonic')});
 const timers=new Map();let timerId=0;
 g.setTimeout=(fn,delay=0,...args)=>{if(typeof fn!=='function')throw TypeError('Timer callback required');const id=++timerId;timers.set(id,()=>fn(...args));try{host('timerStart',id,Math.floor(Math.max(0,Math.min(2147483647,Number(delay)||0))));}catch(e){timers.delete(id);throw e;}return id;};
 g.clearTimeout=id=>{timers.delete(id);host('timerStop',Number(id)||0);};
 const intervals=new Map();
 g.setInterval=(fn,delay=0,...args)=>{if(typeof fn!=='function')throw TypeError('Interval callback required');const id=g.setTimeout(fn,delay,...args);intervals.set(id,{fn,args,delay:Math.floor(Math.max(0,Math.min(2147483647,Number(delay)||0)))});return id;};
 const clearTimer=g.clearTimeout;
 g.clearTimeout=g.clearInterval=id=>{intervals.delete(id);clearTimer(id);};
 const sockets=new Map(),workers=new Map();
 class WebSocket extends EventTarget{
  static CONNECTING=0;static OPEN=1;static CLOSING=2;static CLOSED=3;
  constructor(url){super();this.url=new URL(url).href;this.readyState=0;this._id=host('socketNew',this.url);sockets.set(this._id,this);}
  get bufferedAmount(){return this.readyState===3?0:host('socketBuffered',this._id);}
  send(data){if(this.readyState!==1)throw fail('InvalidStateError','Socket not open');if(typeof data!=='string')throw TypeError('Only protocol text frames supported');host('socketSend',this._id,data);}
  close(code=1000,reason=''){if(this.readyState===3)return;this.readyState=2;host('socketClose',this._id,code,String(reason));}
 }
 g.WebSocket=WebSocket;
 const encodeClone=value=>JSON.stringify(value,(_,v)=>v instanceof Uint8Array?{__dmashBytes:Array.from(v)}:v);
 const decodeClone=value=>JSON.parse(value,(_,v)=>v&&Object.keys(v).length===1&&Array.isArray(v.__dmashBytes)?Uint8Array.from(v.__dmashBytes):v);
 class Worker extends EventTarget{
  constructor(url){super();this._id=host('workerNew',String(url));workers.set(this._id,this);}
  postMessage(data){host('workerPost',this._id,encodeClone(data));}
  terminate(){workers.delete(this._id);host('workerStop',this._id);}
 }
 g.Worker=Worker;
 const keyData=new WeakMap();
 // Opaque native handles own material; normal JS objects only expose metadata.
 async function importKey(format,value,algorithm,extractable,usages){
  if(format!=='raw')throw fail('NotSupportedError','Raw transport key required');
  const alg=name(algorithm);if(!['HMAC','HKDF','AES-GCM'].includes(alg))throw fail('NotSupportedError','Transport algorithm unavailable');
  if(!Array.isArray(usages)||!usages.length)throw fail('SyntaxError','Key usages required');
  const allowed=alg==='HMAC'?['sign','verify']:alg==='HKDF'?['deriveBits']:['encrypt','decrypt'];
  if(usages.some(x=>!allowed.includes(x)))throw fail('SyntaxError','Invalid key usage');
  if(alg==='HMAC'&&name(algorithm.hash)!=='SHA-256')throw fail('NotSupportedError','HMAC SHA256 required');
  if(alg==='HKDF'&&extractable)throw fail('SyntaxError','HKDF key must be nonextractable');
  const bytes=buffer(value);if(alg==='HMAC'&&!bytes.length)throw fail('DataError','Empty HMAC key');
  if(typeof algorithm==='object'&&algorithm?.length!==undefined&&algorithm.length!==bytes.length*8)throw fail('NotSupportedError','Partial-bit key unavailable');
  const handle=host('keyImport',bytes,alg,usages.join(','),!!extractable);
  const metadata=alg==='HMAC'?{name:alg,hash:Object.freeze({name:'SHA-256'}),length:bytes.length*8}:alg==='AES-GCM'?{name:alg,length:bytes.length*8}:{name:alg};
  const key=Object.freeze({type:'secret',algorithm:Object.freeze(metadata),extractable:!!extractable,usages:Object.freeze([...new Set(usages)])});keyData.set(key,handle);return key;
 }
 const access=(key,alg,usage)=>{const h=keyData.get(key);if(!h||key.algorithm.name!==alg||!key.usages.includes(usage))throw fail('InvalidAccessError','Transport key usage rejected');return h;};
 const subtle={importKey,
  async digest(algorithm,data){if(name(algorithm)!=='SHA-256')throw fail('NotSupportedError','SHA256 required');return host('sha256',buffer(data));},
  async sign(algorithm,key,data){if(name(algorithm)!=='HMAC')throw fail('NotSupportedError','HMAC required');return host('hmac',access(key,'HMAC','sign'),buffer(data));},
  async verify(algorithm,key,signature,data){if(name(algorithm)!=='HMAC')throw fail('NotSupportedError','HMAC required');return host('hmacVerify',access(key,'HMAC','verify'),buffer(signature),buffer(data));},
  async deriveBits(algorithm,key,length){if(name(algorithm)!=='HKDF'||name(algorithm.hash)!=='SHA-256')throw fail('NotSupportedError','HKDF SHA256 required');if(!Number.isSafeInteger(length)||length<8||length%8||length>65280)throw fail('OperationError','Invalid HKDF length');return host('hkdf',access(key,'HKDF','deriveBits'),buffer(algorithm.salt),buffer(algorithm.info),length/8);},
  async encrypt(algorithm,key,data){return aes(true,algorithm,key,data);},
  async decrypt(algorithm,key,data){return aes(false,algorithm,key,data);}
 };
 function aes(encrypt,algorithm,key,data){if(name(algorithm)!=='AES-GCM')throw fail('NotSupportedError','AES-GCM required');const tag=algorithm.tagLength??128;if(![32,64,96,104,112,120,128].includes(tag))throw fail('OperationError','Invalid GCM tag');try{return host(encrypt?'encrypt':'decrypt',access(key,'AES-GCM',encrypt?'encrypt':'decrypt'),buffer(algorithm.iv),algorithm.additionalData===undefined?new Uint8Array():buffer(algorithm.additionalData),buffer(data),tag);}catch(error){if(error.name==='InvalidAccessError')throw error;throw fail('OperationError','Transport authentication failed');}}
 g.crypto=Object.freeze({subtle:Object.freeze(subtle),getRandomValues(value){if(![Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,BigInt64Array,BigUint64Array].some(Type=>value instanceof Type))throw fail('TypeMismatchError','Integer typed array required');if(value.byteLength>65536)throw fail('QuotaExceededError','Random buffer too large');host('randomFill',buffer(value));return value;}});
 g.DMASH_NODE_WORKER_URLS=Object.freeze({identity:'node_identity.js',admission:'node_admission_v4.js',channel:'node_channel_v4.js'});
 g.__nativeEvent=(type,id,data)=>{
  if(type==='timer'){const fn=timers.get(id),interval=intervals.get(id);timers.delete(id);fn?.();if(interval&&intervals.has(id)){timers.set(id,()=>interval.fn(...interval.args));host('timerStart',id,interval.delay);}}
  else if(type==='workerMessage')workers.get(id)?.dispatchEvent({type:'message',data:decodeClone(data)});
  else if(type==='workerError')workers.get(id)?.dispatchEvent({type:'error'});
  else if(type==='workerInput')g.onmessage?.({data:decodeClone(data)});
  else{const socket=sockets.get(id);if(!socket)return;if(type==='open')socket.readyState=1;if(type==='close'){socket.readyState=3;sockets.delete(id);}socket.dispatchEvent(type==='message'?{type,data}:{type});}
 };
 if(host('isWorker')){g.WorkerGlobalScope=class{static [Symbol.hasInstance](v){return v===g;}};g.importScripts=(...names)=>{for(const file of names)host('importScript',file);};g.postMessage=data=>host('workerReply',encodeClone(data));}
 g.NativePlatform=Object.freeze({host,buffer,close(){for(const id of timers.keys())host('timerStop',id);timers.clear();intervals.clear();for(const worker of workers.values())worker.terminate();workers.clear();for(const socket of sockets.values())socket.close();sockets.clear();}});
})(globalThis);
