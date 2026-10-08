'use strict';
(function(g){
 const hex=/^[0-9a-f]{64}$/,ticket=/^[A-Za-z0-9_-]{43}$/;
 const fail=()=>{throw Error('INVALID_ACCOUNT_MEDIA_CONTROL');};
 function exact(v,keys){if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))fail();}
 function plain(v,depth=0){if(depth>4)fail();if(v===null||typeof v==='string'||typeof v==='boolean'||(typeof v==='number'&&Number.isFinite(v)))return;if(!v||typeof v!=='object'||Object.getPrototypeOf(v)!==Object.prototype)fail();for(const k of Reflect.ownKeys(v)){const d=Object.getOwnPropertyDescriptor(v,k);if(typeof k!=='string'||!d.enumerable||!Object.hasOwn(d,'value'))fail();plain(d.value,depth+1);}}
 function integer(v,min,max){if(!Number.isSafeInteger(v)||v<min||v>max)fail();}
 function validate(type,input,{now=Math.floor(Date.now()/1000)}={}){
  if(!['INVITE','ACCEPT','DECLINE','CANCEL','COMMIT_ACK'].includes(type))fail();
  plain(input);let raw;try{raw=JSON.stringify(input);}catch(_){fail();}if(new TextEncoder().encode(raw).length>8192)fail();
  const v=JSON.parse(raw),keys=['version','transferId','kind','expiresAt'];
  if(type==='INVITE')keys.push('transportId','service','signaling','media');
  if(type==='DECLINE'||type==='CANCEL')keys.push('reason');if(type==='DECLINE'&&v.kind==='file')keys.push('sha256');
  if(type==='COMMIT_ACK')keys.push('sha256','size');exact(v,keys);
  if(v.version!==1||!hex.test(v.transferId)||!['voice','circle','file','call'].includes(v.kind))fail();integer(v.expiresAt,now+1,now+86400);
  if(type==='DECLINE'||type==='CANCEL'){if(!['USER','EXPIRED','UNAVAILABLE','INTEGRITY','RECEIVER_DECLINED','RECEIVER_STORAGE_FULL'].includes(v.reason))fail();}
  if(type==='DECLINE'&&v.kind==='file'&&!hex.test(v.sha256))fail();
  if(type==='COMMIT_ACK'){if(v.kind==='call'||!hex.test(v.sha256))fail();integer(v.size,1,67108864);}
  if(type==='INVITE'){
   if(!hex.test(v.transportId))fail();exact(v.service,['nodeId','wssEndpoint']);if(!hex.test(v.service.nodeId))fail();
   let u;try{u=new URL(v.service.wssEndpoint);}catch(_){fail();}if(u.protocol!=='wss:'||u.username||u.password||u.hash||u.href!==v.service.wssEndpoint||u.href.length>2048)fail();
   exact(v.signaling,['sessionId','ticket']);if(!ticket.test(v.signaling.sessionId)||!ticket.test(v.signaling.ticket))fail();
   if(v.kind==='call'){exact(v.media,['audio','video']);if(v.media.audio!==true||typeof v.media.video!=='boolean')fail();}
   else{exact(v.media,['mime','name','size','sha256','chunkBytes','key','nonce']);if(typeof v.media.mime!=='string'||!/^[a-z0-9.+-]+\/[a-z0-9.+-]+(?:;codecs=[a-z0-9., -]+)?$/i.test(v.media.mime)||v.media.mime.length>128||typeof v.media.name!=='string'||new TextEncoder().encode(v.media.name).length>255||/[\x00-\x1f\x7f]/.test(v.media.name)||!hex.test(v.media.sha256))fail();for(const [k,n]of [['key',32],['nonce',8]]){let b;try{b=atob(v.media[k]);}catch(_){fail();}if(b.length!==n||btoa(b)!==v.media[k])fail();}integer(v.media.size,1,67108864);integer(v.media.chunkBytes,1,32768);if(v.kind==='voice'&&!v.media.mime.startsWith('audio/'))fail();if(v.kind==='circle'&&!v.media.mime.startsWith('video/'))fail();}
  }
  return Object.freeze(v);
 }
 g.DmashAccountMediaControlV4=Object.freeze({validate,MAX_BYTES:8192});
 if(typeof module!=='undefined')module.exports=g.DmashAccountMediaControlV4;
})(typeof globalThis!=='undefined'?globalThis:this);
