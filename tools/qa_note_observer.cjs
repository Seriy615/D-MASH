'use strict';
const fs=require('node:fs'),path=require('node:path');
module.exports=async({pages,sourceRoot,report})=>{
 const result=report.noteTransportObservation={limits:'Metadata-only CDP logpoint + readonly RTC stats polling; instrumentation may affect timings; no secrets or payload bodies recorded',messages:[],relay:[]};
 const sessions=[];let closed=false;
 const src=fs.readFileSync(path.join(sourceRoot,'js/core_engine.js'),'utf8'),anchor='const current=()=>!sessionGuard||sessionGuard();',at=src.indexOf(anchor);
 if(at<0)throw Error('Missing send observation anchor');
 for(const [profile,p]of pages.entries()){
  const s=await p.context().newCDPSession(p);sessions.push(s);await s.send('Runtime.enable');await s.send('Debugger.enable');
  s.on('Runtime.consoleAPICalled',event=>{const v=event.args?.[0]?.value;if(typeof v==='string'&&v.startsWith('QA_NOTE_META '))try{result.messages.push({profile,at:new Date().toISOString(),...JSON.parse(v.slice(13))});}catch{}});
  await s.send('Debugger.setBreakpointByUrl',{urlRegex:'/js/core_engine\\.js(?:\\?|$)',lineNumber:src.slice(0,at).split('\n').length-1,columnNumber:at-src.lastIndexOf('\n',at-1)-1,condition:"(()=>{try{if(c&&(queuedAlias==='turn-note-control'||c.type==='dmash_media_fragment'||c.type?.startsWith('voip_media_')))console.debug('QA_NOTE_META '+JSON.stringify({type:c.type,bytes:new TextEncoder().encode(JSON.stringify(c)).length,containsMedia:typeof c.data==='string'||c.type==='dmash_media_fragment'}));}catch{}return false;})()"});
 }
 const polling=(async()=>{while(!closed){for(const [profile,p]of pages.entries())try{const samples=await p.evaluate(async()=>{const out=[];for(const t of Core.recordedNoteTurn?.tasks?.values()||[]){const pc=t.session?.pc;if(!pc)continue;const stats=await pc.getStats();for(const pair of stats.values())if(pair.type==='candidate-pair'&&pair.state==='succeeded'&&pair.nominated){out.push({outbound:!!t.outbound,policy:pc.getConfiguration().iceTransportPolicy,local:stats.get(pair.localCandidateId)?.candidateType,remote:stats.get(pair.remoteCandidateId)?.candidateType,sent:pair.bytesSent,received:pair.bytesReceived});}}return out;});if(samples.length)result.relay.push({profile,at:new Date().toISOString(),samples});}catch{}await new Promise(r=>setTimeout(r,250));}})();
 return async()=>{if(closed)return result;closed=true;await polling;for(const s of sessions)await s.detach();return result;};
};
