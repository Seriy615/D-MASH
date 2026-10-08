'use strict';
// Observational CDP logpoints only: no protocol calls, method replacement, storage
// writes, key/route/Account IDs or payload serialization. Not latency acceptance:
// debugger/progress observation can itself affect timing. Does not launch a browser.
const fs=require('node:fs'),path=require('node:path');
const PREFIX='DMASH_QA_READINESS ';
const safeError=expression=>`(${expression} == null ? null : /^[A-Z][A-Z0-9_]{2,60}$/.test(${expression}||'')?${expression}:['Account changed','Contact reply route is disabled or retired','Contact reply registration unavailable','Contact request route unavailable','Route unavailable','Initial request was not queued'].includes(${expression})?${expression}:'other_error')`;
const probes=[
 ['device_authority_v3.js','return this.mine({ nodeId:', 'pow-request','({kind,difficulty})'],
 ['device_authority_v3.js',"if (error.message !== 'DNSS_NOT_REGISTERED')",'dnss-response-error',`({code:${safeError('error.message')}})`],
 ['device_authority_v3.js',"if (operation !== 'REGISTER_ROUTE'",'route-response-error',`({operation,kind,code:${safeError('error.message')}})`],
 ['device_client_v3.js','this.state = \'connected\'; clearTimeout(this.deadline);','node-policy','({difficulty:this.resourcePowDifficulty})'],
 ['device_client_v3.js','if (this.state !== \'connected\' || !this.capabilities.has(type))','rpc-request','({type,pending:this.pending.size})',"['REGISTER_DNSS','REGISTER_ROUTE','START_PROBE','ROUTE_STATUS','SUBMIT','PULL','ACK'].includes(type)"],
 ['device_client_v3.js','const pending = this.pending.get(message.request_id);','rpc-response',`({type:message.type,code:${safeError('message.code')},state:/^[A-Z_]{2,40}$/.test(message.state||'')?message.state:null})`,"['ERROR','ROUTE_STATUS_RESULT','SUBMIT_RESULT','REGISTER_ROUTE_RESULT','REGISTER_DNSS_RESULT','START_PROBE_RESULT','DELIVERY_AVAILABLE'].includes(message.type)"],
 ['core_engine.js','const results=await Promise.allSettled(nodes.map(node=>window.NodeManager.activatePublicRouteOnConnection(local,node)));','initial-activation-start','({nodes:nodes.length})'],
 ['core_engine.js',"if(!results.some(result=>result.status==='fulfilled'&&['ACTIVATED','READVERTISED'].includes(result.value?.state)))",'initial-activation-result',`({results:results.map(r=>({status:r.status,state:r.value?.state||null,error:r.status==='rejected'?${safeError('r.reason?.message')}:null}))})`],
 ['core_engine.js',"if(!ready?.connection.client)throw Error('Contact request route unavailable');",'initial-target-readiness','({ready:!!ready,connected:!!ready?.connection?.client})'],
 ['contact_flow_v3.js','if(state.nextRetryAt>now)return false;','initial-retry-state','({attempts:state.attempts,status:state.status,retryInMs:Math.max(0,state.nextRetryAt-now),expiresInMs:state.expiresAt-now})'],
 ['contact_flow_v3.js',"state.status='requested';state.lastSentAt=this.clock();",'initial-submitted','({attempts:state.attempts})'],
 ['contact_flow_v3.js','}catch(_){return false;}','initial-error',`({code:${safeError('_?.message')},attempts:state.attempts})`,null,'return false'],
 ['resource_pow.js','if (data.progress) { options.onProgress?.(data.progress); return; }','pow-progress','({kind:options.activationType,difficulty:options.difficulty,attempts:data.progress.attempts,elapsedMs:data.progress.elapsedMs})','!!data.progress && data.progress.attempts % 1048576 === 0'],
 ['resource_pow.js','if (data.error) reject(new Error(data.error)); else resolve(data.proof);','pow-finished',`({kind:options.activationType,difficulty:options.difficulty,elapsedMs:data.proof?.elapsed_ms||null,error:data.error?${safeError('data.error')}:null})`]
];
function locations(sourceRoot){return probes.map(([file,anchor,stage,value,when,columnAnchor])=>{
 const source=fs.readFileSync(path.join(sourceRoot,'js',file),'utf8'),at=source.indexOf(anchor);
 if(at<0||source.indexOf(anchor,at+anchor.length)!==-1)throw Error('Nonunique/missing readiness anchor: '+file+' '+stage);
 const offset=at+(columnAnchor?anchor.indexOf(columnAnchor):0),lineNumber=source.slice(0,offset).split('\n').length-1,columnNumber=offset-(source.lastIndexOf('\n',offset-1)+1);
 const condition=`(()=>{try{if(${when||'true'})console.debug(${JSON.stringify(PREFIX)}+JSON.stringify({stage:${JSON.stringify(stage)},data:${value}}));}catch(_){console.debug(${JSON.stringify(PREFIX)}+JSON.stringify({stage:${JSON.stringify(stage)},observationError:true}));}return false;})()`;
 return {file,stage,lineNumber,columnNumber,condition};
});}
async function attach({page,context,sourceRoot,profile,emit}){
 const client=await context.newCDPSession(page),breakpoints=[];
 await client.send('Runtime.enable');await client.send('Debugger.enable');
 client.on('Runtime.consoleAPICalled',event=>{const text=event.args?.[0]?.value;if(typeof text!=='string'||!text.startsWith(PREFIX))return;try{const row=JSON.parse(text.slice(PREFIX.length));emit({profile,at:new Date().toISOString(),...row});}catch(_){}});
 for(const loc of locations(sourceRoot)){
  const result=await client.send('Debugger.setBreakpointByUrl',{urlRegex:'/not_messenger/js/'+loc.file.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'(?:\\?|$)',lineNumber:loc.lineNumber,columnNumber:loc.columnNumber,condition:loc.condition});
  breakpoints.push(result.breakpointId);
 }
 return {client,close:async()=>{for(const breakpointId of breakpoints)await client.send('Debugger.removeBreakpoint',{breakpointId}).catch(()=>{});await client.detach();}};
}
module.exports={attach,locations};
