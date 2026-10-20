"""Actual accepted E2EE job survives transport pause/resume and paused owner crash.

Own synthetic profiles only. CLI: HOST NODE_HOST NODE24 ORIGINAL_FIXTURE_DIR PRIVATE_CACHE
Original signed-pair fixtures are copied; no source profile or accepted store is reset.
"""
import asyncio,base64,hashlib,json,os,pathlib,secrets,signal,socket,sqlite3,struct,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'D-MASH/client'));sys.path.insert(0,str(ROOT/'native/tests'))
from ipc_delivery_test import mine
from fastapi import FastAPI
import uvicorn
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.resource_pow import activation_pow_difficulty

class Host:
 def __init__(self,binary,node,profile):self.binary=binary;self.node=node;self.profile=profile;self.process=None;self.socket=None;self.lock=asyncio.Lock();self.children=[]
 async def start(self):
  self.profile.mkdir(mode=0o700,exist_ok=True)
  with os.fdopen(os.open(self.profile/'owner.stderr',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),'ab') as log:
   self.process=await asyncio.create_subprocess_exec(self.binary,'--profile',str(self.profile),'--node-host',self.node,stdout=log,stderr=log)
  await self.connect()
 async def connect(self):
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   try:
    s=socket.socket(socket.AF_UNIX);s.settimeout(180);s.connect(json.loads((self.profile/'credential-endpoint.json').read_text())['endpoint']);self.socket=s;return
   except (OSError,ValueError):s.close();await asyncio.sleep(.03)
  raise TimeoutError('owner endpoint')
 async def call(self,method,**params):
  def request():
   raw=json.dumps(dict(v=1,id='pause-proof',method=method,params=params)).encode();self.socket.sendall(struct.pack('>I',len(raw))+raw)
   def exact(n):
    out=b''
    while len(out)<n:
     part=self.socket.recv(n-len(out));assert part,'owner EOF';out+=part
    return out
   reply=json.loads(exact(struct.unpack('>I',exact(4))[0]));assert reply.get('ok'),(method,reply.get('code'));return reply['result']
  async with self.lock:return await asyncio.to_thread(request)
 async def state(self):return (await self.call('host.status'))['value']
 def receipt(self):return json.loads((self.profile/'node/supervisor-child.json').read_text())
 def jobs(self):
  with sqlite3.connect('file:'+str(self.profile/'node/node.sqlite')+'?mode=ro',uri=True) as db:return {id:state for id,state in db.execute('SELECT id,state FROM native_jobs')}
 async def packets(self,node_js,ids):
  with sqlite3.connect('file:'+str(self.profile/'node/node.sqlite')+'?mode=ro',uri=True) as db:
   rows=[dict(id=id,iv=base64.b64encode(iv).decode(),ciphertext=base64.b64encode(ciphertext).decode()) for id,iv,ciphertext in db.execute('SELECT id,iv,ciphertext FROM native_jobs') if id in ids]
  request=json.dumps(dict(synthetic=True,nodeId=self.receipt()['nodeId'],rows=rows)).encode()
  process=await asyncio.create_subprocess_exec(node_js,str(ROOT/'native/credential_host/tests/inspect_pause_jobs.cjs'),stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
  out,error=await process.communicate(request);assert process.returncode==0,'authenticate own synthetic native job rows';return json.loads(out)
 async def enable(self,endpoints=None):
  await self.call('node.enable',**(dict(endpoints=endpoints,directEnabled=False) if endpoints is not None else {}));r=self.receipt()
  assert hashlib.sha256(pathlib.Path('/proc/'+str(r['pid'])+'/exe').read_bytes()).digest()==hashlib.sha256(pathlib.Path(self.node).read_bytes()).digest()
  self.children.append(os.pidfd_open(r['pid']));return r
 async def pause(self):
  previous=self.receipt();reply=await self.call('node.pause');state=await self.state()
  assert reply['value']['nodeState']=='paused' and not state['rootLocked'] and state['accountSessionActive'] and not state['nodeRunning'] and state['nodeState']=='paused'
  try:assert (pathlib.Path('/proc')/str(previous['pid'])/'stat').read_text().split(') ')[1][0]=='Z'
  except FileNotFoundError:pass
 async def close(self):
  if self.socket:self.socket.close();self.socket=None
  if self.process and self.process.returncode is None:
   self.process.terminate()
   try:await asyncio.wait_for(self.process.wait(),15)
   except asyncio.TimeoutError:self.process.kill();await self.process.wait()
  for fd in self.children:
   try:signal.pidfd_send_signal(fd,signal.SIGKILL)
   except ProcessLookupError:pass
   os.close(fd)
  self.children=[]

async def main():
 host_binary,node_binary,node_js,original,cache=sys.argv[1:];original=pathlib.Path(original)
 folder=pathlib.Path(tempfile.mkdtemp(prefix='pause-remote-',dir=cache));folder.chmod(0o700)
 source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in original.glob('account-*.json')}
 started=time.monotonic();timings=[]
 def mark(stage):
  timings.append(dict(stage=stage,elapsedSeconds=round(time.monotonic()-started,3)))
  path=folder/'stages.json';path.write_text(json.dumps(timings));path.chmod(0o600);return stage
 owners=[];server=None;task=None;service=None;phase=mark('synthetic-identities');success=False;port=0
 async def transit(start):
  nonlocal server,task,service,port
  if not start:
   if server:server.should_exit=True
   if task:await task
   if service:await service.close()
   server=task=service=None;return
  service=NodeServiceV4(transit_key,folder/'transit');assert activation_pow_difficulty()==22 and service.listener.difficulty is None
  app=FastAPI();app.state.node_v4=service;app.include_router(router)
  listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',port));port=listener.getsockname()[1]
  server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16));task=asyncio.create_task(server.serve(sockets=[listener]))
  while not server.started:await asyncio.sleep(.01)
 async def sync(owner):
  value=await owner.call('account.sync')
  for row in value['rows']:
   if row.get('code'):
    path=folder/'sync-failure.json';path.write_text(json.dumps(value));path.chmod(0o600);raise AssertionError(row['code'])
  return value
 async def connected():
  deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   states=await asyncio.gather(*(o.state() for o in owners))
   if all(s['node'].get('connectedPeers')==1 for s in states):return
   await asyncio.sleep(.25)
  raise TimeoutError('actual default22 channels')
 try:
  transit_key,*node_keys=await asyncio.to_thread(lambda:[mine() for _ in range(3)])
  seedfile=folder/'synthetic-seeds.json';seedfile.write_text(json.dumps([dict(seed=k.encode().hex(),baseNcrh=secrets.token_hex(32)) for k in node_keys]));seedfile.chmod(0o600)
  prepared=folder/'profiles';prepared.mkdir(mode=0o700)
  process=await asyncio.create_subprocess_exec(node_js,str(ROOT/'native/credential_host/tests/prepare_pause_profiles.cjs'),str(original),str(seedfile),str(prepared),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE);out,error=await process.communicate();assert process.returncode==0,'synthetic profile preparation'
  fixtures=[json.loads((prepared/('account-'+str(i)+'.json')).read_text()) for i in range(2)]
  phase=mark('owners-start');await transit(True);endpoints=[dict(url=f'ws://127.0.0.1:{port}/mesh/v4',nodeId=transit_key.verify_key.encode().hex())]
  receipts=[]
  for i in range(2):
   o=Host(host_binary,node_binary,folder/('owner-'+str(i)));owners.append(o);await o.start();f=fixtures[i]
   await o.call('profile.import',profile=f['profile'],pin=f['rootPin']);receipts.append(await o.enable(endpoints));await o.call('account.login',identity=f['identity'],password=f['password'])
  assert receipts[0]['nodeId']!=receipts[1]['nodeId'];await connected()
  phase=mark('existing-Account-E2EE-handshake');await asyncio.gather(*(sync(o) for o in owners))
  operation=secrets.token_hex(32);text='native durable paused text '+secrets.token_hex(16)
  initial=await owners[0].call('account.sendText',peer=fixtures[0]['peer'],operationId=operation,text=text);assert initial['value']['transportState']=='HANDSHAKE_PENDING'
  deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   pages=await asyncio.gather(*(sync(o) for o in owners))
   if all(any(row.get('status',{}).get('phase')=='ESTABLISHED' for row in p['rows']) for p in pages):break
   await asyncio.sleep(.5)
  else:raise TimeoutError('actual E2EE established')
  await asyncio.gather(*(sync(o) for o in owners));before=owners[0].jobs()
  phase=mark('offline-accepted-native-job');await transit(False)
  queued=await owners[0].call('account.sendText',peer=fixtures[0]['peer'],operationId=operation,text=text);assert queued['value']['accepted']
  diagnostic=folder/'initial-account-queue-receipt.json';diagnostic.write_text(json.dumps(queued));diagnostic.chmod(0o600)
  # Account acceptance means durable application intent. Wait for the actual
  # retry/sync flush and accepted native row before testing transport pause.
  deadline=time.monotonic()+45
  while time.monotonic()<deadline:
   await sync(owners[0]);after=owners[0].jobs();accepted=set(after)-set(before)
   if accepted:break
   await asyncio.sleep(.25)
  assert len(accepted)==1 and all(after[id] not in ['TRANSPORT_SENT','CANCELLED','EXPIRED','FAILED_RETRY_BUDGET'] for id in accepted),after
  original_packets=await owners[0].packets(node_js,accepted)
  assert set(original_packets)==accepted
  phase=mark('pause-preserves-owner-and-job');await asyncio.gather(*(o.pause() for o in owners))
  for i,o in enumerate(owners):
   assert (await o.state())['account']['accountPublicId']==fixtures[i]['accountPublicId']
   await o.call('account.sendText',peer='local:saved-messages:v1',operationId=str(i+1)*64,text='Saved while Node paused')
   assert len((await o.call('account.history',peer='local:saved-messages:v1'))['rows'])==1
   o.socket.close();o.socket=None;await o.connect();assert (await o.state())['accountSessionActive']
  paused_jobs=owners[0].jobs();assert accepted<=set(paused_jobs) and await owners[0].packets(node_js,accepted)==original_packets
  phase=mark('resume-without-PIN-or-Account-login');resumed=await owners[0].enable();assert resumed['nodeId']==receipts[0]['nodeId'] and resumed['generation']>receipts[0]['generation']
  assert (await owners[0].state())['accountSessionActive'] and accepted<=set(owners[0].jobs())
  assert await owners[0].packets(node_js,accepted)==original_packets
  phase=mark('paused-owner-SIGKILL');await owners[0].pause();owners[0].socket.close();owners[0].socket=None;owners[0].process.kill();await owners[0].process.wait();await owners[0].start()
  assert (await owners[0].state())['rootLocked']
  await owners[0].call('root.unlock',pin=fixtures[0]['rootPin']);await owners[0].call('account.login',identity=fixtures[0]['identity'],password=fixtures[0]['password'])
  assert len((await owners[0].call('account.history',peer='local:saved-messages:v1'))['rows'])==1
  restarted=await owners[0].enable();recipient=await owners[1].enable();assert restarted['nodeId']==resumed['nodeId'] and restarted['deviceId']==receipts[0]['deviceId'] and restarted['generation']>resumed['generation'];assert recipient['nodeId']==receipts[1]['nodeId'] and accepted<=set(owners[0].jobs())
  assert await owners[0].packets(node_js,accepted)==original_packets
  phase=mark('same-transit-restart-original-job-delivery');await transit(True);await connected()
  deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   await asyncio.gather(*(sync(o) for o in owners));history=(await owners[1].call('account.history',peer=fixtures[1]['peer']))['rows']
   if any(row.get('operationId')==operation for row in history):break
   await asyncio.sleep(.5)
  else:raise TimeoutError('original queued application delivery')
  assert len(history)==1 and history[0]['operationId']==operation and history[0]['text']==text
  await asyncio.gather(*(sync(o) for o in owners));assert len((await owners[1].call('account.history',peer=fixtures[1]['peer']))['rows'])==1
  assert accepted<=set(owners[0].jobs()) and all(owners[0].jobs()[id]=='TRANSPORT_SENT' for id in accepted)
  assert await owners[0].packets(node_js,accepted)==original_packets
  for i,o in enumerate(owners):
   for p in (o.profile/'node').iterdir():
    if p.is_file():assert text.encode() not in p.read_bytes()
   await o.call('root.lock');state=await o.state();assert state['rootLocked'] and not state['accountSessionActive'] and not state['nodeRunning']
  assert source_hashes=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in original.glob('account-*.json')}
  print(json.dumps(dict(ok=True,scope='actual resident owners transport-only pause/resume/paused-owner crash; preselected signed contacts',admissionDifficulty=22,actualAccountE2EE=True,acceptedNativeJobs=len(accepted),sameOriginalJobRetained=True,sameOpaqueCiphertextAndExpiry=True,recipientHistoryExactlyOnce=1,pausedSavedRows=2,resumeWithoutPINOrLogin=True,pausedOwnerSigkillRecovery=True,generations=[receipts[0]['generation'],resumed['generation'],restarted['generation']],identitiesAndSourcePreserved=True,nodeContainsPlaintext=False)),flush=True);success=True
 except BaseException as error:
  marker=folder/'failure.json';marker.write_text(json.dumps(dict(phase=phase,errorClass=type(error).__name__)));marker.chmod(0o600)
  print(json.dumps(dict(ok=False,phase=phase,errorClass=type(error).__name__,privateDiagnosticDirectory=str(folder))),flush=True);raise
 finally:
  await asyncio.gather(*(o.close() for o in owners));await transit(False)
  # Both successful and failed private fixtures remain available for independent review.
  if success:print(json.dumps(dict(privateSyntheticEvidenceDirectory=str(folder))),flush=True)

if __name__=='__main__':asyncio.run(main())
