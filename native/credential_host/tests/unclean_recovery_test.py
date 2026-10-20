"""Own synthetic actual hostSIGKILL/NodeEOF/public-counter rollback recovery; no reset."""
import json,pathlib,socket,struct,subprocess,sys,tempfile,time,sqlite3,os,signal,contextlib,shutil
host,node=map(pathlib.Path,sys.argv[1:3]);fixture=json.loads((pathlib.Path(__file__).parents[2]/'account/tests/account_profile.json').read_text())
@contextlib.contextmanager
def ownProfile():
 directory=tempfile.mkdtemp(prefix='dmhc-',dir=pathlib.Path.home()/'.cache');os.chmod(directory,0o700)
 try:yield directory
 except BaseException:
  print(json.dumps(dict(preservedSyntheticDiagnosticProfile=directory)),file=sys.stderr);raise
 else:shutil.rmtree(directory)
with ownProfile() as directory:
 profile=pathlib.Path(directory);profile.chmod(0o700);owner=None;connection=None;suspended_fd=None
 def exact(n):
  data=b''
  while len(data)<n:
   more=connection.recv(n-len(data));assert more,'unexpected owner EOF';data+=more
  return data
 def call(method,params=None):
  started=time.monotonic()
  raw=json.dumps(dict(v=1,id='recovery',method=method,params=params or {})).encode();connection.sendall(struct.pack('>I',len(raw))+raw)
  reply=json.loads(exact(struct.unpack('>I',exact(4))[0]));assert reply['ok'],(method,reply.get('code'),dict(elapsedMs=int((time.monotonic()-started)*1000)));return reply['result']
 def launch():
  global owner,connection
  with os.fdopen(os.open(profile/'owner.stderr',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),'ab') as log:
   owner=subprocess.Popen([str(host),'--profile',str(profile),'--node-host',str(node)],stdout=subprocess.DEVNULL,stderr=log)
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   try:
    endpoint=json.loads((profile/'credential-endpoint.json').read_text())['endpoint'];connection=socket.socket(socket.AF_UNIX);connection.settimeout(180);connection.connect(endpoint);return
   except (OSError,ValueError):
    if connection:connection.close()
    time.sleep(.03)
  raise RuntimeError('owner unavailable after restart')
 def receipt():return json.loads((profile/'node/supervisor-child.json').read_text())
 def crash():
  global owner,connection
  previous=receipt();connection.close();connection=None;owner.kill();assert owner.wait(15)!=0;owner=None
  # The old inherited broker lease reaches EOF without an orderly Host destructor.
  deadline=time.monotonic()+10
  while time.monotonic()<deadline:
   try:
    raw=(pathlib.Path('/proc')/str(previous['pid'])/'stat').read_text();state=raw[raw.rfind(')')+2:].split()[0]
    if state=='Z':return previous
   except FileNotFoundError:return previous
   time.sleep(.02)
  raise RuntimeError('old owned Node did not exit on broker lease EOF')
 try:
  # Provisioning/mining has its own gates; crash recovery reuses this synthetic
  # fixture's verified retained Node slots to avoid random proof-of-work latency.
  launch();package=fixture['profile']
  known=json.loads(pathlib.Path(__file__).with_name('crash_node_material.json').read_text());package['root']['materials']['node-ed25519-pow-v4']=known['material']
  call('profile.import',dict(profile=package,pin=fixture['rootPin']))
  call('node.enable',dict(endpoints=[],directEnabled=False));initial=receipt();assert initial['nodeId']==known['nodeId']
  # Node enabled before ANY Account login; then retain a native write across both crashes.
  call('account.login',dict(identity=fixture['identity'],password=fixture['password']))
  saved='local:saved-messages:v1';call('account.sendText',dict(peer=saved,operationId='d'*64,text='native history before owner crash'));call('account.logout')
  first=crash();launch();call('root.unlock',dict(pin=fixture['rootPin']));call('node.enable');second=receipt()
  assert second['nodeId']==initial['nodeId'] and second['deviceId']==initial['deviceId'] and second['generation']>first['generation']
  crash()
  # Roll back only this fixture's PUBLIC broker counters. Authenticated native
  # ledger floors, encrypted Node/Account databases and keys remain untouched.
  with sqlite3.connect(profile/'control.sqlite') as db:db.execute("UPDATE broker_control SET generation=1,policy_revision=1,phase='ACTIVE'")
  launch();call('root.unlock',dict(pin=fixture['rootPin']));call('node.enable');third=receipt()
  assert third['nodeId']==initial['nodeId'] and third['deviceId']==initial['deviceId'] and third['generation']>second['generation'],'authenticated floor merge must retry above native floor'
  state=call('host.status')['value'];assert state['nodeRunning'] and state['node']['transportEnabled']
  call('account.login',dict(identity=fixture['identity'],password=fixture['password']));assert len(call('account.history',dict(peer=saved))['rows'])==2
  call('account.logout')
  # Root cancellation must also stop a verified old child that cannot process
  # lease EOF itself. Only this fixture's journaled PID is suspended.
  suspended_fd=os.pidfd_open(third['pid']);signal.pidfd_send_signal(suspended_fd,signal.SIGSTOP);connection.close();connection=None;owner.kill();owner.wait(15);owner=None
  launch()
  for id,method,params in [('unlock-cancelled','root.unlock',dict(pin=fixture['rootPin'])),('cancel','account.cancel',{})]:
   raw=json.dumps(dict(v=1,id=id,method=method,params=params)).encode();connection.sendall(struct.pack('>I',len(raw))+raw)
  replies={}
  for _ in range(2):
   result=json.loads(exact(struct.unpack('>I',exact(4))[0]));replies[result['id']]=result
  assert replies['cancel']['ok'] and not replies['unlock-cancelled']['ok']
  state=call('host.status')['value'];assert state['rootLocked'] and not state['nodeRunning']
  try:
   raw=(pathlib.Path('/proc')/str(third['pid'])/'stat').read_text();assert raw[raw.rfind(')')+2:].split()[0]=='Z','Root cancel must confirm actual old child exit'
  except FileNotFoundError:pass
  call('root.unlock',dict(pin=fixture['rootPin']));call('node.enable');fourth=receipt();assert fourth['nodeId']==initial['nodeId']
  call('root.lock');assert not call('host.status')['value']['nodeRunning']
  print(json.dumps(dict(ok=True,scope='actual native host/child crash and authenticated floor rollback; not full N4',nodeBeforeAnyAccountLogin=True,hostSigkillNodeLeaseEof=True,sameNodeAndRoot=True,authenticatedFloorMergeRetry=True,nativeSavedRowsRetained=2,cancelStopsVerifiedSuspendedOldChild=True,generations=[initial['generation'],second['generation'],third['generation'],fourth['generation']])))
 finally:
  if suspended_fd is not None:
   try:signal.pidfd_send_signal(suspended_fd,signal.SIGKILL)
   except ProcessLookupError:pass
   os.close(suspended_fd)
  if connection:connection.close()
  if owner and owner.poll() is None:owner.terminate();owner.wait(20)
