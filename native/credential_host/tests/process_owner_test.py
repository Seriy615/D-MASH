"""Actual private credential host process/IPC/retained Saved/reopen/Node lifetime gate."""
import hashlib,json,os,pathlib,socket,struct,subprocess,sys,tempfile,time
host=pathlib.Path(sys.argv[1]);node=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else None
fixture=json.loads((pathlib.Path(__file__).parents[2]/'account/tests/account_profile.json').read_text())
with tempfile.TemporaryDirectory(prefix='dmh-',dir=pathlib.Path.home()/'.cache') as folder:
 profile=pathlib.Path(folder);profile.chmod(0o700);process=None;s=None
 def connect():
  global s
  limit=time.monotonic()+15
  while time.monotonic()<limit:
   try:
    locator=json.loads((profile/'credential-endpoint.json').read_text());s=socket.socket(socket.AF_UNIX);s.settimeout(240);s.connect(locator['endpoint']);return
   except (OSError,ValueError):
    if s:s.close()
    time.sleep(.05)
  raise RuntimeError('host locator unavailable')
 def send_request(id,method,params=None):
  raw=json.dumps(dict(v=1,id=id,method=method,params=params or {}),separators=(',',':')).encode();s.sendall(struct.pack('>I',len(raw))+raw)
 def read_reply():
  def exact(n):
   b=b''
   while len(b)<n:
    chunk=s.recv(n-len(b));assert chunk,'owner EOF';b+=chunk
   return b
  return json.loads(exact(struct.unpack('>I',exact(4))[0]))
 def request(method,params=None):
  send_request('probe',method,params);result=read_reply();assert result['id']=='probe';return result
 def cancel_pending(method,params):
  send_request('cancelled-job',method,params);send_request('cancel-request','account.cancel')
  replies={}
  for _ in range(2):
   reply=read_reply();replies[reply['id']]=reply
  assert replies['cancel-request']['ok'],replies['cancel-request']
  assert not replies['cancelled-job']['ok'],replies['cancelled-job']
 def good(method,params=None):
  result=request(method,params);assert result['ok'],(method,result.get('code'));return result['result']
 def launch():
  global process
  args=[str(host),'--profile',str(profile)]
  if node:args+=['--node-host',str(node)]
  process=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);connect()
 try:
  launch();assert good('host.status')['value']['rootLocked']
  package=fixture['profile'];materials=package['root']['materials'];materials.pop('node-ed25519-pow-v4',None);materials.pop('node-base-ncrh-v4',None)
  digest=hashlib.sha256(json.dumps(package,sort_keys=True).encode()).hexdigest()
  imported=good('profile.import',dict(profile=package,pin=fixture['rootPin']));assert len(imported['rows'])==1
  logged=good('account.login',dict(identity=fixture['identity'],password=fixture['password']));assert logged['value']['accountPublicId']==fixture['accountPublicId']
  saved='local:saved-messages:v1';assert len(good('account.history',dict(peer=saved))['rows'])==1
  good('account.sendText',dict(peer=saved,operationId='c'*64,text='resident host synthetic Saved'))
  assert len(good('account.history',dict(peer=saved))['rows'])==2
  s.close();s=None;time.sleep(.15);assert process.poll() is None
  connect();state=good('host.status')['value'];assert state['accountSessionActive'] and state['account']['accountPublicId']==fixture['accountPublicId']
  node_survived=False
  if node:
   enabled=good('node.enable',dict(endpoints=[],directEnabled=False));assert enabled['value']['nodeRunning']
   assert good('host.status')['value']['nodeRunning']
   assert good('node.renew')['value']['capabilitiesRenewed']==2
   assert good('host.status')['value']['nodeRunning'],'broker context survives capability renewal'
   cancel_pending('account.login',dict(identity=fixture['identity'],password=fixture['password']))
   state=good('host.status')['value'];assert state['nodeRunning'] and not state['rootLocked'] and not state['accountSessionActive'],'Account cancel preserves prepared Root and approved Node'
   good('account.login',dict(identity=fixture['identity'],password=fixture['password']))
   good('account.logout');s.close();s=None;time.sleep(.3);assert process.poll() is None;connect();state=good('host.status')['value'];assert state['nodeRunning'] and not state['accountSessionActive'];node_survived=True
  good('root.lock');assert not good('host.status')['value']['nodeRunning']
  cancel_pending('root.unlock',dict(pin=fixture['rootPin']))
  state=good('host.status')['value'];assert state['rootLocked'] and not state['nodeRunning'],'Root unlock cancellation confirms actual locked/stopped state'
  good('root.unlock',dict(pin=fixture['rootPin']));good('account.login',dict(identity=fixture['identity'],password=fixture['password']));assert len(good('account.history',dict(peer=saved))['rows'])==2
  s.close();s=None;process.terminate();assert process.wait(15)==0;process=None
  launch();good('root.unlock',dict(pin=fixture['rootPin']));good('account.login',dict(identity=fixture['identity'],password=fixture['password']));assert len(good('account.history',dict(peer=saved))['rows'])==2
  s.close();s=None;process.terminate();assert process.wait(15)==0;process=None
  accepted=profile/'account.sqlite';preserved=profile/'account-preserved.sqlite';accepted.rename(preserved)
  launch();rejected=request('root.unlock',dict(pin=fixture['rootPin']));assert not rejected['ok'] and not accepted.exists(),'accepted missing DB must not replay initial snapshot'
  preserved.rename(accepted);good('root.unlock',dict(pin=fixture['rootPin']));good('account.login',dict(identity=fixture['identity'],password=fixture['password']));assert len(good('account.history',dict(peer=saved))['rows'])==2
  s.close();s=None;process.terminate();assert process.wait(15)==0;process=None
  key=profile/'app-local.key';saved_key=profile/'preserved.key';key.rename(saved_key)
  db_hash=hashlib.sha256((profile/'credentials.sqlite').read_bytes()).hexdigest()
  process=subprocess.Popen([str(host),'--profile',str(profile)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);assert process.wait(15)!=0
  assert not key.exists() and hashlib.sha256((profile/'credentials.sqlite').read_bytes()).hexdigest()==db_hash,'missing key must not create new installation'
  saved_key.rename(key)
  assert hashlib.sha256(json.dumps(package,sort_keys=True).encode()).hexdigest()==digest
  print(json.dumps(dict(ok=True,scope='native process IPC; no remote/UI acceptance',sameAccount=True,retainedSavedBefore=1,savedAfterReopen=2,uiDetachPreservesOwner=True,logoutAndDetachPreservesNode=node_survived,rootLockStopsOwnedNode=True,cleanRestartPreservesHistory=True,acceptedMissingDatabaseRefusesReplay=True,missingKeyRefusesNewInstallation=True,accountCancelPreservesRootAndNode=node_survived,rootUnlockCancelActuallyLocksAndStops=True,capabilityRenewalRetainsNodeAndContexts=node_survived)))
 finally:
  if s:s.close()
  if process and process.poll() is None:process.terminate();process.wait(15)
