"""Own synthetic explicit fresh Root and optional Account; never reset accepted state."""
import contextlib,json,os,pathlib,shutil,socket,sqlite3,struct,subprocess,sys,tempfile,time
host=pathlib.Path(sys.argv[1]);node=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else None
fixture=json.loads((pathlib.Path(__file__).parents[2]/'account/tests/account_profile.json').read_text())
@contextlib.contextmanager
def ownProfile():
 path=pathlib.Path(tempfile.mkdtemp(prefix='dmfresh-',dir=pathlib.Path.home()/'.cache'));path.chmod(0o700)
 try:yield path
 except BaseException:print(json.dumps(dict(preservedSyntheticProfile=str(path))),file=sys.stderr);raise
 else:shutil.rmtree(path)
with ownProfile() as profile:
 owner=None;connection=None
 def launch():
  global owner,connection
  args=[str(host),'--profile',str(profile)]+(['--node-host',str(node)] if node else [])
  with os.fdopen(os.open(profile/'owner.stderr',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),'ab') as log:owner=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=log)
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   try:
    locator=json.loads((profile/'credential-endpoint.json').read_text());connection=socket.socket(socket.AF_UNIX);connection.settimeout(240);connection.connect(locator['endpoint']);return
   except (OSError,ValueError):
    if connection:connection.close()
    time.sleep(.03)
  raise RuntimeError('owner unavailable')
 def exact(n):
  data=b''
  while len(data)<n:
   part=connection.recv(n-len(data));assert part;data+=part
  return data
 def call(method,params=None,ok=True):
  raw=json.dumps(dict(v=1,id='fresh',method=method,params=params or {})).encode();connection.sendall(struct.pack('>I',len(raw))+raw)
  reply=json.loads(exact(struct.unpack('>I',exact(4))[0]));assert reply['ok']==ok,(method,reply.get('code'));return reply['result'] if ok else reply
 def stop():
  global owner,connection
  if connection:connection.close();connection=None
  if owner and owner.poll() is None:owner.terminate();owner.wait(20)
  owner=None
 try:
  launch();state=call('host.status')['value'];assert not state['profileExists'] and not state['accountSessionActive']
  call('profile.create',dict(pin=''),False);assert not call('host.status')['value']['profileExists']
  # Fresh creation is fenced at request dispatch; cancellation never creates
  # an installation afterwards or leaves an implicitly unlocked Root.
  for id,method,params in [('root-create-cancelled','profile.create',dict(pin=fixture['rootPin'])),('cancel-root','account.cancel',{})]:
   raw=json.dumps(dict(v=1,id=id,method=method,params=params)).encode();connection.sendall(struct.pack('>I',len(raw))+raw)
  replies={}
  for _ in range(2):
   reply=json.loads(exact(struct.unpack('>I',exact(4))[0]));replies[reply['id']]=reply
  assert replies['cancel-root']['ok'] and not replies['root-create-cancelled']['ok']
  state=call('host.status')['value'];assert state['rootLocked']
  if state['profileExists']:created=call('root.unlock',dict(pin=fixture['rootPin']))
  else:created=call('profile.create',dict(pin=fixture['rootPin']))
  assert created['rows']==[]
  assert call('account.listAccounts')['rows']==[]
  with sqlite3.connect(profile/'account.sqlite') as db:assert db.execute("SELECT COUNT(*) FROM account_rows WHERE database_name='dm_registry_secure_v1' AND store_name='accounts'").fetchone()[0]==0
  if node:
   call('node.enable',dict(endpoints=[],directEnabled=False));state=call('host.status')['value'];assert state['nodeRunning'] and not state['accountSessionActive'];assert call('account.listAccounts')['rows']==[]
  call('profile.create',dict(pin='replacement-refused'),False)
  # Cancellation is Account-only and must not publish an interrupted derivation.
  for id,method,params in [('create-cancelled','account.create',dict(identity='cancelled-synthetic',password='synthetic-cancel-password')),('cancel','account.cancel',{})]:
   raw=json.dumps(dict(v=1,id=id,method=method,params=params)).encode();connection.sendall(struct.pack('>I',len(raw))+raw)
  replies={}
  for _ in range(2):
   reply=json.loads(exact(struct.unpack('>I',exact(4))[0]));replies[reply['id']]=reply
  assert replies['cancel']['ok'] and not replies['create-cancelled']['ok']
  assert call('account.listAccounts')['rows']==[] and not call('host.status')['value']['rootLocked']
  inputs=dict(identity=fixture['identity'],password=fixture['password'],displayName='Native fresh Account')
  account=call('account.create',inputs)['value'];assert account['created'] and account['accountPublicId']==fixture['accountPublicId']
  call('account.create',dict(inputs,password='different-refused'),False)
  assert len(call('account.listAccounts')['rows'])==1
  logged=call('account.login',dict(identity=fixture['identity'],password=fixture['password']))['value'];assert logged['accountPublicId']==fixture['accountPublicId'] and logged['displayName']==inputs['displayName']
  peer='local:saved-messages:v1';call('account.sendText',dict(peer=peer,operationId='e'*64,text='fresh native Saved'))
  assert len(call('account.history',dict(peer=peer))['rows'])==1
  call('account.logout');state=call('host.status')['value'];assert not state['accountSessionActive'] and not state['rootLocked'] and (not node or state['nodeRunning'])
  call('root.lock');stop();launch();call('root.unlock',dict(pin=fixture['rootPin']));assert len(call('account.listAccounts')['rows'])==1
  call('account.login',dict(identity=fixture['identity'],password=fixture['password']));assert len(call('account.history',dict(peer=peer))['rows'])==1
  call('root.lock');stop()
  # Existing accepted profile with its development key missing is preserved/refused.
  key=profile/'app-local.key';retained=key.read_bytes();key.unlink();launch_failed=subprocess.run([str(host),'--profile',str(profile)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15);assert launch_failed.returncode!=0 and not key.exists()
  key.write_bytes(retained);key.chmod(0o600);launch();call('profile.create',dict(pin='must-not-reset'),False);call('root.unlock',dict(pin=fixture['rootPin']));call('account.login',dict(identity=fixture['identity'],password=fixture['password']));assert len(call('account.history',dict(peer=peer))['rows'])==1;call('root.lock')
  print(json.dumps(dict(ok=True,scope='explicit native fresh Root and optional Account; UI/foreign transit separate',freshRootWithoutAccount=True,nodeBeforeAccount=bool(node),sameAccountAsExistingJsFixture=True,duplicateRefusesOverwrite=True,savedRetainedAfterReopen=True,missingKeyRefusesReset=True)))
 finally:stop()
