"""Own retained synthetic Account: actual Node pause keeps Root/Account/Saved live."""
import contextlib,json,os,pathlib,shutil,socket,struct,subprocess,sys,tempfile,time
host,node=map(pathlib.Path,sys.argv[1:3]);fixture=json.loads((pathlib.Path(__file__).parents[2]/'account/tests/account_profile.json').read_text())
@contextlib.contextmanager
def ownProfile():
 path=pathlib.Path(tempfile.mkdtemp(prefix='dmpause-',dir=pathlib.Path.home()/'.cache'));path.chmod(0o700)
 try:yield path
 except BaseException:print(json.dumps(dict(preservedSyntheticProfile=str(path))),file=sys.stderr);raise
 else:shutil.rmtree(path)
with ownProfile() as profile:
 owner=None;s=None
 def connect():
  global s
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   try:s=socket.socket(socket.AF_UNIX);s.settimeout(180);s.connect(json.loads((profile/'credential-endpoint.json').read_text())['endpoint']);return
   except (OSError,ValueError):s.close();time.sleep(.03)
  raise TimeoutError('owner endpoint')
 def call(method,expect_ok=True,**params):
  raw=json.dumps(dict(v=1,id='pause',method=method,params=params)).encode();s.sendall(struct.pack('>I',len(raw))+raw)
  def exact(n):
   b=b''
   while len(b)<n:
    part=s.recv(n-len(b));assert part;b+=part
   return b
  reply=json.loads(exact(struct.unpack('>I',exact(4))[0]));assert reply['ok']==expect_ok,(method,reply.get('code'));return reply['result'] if expect_ok else reply
 def receipt():return json.loads((profile/'node/supervisor-child.json').read_text())
 try:
  owned_node=profile/'test-node-host';shutil.copy2(node,owned_node);owned_node.chmod(0o700)
  with os.fdopen(os.open(profile/'owner.stderr',os.O_WRONLY|os.O_CREAT,0o600),'ab') as log:owner=subprocess.Popen([str(host),'--profile',str(profile),'--node-host',str(owned_node)],stdout=subprocess.DEVNULL,stderr=log)
  connect();package=fixture['profile'];known=json.loads(pathlib.Path(__file__).with_name('crash_node_material.json').read_text());package['root']['materials']['node-ed25519-pow-v4']=known['material']
  call('profile.import',profile=package,pin=fixture['rootPin']);call('account.login',identity=fixture['identity'],password=fixture['password']);call('node.enable',endpoints=[],directEnabled=False);first=receipt()
  call('node.pause');state=call('host.status')['value'];assert not state['nodeRunning'] and not state['rootLocked'] and state['nodeState']=='paused' and state['accountSessionActive']
  try:assert (pathlib.Path('/proc')/str(first['pid'])/'stat').read_text().split(') ')[1][0]=='Z'
  except FileNotFoundError:pass
  assert call('account.listAccounts')['rows'][0]['accountPublicId']==fixture['accountPublicId']
  call('account.sendText',peer='local:saved-messages:v1',operationId='f'*64,text='Saved during actual Node pause')
  assert len(call('account.history',peer='local:saved-messages:v1')['rows'])==2
  s.close();s=None;connect();assert call('host.status')['value']['accountSessionActive']
  call('node.pause')
  # Failed resume is a transport error; the retained Root/Account remain usable.
  hidden=profile/'test-node-host-held';owned_node.rename(hidden)
  error=call('node.enable',expect_ok=False);assert error['code']=='NODE_HOST_UNAVAILABLE'
  state=call('host.status')['value'];assert not state['rootLocked'] and state['accountSessionActive'] and not state['nodeRunning']
  assert call('account.listAccounts')['rows'][0]['accountPublicId']==fixture['accountPublicId']
  hidden.rename(owned_node);call('node.enable');second=receipt();assert second['nodeId']==first['nodeId']==known['nodeId'] and second['deviceId']==first['deviceId'] and second['generation']>first['generation']
  state=call('host.status')['value'];assert state['node']['initialized'] and state['accountSessionActive'] and not state['rootLocked']
  assert len(call('account.history',peer='local:saved-messages:v1')['rows'])==2
  call('account.logout');state=call('host.status')['value'];assert state['nodeRunning'] and not state['rootLocked'] and not state['accountSessionActive']
  call('account.login',identity=fixture['identity'],password=fixture['password']);call('node.disable');state=call('host.status')['value'];assert state['rootLocked'] and not state['accountSessionActive'] and not state['nodeRunning'],'old Stop Node & lock alias must retain full lock behavior'
  print(json.dumps(dict(ok=True,scope='actual retained native owner pause; remote queuedjob separate',rootAndAccountRemainCurrent=True,actualChildExited=True,failedResumePreservesRootAndAccount=True,savedRows=2,resumeWithoutPINOrLogin=True,sameNodeAndRoot=True,accountLogoutPreservesNode=True,legacyDisableStillFullLock=True,generations=[first['generation'],second['generation']])))
 finally:
  if s:s.close()
  if owner and owner.poll() is None:owner.terminate();owner.wait(20)
