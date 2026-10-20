"""Two actual credential clients, synthetic Accounts and retained Saved histories.
No Node, mesh or UI acceptance. All profiles/logs are retained privately.
"""
import hashlib,json,os,pathlib,secrets,socket,struct,subprocess,sys,tempfile,time
host,cache=sys.argv[1:]
fixture_path=pathlib.Path(__file__).parents[2]/'account/tests/account_profile.json'
source_hash=hashlib.sha256(fixture_path.read_bytes()).hexdigest();fixture=json.loads(fixture_path.read_text())
folder=pathlib.Path(tempfile.mkdtemp(prefix='client-binding-',dir=cache));folder.chmod(0o700)
profile=folder/'owner';profile.mkdir(mode=0o700);owner=log=None;clients=[]
inputs=dict(identity='second-'+secrets.token_hex(12),password=secrets.token_hex(32),displayName='Second synthetic Account')
private=folder/'inputs.json';private.write_text(json.dumps(inputs));private.chmod(0o600)
def launch():
 global owner,log
 log=os.fdopen(os.open(folder/'owner.log',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),'ab',buffering=0)
 owner=subprocess.Popen([host,'--profile',str(profile)],stdout=log,stderr=log)
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  try:return connect()
  except (OSError,ValueError):
   assert owner.poll() is None;time.sleep(.03)
 raise TimeoutError('owner locator')
def connect():
 locator=json.loads((profile/'credential-endpoint.json').read_text());c=socket.socket(socket.AF_UNIX);c.settimeout(240);c.connect(locator['endpoint']);clients.append(c);return c
def send(c,method,params=None,id='probe'):
 raw=json.dumps(dict(v=1,id=id,method=method,params=params or {})).encode();c.sendall(struct.pack('>I',len(raw))+raw)
def receive(c):
 def exact(n):
  data=b''
  while len(data)<n:
   part=c.recv(n-len(data));assert part;data+=part
  return data
 return json.loads(exact(struct.unpack('>I',exact(4))[0]))
def call(c,method,params=None,ok=True):
 send(c,method,params);reply=receive(c);assert reply['ok']==ok,(method,reply.get('code'));return reply['result'] if ok else reply
saved='local:saved-messages:v1'
def history(c):return call(c,'account.history',dict(peer=saved))['rows']
def login(c,second=False):
 args=inputs if second else fixture
 return call(c,'account.login',dict(identity=args['identity'],password=args['password']))['value']
def stop():
 global owner,log
 for c in clients:
  try:c.close()
  except OSError:pass
 clients.clear()
 if owner and owner.poll() is None:owner.terminate();assert owner.wait(15)==0
 owner=None
 if log:log.close();log=None
try:
 first=launch();second=connect()
 call(first,'profile.import',dict(profile=fixture['profile'],pin=fixture['rootPin']))
 assert call(second,'account.history',dict(peer=saved),False)['code']=='ACCOUNT_CONTEXT_REQUIRED'
 a=login(first);assert a['accountPublicId']==fixture['accountPublicId'] and a['sessionEpoch']>0
 assert len(history(first))==1
 call(second,'account.create',inputs);b=login(second,True);assert b['accountPublicId']!=a['accountPublicId'] and b['sessionEpoch']!=a['sessionEpoch'];assert history(second)==[]
 for method,params in [('account.history',dict(peer=saved)),('account.contacts',{}),('account.sync',{}),('account.sendText',dict(peer=saved,operationId='a'*64,text='must never enter another Account')),('account.logout',{}),('account.pairingOffers',{})]:
  assert call(first,method,params,False)['code']=='ACCOUNT_SESSION_CHANGED'
 # Same-socket immediate Cancel of a stale queued read must not cancel B.
 send(first,'account.history',dict(peer=saved),'stale-read');send(first,'account.cancel',{},'stale-cancel')
 replies=[receive(first),receive(first)];assert {r['id'] for r in replies}=={'stale-read','stale-cancel'} and all(not r['ok'] for r in replies)
 state=call(second,'host.status')['value'];assert state['accountSessionActive'] and state['account']['accountPublicId']==b['accountPublicId']
 third=connect();assert call(third,'account.contacts',ok=False)['code']=='ACCOUNT_CONTEXT_REQUIRED'
 assert call(third,'account.attach',dict(accountPublicId=a['accountPublicId']),False)['code']=='ACCOUNT_SESSION_CHANGED'
 attached=call(third,'account.attach',dict(accountPublicId=b['accountPublicId']))['value'];assert attached['accountPublicId']==b['accountPublicId'] and attached['sessionEpoch']==b['sessionEpoch']
 call(third,'account.sendText',dict(peer=saved,operationId='b'*64,text='only second Account'));assert len(history(second))==1
 b_again=login(second,True);assert b_again['sessionEpoch']!=b['sessionEpoch']
 assert call(third,'account.history',dict(peer=saved),False)['code']=='ACCOUNT_SESSION_CHANGED'
 # Another window cannot cancel this window's in-flight Account selection.
 send(second,'account.login',dict(identity=inputs['identity'],password=inputs['password']),'own-login')
 # The host globally serializes jobs. Observe selection started before injecting
 # another socket's cancel, so an earlier cancel cannot win the job slot itself.
 deadline=time.monotonic()+5
 while call(third,'host.status')['value']['accountSessionActive']:
  assert time.monotonic()<deadline
  time.sleep(.01)
 send(first,'account.cancel',{},'foreign-cancel')
 foreign=receive(first);selected=receive(second)
 assert not foreign['ok'],foreign.get('code');assert selected['ok'],selected.get('code');assert len(history(second))==1
 login(second);assert call(first,'account.history',dict(peer=saved),False)['code']=='ACCOUNT_SESSION_CHANGED'
 attached_a=call(first,'account.attach',dict(accountPublicId=a['accountPublicId']))['value'];assert attached_a['sessionEpoch']!=a['sessionEpoch'];assert len(history(first))==1
 assert call(third,'account.attach',dict(accountPublicId=b['accountPublicId']),False)['code']=='ACCOUNT_SESSION_CHANGED'
 call(second,'account.logout');assert call(first,'account.history',dict(peer=saved),False)['code']=='ACCOUNT_SESSION_CHANGED'
 stop();first=launch();call(first,'root.unlock',dict(pin=fixture['rootPin']));assert call(first,'account.contacts',ok=False)['code']=='ACCOUNT_CONTEXT_REQUIRED';login(first,True);assert len(history(first))==1
 login(first);assert len(history(first))==1;call(first,'root.lock');stop()
 assert hashlib.sha256(fixture_path.read_bytes()).hexdigest()==source_hash
 print(json.dumps(dict(status='PASS',scope='actual two-client credential IPC; no UI/mesh',checks=['unbound selected-Account RPC rejected','worker binding rejects old Account read/write/logout/sync/pairing','stale pending Cancel cannot cancel new Account','explicit exact expected Account attach','same Account relogin invalidates old epoch','foreign window cannot cancel pending login','logout invalidates other attached client','separate Saved histories retained after owner restart','source fixture unchanged'],privateDirectory=folder.name)))
except BaseException as error:
 p=folder/'failure.json';p.write_text(json.dumps(dict(errorClass=type(error).__name__)));p.chmod(0o600);raise
finally:stop()
