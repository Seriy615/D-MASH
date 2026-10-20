"""Kill the actual Qt UI process after real Account clicks; verify resident Node.

Synthetic imported profile only by default. Credentials never enter Node or report.
"""
import argparse,json,os,pathlib,signal,socket,struct,subprocess,tempfile,time
p=argparse.ArgumentParser();p.add_argument('ui_test',type=pathlib.Path);p.add_argument('node_host',type=pathlib.Path);p.add_argument('--report',type=pathlib.Path);a=p.parse_args()
cache=pathlib.Path.home()/'.cache/dmash-native-20261020';private=pathlib.Path(tempfile.mkdtemp(prefix='ui-resident-life-',dir=cache));os.chmod(private,0o700)
ready=private/'ready.json';env=os.environ.copy();fixture_mode='Caller-provided complete profile; no identity changes'
if 'DMASH_ACCOUNT_UI_FIXTURE' not in env:
 # Construct a fresh synthetic Node fixture BEFORE import. The legacy test slots
 # have invalid default22 PoW. Accepted/imported profiles are never rewritten.
 fixture=json.loads((pathlib.Path(__file__).parents[3]/'account/tests/account_profile.json').read_text())
 for slot in ['node-ed25519-pow-v4','node-base-ncrh-v4']:fixture['profile']['root']['materials'].pop(slot,None)
 fixture_path=private/'fresh-node-fixture.json';fixture_path.write_text(json.dumps(fixture));fixture_path.chmod(0o600)
 env['DMASH_ACCOUNT_UI_FIXTURE']=str(fixture_path);fixture_mode='Fresh synthetic Node provisioned before first enable; same synthetic Account/history retained'
env.update(QT_QPA_PLATFORM='offscreen',DMASH_UI_LIFETIME_READY=str(ready),DMASH_UI_NODE_HOST=str(a.node_host.resolve()))
ui=subprocess.Popen([str(a.ui_test.resolve()),'accountRoundtrip'],env=env,stdout=(private/'ui.log').open('wb'),stderr=subprocess.STDOUT)
host_pid=None;profile=None
checks=[]
def wait(predicate,seconds,label):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  if predicate():return
  time.sleep(.05)
 raise RuntimeError(label)
def rpc(method,params=None,timeout=180):
 locator=json.loads((profile/'credential-endpoint.json').read_text());channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);channel.settimeout(timeout)
 try:
  channel.connect(locator['endpoint']);body=json.dumps({'v':1,'id':'lifecycle-proof','method':method,'params':params or {}}).encode();channel.sendall(struct.pack('>I',len(body))+body)
  def exact(length):
   data=b''
   while len(data)<length:
    block=channel.recv(length-len(data))
    if not block:raise RuntimeError('credential host EOF')
    data+=block
   return data
  length=struct.unpack('>I',exact(4))[0]
  if not 0<length<=128*1024*1024:raise RuntimeError('credential host frame')
  reply=json.loads(exact(length))
  if not reply.get('ok'):raise RuntimeError(method+': '+reply.get('code','UNKNOWN'))
  return reply['result'].get('value',{})
 finally:channel.close()
try:
 wait(lambda:ready.exists() or ui.poll() is not None,90,'real UI flow did not finish')
 if ui.poll() is not None:raise RuntimeError('real Account UI exited before lifecycle checkpoint')
 handoff=json.loads(ready.read_text());host_pid=int(handoff['hostPid']);profile=pathlib.Path(handoff['profileDirectory'])
 assert handoff['uiPid']==ui.pid
 before=rpc('host.status');assert before['accountSessionActive'] and not before['rootLocked'];checks.append('Actual Qt Account import/login/Saved send clicks reached resident host')
 enabled=rpc('node.enable',{'endpoints':[],'directEnabled':False});assert enabled['nodeRunning'];checks.append('Actual scoped Node child started; no mesh endpoint configured')
 ui.kill();ui.wait(timeout=5);assert ui.returncode==-signal.SIGKILL;checks.append('Actual UI process killed with SIGKILL')
 after=rpc('host.status');assert after['nodeRunning'] and after['accountSessionActive'];checks.append('Resident credential host and real Node remain running after UI process death')
 locked=rpc('root.lock');assert not locked['nodeRunning'] and locked['rootLocked'];checks.append('Explicit Root lock confirms owned Node stopped')
 result={'kind':'Linux real native process lifetime proof after actual Qt UI actions','status':'PASS','fixture':fixture_mode,'nodeEnableAction':'Harness authenticated local IPC, not a UI button in this checkpoint','checks':checks,'limits':['Synthetic imported Account only','No configured mesh endpoints or remote message delivery in this gate','Does not prove Android or Windows runtime']}
 if a.report:a.report.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
finally:
 if ui.poll() is None:ui.kill();ui.wait(timeout=5)
 if host_pid:
  try:os.kill(host_pid,signal.SIGTERM)
  except ProcessLookupError:pass
 # Retain private test profile/log for independent inspection; never touch source profile.
