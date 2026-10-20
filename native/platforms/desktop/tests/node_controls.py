"""Real Qt Start/Stop/connection controls against an actual separate Node child."""
import argparse,json,os,pathlib,subprocess,tempfile,time
p=argparse.ArgumentParser();p.add_argument('ui_test',type=pathlib.Path);p.add_argument('credential_host',type=pathlib.Path);p.add_argument('node_host',type=pathlib.Path);p.add_argument('--report',type=pathlib.Path);a=p.parse_args()
cache=pathlib.Path.home()/'.cache/dmash-native-20261020';private=pathlib.Path(tempfile.mkdtemp(prefix='ui-node-controls-',dir=cache));private.chmod(0o700)
env=os.environ.copy();mode='Caller-provided profile, unchanged'
if 'DMASH_ACCOUNT_UI_FIXTURE' not in env:
 fixture=json.loads((pathlib.Path(__file__).parents[3]/'account/tests/account_profile.json').read_text())
 # Build a fresh synthetic Node fixture BEFORE import, never modify accepted state.
 for slot in ['node-ed25519-pow-v4','node-base-ncrh-v4']:fixture['profile']['root']['materials'].pop(slot,None)
 fixture_path=private/'fresh-node-fixture.json';fixture_path.write_text(json.dumps(fixture));fixture_path.chmod(0o600);env['DMASH_ACCOUNT_UI_FIXTURE']=str(fixture_path);mode='Fresh synthetic Node; same synthetic Account and original Saved history'
env.update(QT_QPA_PLATFORM='offscreen',DMASH_UI_NODE_CONTROLS='1',DMASH_UI_CREDENTIAL_HOST=str(a.credential_host.resolve()),DMASH_UI_NODE_HOST=str(a.node_host.resolve()))
started=time.monotonic()
failure=None
try:
 with (private/'controls.log').open('wb') as log:run=subprocess.run([str(a.ui_test.resolve()),'accountRoundtrip'],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240)
 code=run.returncode
except subprocess.TimeoutExpired:
 code=124;failure='TimeoutExpired'
result={'kind':'Actual Linux Qt mouse/key Node control acceptance','status':'PASS' if code==0 else 'FAIL','seconds':round(time.monotonic()-started,3),'fixture':mode,'checks':['Connections Add/invalid Start/error/Remove/direct checkbox/Cancel','Visible Start Node button creates actual scoped native Node child','Actual host.status refresh shows zero connected peers','Account sign out leaves actual Node running','Visible Stop Node & lock confirms Node stopped and Device unlock required','Root unlock/relogin retains Saved write'],'limits':['No mesh endpoint configured; no remote chat proof','No Android or Windows runtime claim']}
if code:result['intendedChecks']=result.pop('checks');result['checks']=[]
if failure:result['failureClass']=failure
if a.report:a.report.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
if code:raise SystemExit(code)
