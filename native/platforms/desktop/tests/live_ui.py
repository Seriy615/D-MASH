"""Real Widgets clicks against a separate native Node host; synthetic private profile.
Usage: TEST_PYTHON live_ui.py HOST UI_TEST CACHE
This is native/offscreen UI acceptance, not browser or Android/Windows acceptance.
"""
import json, os, pathlib, secrets, socket, subprocess, sys, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'native/tests'))
sys.path.insert(0,str(ROOT/'D-MASH/client'))
from local_ipc_test import send,recv
from nacl.signing import SigningKey
from backend.crypto import NodeCryptoManager
host,ui,cache=sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='widgets-live-',dir=cache) as directory:
 profile=pathlib.Path(directory)/'node';profile.mkdir(mode=0o700)
 key=SigningKey.generate()
 while not NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):key=SigningKey.generate()
 a,b=socket.socketpair();a.settimeout(15)
 with open(pathlib.Path(directory)/'daemon.log','wb') as log:
  child=subprocess.Popen([host,'--profile',str(profile),'--bootstrap-fd',str(b.fileno())],pass_fds=[b.fileno()],stdout=log,stderr=log);b.close()
  try:
   bundle=dict(version=1,nodeSeed=key.encode().hex(),storageKey=secrets.token_hex(32),baseNcrh=secrets.token_hex(32),generation=1,directEnabled=False,endpoints=[])
   send(a,dict(v=1,type='InstallTransportSession',request_id='install',generation=1,effective_policy_revision=1,transport_bundle=bundle,principals=[dict(id='ui',role='owner',ttl_seconds=60)]))
   ready=recv(a);assert ready['type']=='TransportSessionReady'
   cap=ready['capabilities'][0];ui_a,ui_b=socket.socketpair()
   send(ui_a,dict(v=1,endpoint=ready['endpoint'],generation=ready['generation'],role='owner',capability=cap['token'],expiresAt=cap['expiresAt']))
   env={**os.environ,'QT_QPA_PLATFORM':'offscreen','DMASH_UI_SESSION_FD':str(ui_b.fileno())}
   result=subprocess.run([ui,'liveService'],pass_fds=[ui_b.fileno()],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
   ui_a.close();ui_b.close()
   if result.returncode:print(result.stdout.decode());print(result.stderr.decode());raise RuntimeError('Widgets UI actions failed')
   assert child.poll() is None,'UI detach stopped Node'
   a.close();assert child.wait(timeout=10)==0
   print(json.dumps(dict(suite='native-widgets-live-controls',status='PASS',checks=['real-node-host','owner-capability-authentication','visible-node-status','refresh-click','detach-click','UI-close-service-survives','broker-EOF-service-stops'],meshDelivery='NOT RUN',android='NOT RUN',windows='NOT RUN')))
  finally:
   a.close()
   if child.poll() is None:child.terminate();child.wait(timeout=10)
