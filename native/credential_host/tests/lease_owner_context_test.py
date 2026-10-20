"""Actual owner.register/ACTIVE route grant survives private bounded lease extension."""
import json,os,pathlib,secrets,socket,struct,subprocess,sys,tempfile,time
from nacl.public import PrivateKey
from nacl.signing import SigningKey
ROOT=pathlib.Path(__file__).parents[3];sys.path.insert(0,str(ROOT/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.route_discovery_v4 import issue_certificate
binary=pathlib.Path(sys.argv[1])
def send(s,v):
 raw=json.dumps(v,separators=(',',':')).encode();s.sendall(struct.pack('>I',len(raw))+raw)
def recv(s):
 def exact(n):
  data=b''
  while len(data)<n:
   chunk=s.recv(n-len(data));assert chunk,'unexpected local EOF';data+=chunk
  return data
 return json.loads(exact(struct.unpack('>I',exact(4))[0]))
def request(s,method,params):
 send(s,dict(v=1,id='owner-proof',method=method,params=params));return recv(s)
def checked(s,method,params):
 result=request(s,method,params);assert result['ok'],(method,result.get('code'));return result['result']
with tempfile.TemporaryDirectory(prefix='dmhl-',dir=pathlib.Path.home()/'.cache') as name:
 profile=pathlib.Path(name);profile.chmod(0o700);process=None;parent=None;sockets=[]
 try:
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   node=SigningKey.generate()
   if NodeCryptoManager.verify_node_pow(node.verify_key.encode().hex()):break
  else:raise TimeoutError('synthetic Node identity')
  parent,child=socket.socketpair();parent.settimeout(15)
  process=subprocess.Popen([str(binary),'--profile',str(profile),'--bootstrap-fd',str(child.fileno())],pass_fds=[child.fileno()],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);child.close()
  bundle=dict(version=1,nodeSeed=node.encode().hex(),storageKey=secrets.token_hex(32),baseNcrh=secrets.token_hex(32),generation=1,directEnabled=False,endpoints=[])
  send(parent,dict(v=1,type='InstallTransportSession',request_id='lease-owner-proof',generation=1,effective_policy_revision=1,transport_bundle=bundle,principals=[dict(id='lease-owner',role='owner',ttl_seconds=60),dict(id='lease-broker',role='broker',ttl_seconds=60)]))
  ready=recv(parent);assert ready['features']['capabilityLeaseRenewal']
  def connect(role):
   s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(ready['endpoint']);sockets.append(s)
   token=next(row['token'] for row in ready['capabilities'] if row['role']==role)
   checked(s,'authenticate',dict(generation=ready['generation'],capability=token));return s
  owner=connect('owner');admin=connect('broker')
  account,route,discovery=SigningKey.generate(),SigningKey.generate(),SigningKey.generate();box,recipient=PrivateKey.generate(),PrivateKey.generate();now=int(time.time())
  certificate=issue_certificate(route,discovery.verify_key.encode(),box.public_key.encode(),recipient.public_key.encode(),generation=1,issued_at=now,expires_at=now+3600)
  challenge=checked(owner,'owner.challenge',dict(accountPublic=account.verify_key.encode().hex(),certificate=certificate,archive=False))
  checked(owner,'owner.register',dict(challenge=challenge['challenge'],signature=account.sign(challenge['transcript'].encode()).signature.hex()))
  migration,digest=secrets.token_hex(32),secrets.token_hex(32)
  prepared=checked(owner,'owner.prepare',dict(migrationId=migration,bindingDigest=digest,expectedGeneration=1,certificate=certificate,discoverySeed=discovery.encode().hex(),discoveryBox=box.encode().hex(),recipientKeys=[recipient.encode().hex()]));prepared.pop('state');checked(owner,'owner.activate',dict(tuple=prepared))
  assert checked(owner,'owner.query',dict(migrationId=migration))['state']=='ACTIVE'
  for principal in ['lease-owner','lease-broker']:
   before=next(row for row in ready['capabilities'] if row['id']==principal)
   send(parent,dict(v=1,type='RenewCapabilityLease',request_id=principal,principal=principal,ttl_seconds=3600));lease=recv(parent)
   assert lease['type']=='CapabilityLeaseRenewed' and lease['token']==before['token'] and lease['generation']==ready['generation'] and lease['expiresAt']>=before['expiresAt']
  active=checked(owner,'owner.query',dict(migrationId=migration));assert active['state']=='ACTIVE' and active['bindingDigest']==digest
  destination=checked(owner,'destination.install',dict(certificate=certificate,replyRouteId=certificate['route_id']));assert destination['handle']
  assert checked(admin,'node.status',{})['initialized']
  different=connect('owner');assert not request(different,'owner.query',dict(migrationId=migration))['ok'],'separate caller must not inherit existing owner grant'
  old=next(row for row in ready['capabilities'] if row['role']=='owner')
  send(parent,dict(v=1,type='MintCapability',request_id='rotate',principal=old['id'],ttl_seconds=60));rotated=recv(parent);assert rotated['type']=='CapabilityMinted' and rotated['token']!=old['token']
  try:assert not owner.recv(1),'explicit Mint retains its context invalidation behavior'
  except ConnectionResetError:pass
  print(json.dumps(dict(ok=True,scope='actual daemon owner/register/ACTIVE grant private lease extension',existingOwnerContextAndActiveGrantPreserved=True,existingBrokerContextPreserved=True,sameTokenAndGeneration=True,separateCallerHasNoGrant=True,explicitMintStillRotatesAndDrops=True)))
 finally:
  for s in sockets:s.close()
  if parent:parent.close()
  if process:
   try:process.wait(10)
   except subprocess.TimeoutExpired:process.kill();process.wait(10)
