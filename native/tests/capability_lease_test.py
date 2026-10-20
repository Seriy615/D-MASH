"""Real-clock lease extension preserves a registered Account owner connection.
Usage: python capability_lease_test.py HOST PRIVATE_CACHE
"""
import json,os,pathlib,secrets,socket,subprocess,sys,tempfile,time
from ipc_delivery_test import mine,material,register,checked
from local_ipc_test import send,recv,connect

def main():
    binary,cache=sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix='lease-',dir=cache) as folder:
        os.chmod(folder,0o700);profile=pathlib.Path(folder)/'node';profile.mkdir(mode=0o700)
        key=mine();a,b=socket.socketpair();a.settimeout(15)
        with open(pathlib.Path(folder)/'actor.log','wb') as log:
            os.chmod(log.name,0o600)
            p=subprocess.Popen([binary,'--profile',str(profile),'--bootstrap-fd',str(b.fileno())],pass_fds=[b.fileno()],stdout=log,stderr=log);b.close()
            try:
                bundle=dict(version=1,nodeSeed=key.encode().hex(),storageKey=secrets.token_hex(32),baseNcrh=secrets.token_hex(32),generation=1,directEnabled=False,endpoints=[])
                send(a,dict(v=1,type='InstallTransportSession',request_id='install',generation=1,effective_policy_revision=1,transport_bundle=bundle,principals=[dict(id='ui',role='owner',ttl_seconds=10),dict(id='broker',role='broker',ttl_seconds=60)]))
                ready=recv(a);assert ready['type']=='TransportSessionReady' and ready['features']['capabilityLeaseRenewal']
                original=ready['capabilities'][0];m=material();owner=connect(ready);assert recv(owner)['ok'];register(owner,m['account'],m['cert'])
                migration=secrets.token_hex(32)
                prepared=checked(owner,'owner.prepare',dict(migrationId=migration,bindingDigest=secrets.token_hex(32),expectedGeneration=1,certificate=m['cert'],discoverySeed=m['discovery'].encode().hex(),discoveryBox=m['box'].encode().hex(),recipientKeys=[m['recipient'].encode().hex()]))
                prepared.pop('state');checked(owner,'owner.activate',dict(tuple=prepared))
                before=checked(owner,'owner.query',dict(migrationId=migration))
                send(a,dict(v=1,type='RenewCapabilityLease',request_id='extend',principal='ui',ttl_seconds=30));renewed=recv(a)
                assert renewed['type']=='CapabilityLeaseRenewed' and renewed['token']==original['token'] and renewed['id']==original['id'] and renewed['generation']==ready['generation']
                assert renewed['expiresAt']>original['expiresAt']
                time.sleep(max(0,(original['expiresAt']-time.time()*1000)/1000)+.6)
                assert checked(owner,'node.status',{})['initialized']
                assert checked(owner,'owner.query',dict(migrationId=migration))==before # Same registered context, no new challenge/register.
                fresh=connect(ready);assert recv(fresh)['ok'];assert checked(fresh,'node.status',{})['initialized'];fresh.close();owner.close()
                a.close();assert p.wait(timeout=10)==0
            finally:
                a.close()
                if p.poll() is None:p.terminate();p.wait(timeout=10)
    print(json.dumps(dict(suite='native-capability-lease-real-expiry',status='PASS',checks=['short-initial-TTL10','real-clock-past-original-expiry','same-token-principal-generation','same-authenticated-registered-owner-context','initialized-Node','fresh-authentication-after-original-expiry','broker-EOF-exit'])))
if __name__=='__main__':main()
