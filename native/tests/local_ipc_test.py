"""Actual headless actor IPC lifecycle, with synthetic existing scoped material.
No credentials, capabilities, or raw frames are printed. No mesh peer is dialled.
Usage: python local_ipc_test.py HOST SYNTHETIC_BUNDLE CACHE_DIRECTORY
"""
import json, os, pathlib, socket, struct, subprocess, sys, tempfile, time


def send(sock, value):
    data=json.dumps(value,separators=(',',':')).encode()
    sock.sendall(struct.pack('>I',len(data))+data)


def recv(sock):
    def read(n):
        data=b''
        while len(data)<n:
            part=sock.recv(n-len(data))
            if not part: raise EOFError()
            data+=part
        return data
    size=struct.unpack('>I',read(4))[0]
    assert 0<size<=524288
    return json.loads(read(size))


def start(binary, profile, bundle, generation=1, revision=1):
    parent, child=socket.socketpair(); parent.settimeout(10)
    process=subprocess.Popen([binary,'--profile',str(profile),'--bootstrap-fd',str(child.fileno())],pass_fds=[child.fileno()],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.close(); bundle=dict(bundle,generation=generation,endpoints=[])
    send(parent,dict(v=1,type='InstallTransportSession',request_id='install',generation=generation,effective_policy_revision=revision,transport_bundle=bundle,principals=[dict(id='ui',role='owner',ttl_seconds=60),dict(id='broker',role='broker',ttl_seconds=60)]))
    response=recv(parent)
    return process,parent,response


def connect(response, role='owner', token=None):
    s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect(response['endpoint'])
    cap=next(c for c in response['capabilities'] if c['role']==role)
    send(s,dict(v=1,id='auth',method='authenticate',params=dict(generation=response['generation'],capability=token or cap['token'])))
    return s


def request(s, method, params, id='test'):
    send(s,dict(v=1,id=id,method=method,params=params));return recv(s)


def closed(s):
    try:
        assert not s.recv(1)
    except ConnectionResetError: pass
    s.close()


def main():
    binary,bundlefile,cache=sys.argv[1:]
    bundle=json.loads(pathlib.Path(bundlefile).read_text())
    with tempfile.TemporaryDirectory(prefix='ipc-',dir=cache) as temp:
        profile=pathlib.Path(temp)/'node'; profile.mkdir(mode=0o700)
        p,bootstrap,r=start(binary,profile,bundle)
        assert r['type']=='TransportSessionReady'
        endpoint=pathlib.Path(r['endpoint']);assert endpoint.stat().st_mode&0o077==0
        wrong=connect(r,token='0'*64);closed(wrong)
        oversized=socket.socket(socket.AF_UNIX);oversized.settimeout(5);oversized.connect(r['endpoint']);oversized.sendall(struct.pack('>I',65537));closed(oversized)
        invalid=socket.socket(socket.AF_UNIX);invalid.settimeout(5);invalid.connect(r['endpoint']);invalid.sendall(struct.pack('>I',1)+b'\xff');closed(invalid)
        ui=connect(r);assert recv(ui)['ok']
        status=request(ui,'node.status',{});assert status['ok'] and status['result']['initialized'] and status['result']['role']=='NODE' and status['result']['connectedPeers']==0
        assert request(ui,'node.status',{'accountPublic':'0'*64})['ok'] is False
        denied=request(ui,'broker.policy',dict(generation=1,revision=2,transportEnabled=True,directEnabled=False));assert denied['ok'] is False
        absent=request(ui,'job.query',dict(id='0'*64));assert absent['ok'] is False
        ui.close() # UI lifetime does not revoke the broker service lease.
        time.sleep(.1);assert p.poll() is None
        ui=connect(r);assert recv(ui)['ok'];ui.close()
        old=r['capabilities'][0]['token']
        send(bootstrap,dict(v=1,type='MintCapability',request_id='renew',principal='ui',ttl_seconds=60))
        minted=recv(bootstrap);assert minted['type']=='CapabilityMinted'
        stale=connect(r,token=old);closed(stale)
        r['capabilities'][0].update(token=minted['token'],expiresAt=minted['expiresAt'])
        ui=connect(r);assert recv(ui)['ok'];ui.close()
        admin=connect(r,'broker');assert recv(admin)['ok']
        assert request(admin,'broker.policy',dict(generation=1,revision=2,transportEnabled=False,directEnabled=False))['ok']
        assert request(admin,'broker.policy',dict(generation=1,revision=2,transportEnabled=True,directEnabled=False))['ok'] is False
        admin.close();bootstrap.close() # Broker death fences and stops the child.
        assert p.wait(timeout=10)==0
        out,err=p.communicate();assert all(c['token'].encode() not in out+err for c in r['capabilities'])
        p,b,floors=start(binary,profile,bundle)
        assert floors['type']=='STALE_FLOOR' and floors['minTransportGeneration']==2 and floors['minPolicyRevision']==3
        assert p.wait(timeout=10)==1;b.close()
        p,b,r2=start(binary,profile,bundle,3,4)
        assert r2['type']=='TransportSessionReady' and r2['generation']>r['generation']
        stale=connect(r2,token=r['capabilities'][0]['token']);closed(stale)
        admin=connect(r2,'broker');assert recv(admin)['ok']
        result=request(admin,'broker.revoke',dict(generation=3,revision=5,reason='FULL_ROOT_LOCK'))
        assert result['ok'] and result['result']['transportGeneration']==4
        b.close() # Immediate broker close after full-lock ACK must stay idempotent.
        assert p.wait(timeout=10)==0;admin.close()
    print(json.dumps({'suite':'native-local-ipc','status':'PASS','checks':['private-socket','scoped-bounded-node-status','capability-rejection','preparse-length-and-UTF8','role-isolation','owner-required','UI-reconnect-independent-lifetime','broker-private-capability-renewal','policy-revision-fence','broker-EOF-durable-floors','stale-bootstrap-private-floors','restart-stale-capability','explicit-full-lock-ACK'],'meshDelivery':'NOT_RUN'}))


if __name__=='__main__': main()
