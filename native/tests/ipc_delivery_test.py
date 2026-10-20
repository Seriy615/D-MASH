"""Real native sender -> unchanged Python transit -> native durable Inbox.
Synthetic private inputs remain in temporary profiles/pipes; output is metadata only.
Usage: python ipc_delivery_test.py HOST CACHE_DIRECTORY
"""
import asyncio, contextlib, hashlib, json, os, pathlib, secrets, shutil, signal, socket, subprocess, sys, tempfile, time
from local_ipc_test import send, recv, connect, request
from nacl.signing import SigningKey
from nacl.public import PrivateKey
import uvicorn
from fastapi import FastAPI
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.resource_pow import activation_pow_difficulty
from backend.route_discovery_v4 import issue_certificate
from backend.recipient_payload_v4 import seal_payload


def mine():
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        key=SigningKey.generate()
        if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):return key
    raise TimeoutError('synthetic identity work')


def material():
    account,route,discovery=SigningKey.generate(),SigningKey.generate(),SigningKey.generate()
    box,recipient=PrivateKey.generate(),PrivateKey.generate();now=int(time.time())
    cert=issue_certificate(route,discovery.verify_key.encode(),box.public_key.encode(),recipient.public_key.encode(),generation=1,issued_at=now,expires_at=now+3600)
    return dict(account=account,discovery=discovery,box=box,recipient=recipient,cert=cert)


RPC_TIMINGS=[]
def checked(s,method,params):
    
    started=time.monotonic()
    try:value=request(s,method,params)
    except TimeoutError as exc:raise TimeoutError('local RPC timeout: '+method) from exc
    finally:RPC_TIMINGS.append(dict(method=method,elapsedMs=round((time.monotonic()-started)*1000)))
    assert value['ok'],(method,value)
    return value['result']


def register(s,account,cert):
    proof=checked(s,'owner.challenge',dict(accountPublic=account.verify_key.encode().hex(),certificate=cert,archive=False))
    checked(s,'owner.register',dict(challenge=proof['challenge'],signature=account.sign(proof['transcript'].encode()).signature.hex()))


def bind(r,m):
    s=connect(r);assert recv(s)['ok'];register(s,m['account'],m['cert'])
    prepared=checked(s,'owner.prepare',dict(migrationId=secrets.token_hex(32),bindingDigest=secrets.token_hex(32),expectedGeneration=1,certificate=m['cert'],discoverySeed=m['discovery'].encode().hex(),discoveryBox=m['box'].encode().hex(),recipientKeys=[m['recipient'].encode().hex()]))
    prepared.pop('state');checked(s,'owner.activate',dict(tuple=prepared));return s


def child():
    data=json.load(sys.stdin);r=data['ready'];s=connect(r);assert recv(s)['ok']
    register(s,SigningKey(bytes.fromhex(data['account'])),data['certificate'])
    result=checked(s,'job.submit',data['job']);print(json.dumps(result),flush=True)
    # Parent kills this UI process after the durable ACCEPTED reply.
    while True:time.sleep(1)


async def main():
    binary,cache=sys.argv[1:];processes=[];boots=[];logs=[];ui=None
    with (contextlib.nullcontext(tempfile.mkdtemp(prefix='delivery-',dir=cache)) if os.environ.get('DMASH_KEEP_TEST_PROFILE')=='1' else tempfile.TemporaryDirectory(prefix='delivery-',dir=cache)) as name:
        base=pathlib.Path(name);os.chmod(base,0o700)
        peer,sender,recipient=await asyncio.to_thread(lambda:tuple(mine() for _ in range(3)))
        service=NodeServiceV4(peer,base/'transit');assert service.listener.difficulty is None and activation_pow_difficulty()==22
        app=FastAPI();app.state.node_v4=service;app.include_router(router)
        listener=socket.socket();listener.bind(('127.0.0.1',0))
        server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16))
        delay=int(os.environ.get('DMASH_TEST_PEER_DELAY_SECONDS','0'));assert 0<=delay<=90
        async def serve():
            if delay:await asyncio.sleep(delay)
            await server.serve(sockets=[listener])
        running=asyncio.create_task(serve())
        if not delay:
            while not server.started:await asyncio.sleep(.01)
        port=listener.getsockname()[1]
        def start(key,label,bundle=None,revision=1):
            profile=base/label;profile.mkdir(mode=0o700,exist_ok=True)
            if bundle is None:bundle=dict(version=1,nodeSeed=key.encode().hex(),storageKey=secrets.token_hex(32),baseNcrh=secrets.token_hex(32),generation=1,directEnabled=False,endpoints=[dict(url=f'ws://127.0.0.1:{port}/mesh/v4',nodeId=peer.verify_key.encode().hex())])
            a,b=socket.socketpair();a.settimeout(15);log=os.fdopen(os.open(base/(label+'.log'),os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),'ab',buffering=0);logs.append(log)
            p=subprocess.Popen([binary,'--profile',str(profile),'--bootstrap-fd',str(b.fileno())],pass_fds=[b.fileno()],stdout=log,stderr=log);b.close();processes.append(p);boots.append(a)
            send(a,dict(v=1,type='InstallTransportSession',request_id='install',generation=1,effective_policy_revision=revision,transport_bundle=bundle,principals=[dict(id='ui',role='owner',ttl_seconds=600),dict(id='broker',role='broker',ttl_seconds=600)]));r=recv(a);assert r['type']=='TransportSessionReady';return p,a,r,bundle
        try:
            sp,sb,sr,bundle=await asyncio.to_thread(start,sender,'sender')
            rp,rb,rr,recipient_bundle=await asyncio.to_thread(start,recipient,'recipient')
            sm,rm=material(),material()
            sc=await asyncio.to_thread(bind,sr,sm);rc=await asyncio.to_thread(bind,rr,rm)
            dest=await asyncio.to_thread(checked,sc,'destination.install',dict(certificate=rm['cert'],replyRouteId=sm['cert']['route_id']))
            admin=connect(sr,'broker');assert recv(admin)['ok']
            await asyncio.to_thread(checked,admin,'broker.policy',dict(generation=1,revision=2,transportEnabled=False,directEnabled=False))
            payload='opaque-account-ciphertext-fixture-'+secrets.token_hex(16)
            job=dict(destination=dest['handle'],operationId='one-application-intent',blob=seal_payload(rm['recipient'].public_key.encode(),payload),expiresAt=int(time.time()*1000)+180000)
            ui=subprocess.Popen([sys.executable,__file__,'--ui-child'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            ui.stdin.write(json.dumps(dict(ready=sr,account=sm['account'].encode().hex(),certificate=sm['cert'],job=job)));ui.stdin.close()
            accepted=json.loads(await asyncio.wait_for(asyncio.to_thread(ui.stdout.readline),20));assert accepted['accepted'] and accepted['state']=='BLOCKED_POLICY';ui.kill();assert await asyncio.to_thread(ui.wait)==-signal.SIGKILL
            sc.close() # All sender UI/Account local connections are now gone.
            assert service.runtime.stats.get('forwarded',0)==0
            # Hard process death while accepted and blocked: retained policy and
            # exact opaque bytes resume only with a newer authorized boot policy.
            admin.close();sp.kill();assert await asyncio.to_thread(sp.wait)==-signal.SIGKILL;sb.close()
            sp,sb,sr,_=await asyncio.to_thread(start,sender,'sender',bundle,3)
            probe=connect(sr);assert recv(probe)['ok'];await asyncio.to_thread(register,probe,sm['account'],sm['cert'])
            retained=await asyncio.to_thread(checked,probe,'job.query',dict(id=accepted['id']));assert retained['id']==accepted['id'] and retained['state'] in {'BLOCKED_POLICY','WAITING_BOOTSTRAP','WAITING_PATH','IN_FLIGHT','TRANSPORT_SENT'}
            retry=await asyncio.to_thread(checked,probe,'job.submit',job);assert retry['id']==accepted['id'];probe.close()
            admin=connect(sr,'broker');assert recv(admin)['ok']
            await asyncio.to_thread(checked,admin,'broker.policy',dict(generation=1,revision=4,transportEnabled=True,directEnabled=False));admin.close()
            deadline=time.monotonic()+180;records=[]
            while time.monotonic()<deadline:
                listing=await asyncio.to_thread(checked,rc,'inbox.list',dict(limit=128,after=None));records=listing['records']
                if records:break
                assert sp.poll() is None and rp.poll() is None
                await asyncio.sleep(.25)
            assert len(records)==1 and records[0]['payload']==payload,'recipient durable Inbox not reached'
            sc=await asyncio.to_thread(lambda:connect(sr));assert recv(sc)['ok'];await asyncio.to_thread(register,sc,sm['account'],sm['cert'])
            status=await asyncio.to_thread(checked,sc,'job.query',dict(id=accepted['id']));assert status['state']=='TRANSPORT_SENT'
            same=await asyncio.to_thread(checked,sc,'job.submit',job);assert same['id']==accepted['id']
            changed=dict(job,blob=seal_payload(rm['recipient'].public_key.encode(),payload+'changed'));assert (await asyncio.to_thread(request,sc,'job.submit',changed))['ok'] is False
            duplicate=dict(job,operationId='second-intent-same-packet')
            second=await asyncio.to_thread(checked,sc,'job.submit',duplicate)
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                state=await asyncio.to_thread(checked,sc,'job.query',dict(id=second['id']))
                if state['state']=='TRANSPORT_SENT':break
                await asyncio.sleep(.25)
            assert state['state']=='TRANSPORT_SENT'
            # Sender restart retains identity, binding, accepted job and old bytes.
            sc.close();sp.terminate();assert await asyncio.to_thread(sp.wait,10)==0;sb.close()
            sp,sb,sr,_=await asyncio.to_thread(start,sender,'sender',bundle,4)
            sc=connect(sr);assert recv(sc)['ok'];await asyncio.to_thread(register,sc,sm['account'],sm['cert'])
            retained=await asyncio.to_thread(checked,sc,'job.query',dict(id=accepted['id']));assert retained['state']=='TRANSPORT_SENT' and retained['id']==accepted['id']
            await asyncio.sleep(1);again=await asyncio.to_thread(checked,rc,'inbox.list',dict(limit=128,after=None));assert len(again['records'])==1
            sc.close();rc.close()
            # Process reopen proves durable Inbox and packet dedupe metadata,
            # rather than reading the original recipient process's cache.
            rp.kill();assert await asyncio.to_thread(rp.wait)==-signal.SIGKILL;rb.close()
            rp,rb,rr,_=await asyncio.to_thread(start,recipient,'recipient',recipient_bundle,1)
            rc=connect(rr);assert recv(rc)['ok'];await asyncio.to_thread(register,rc,rm['account'],rm['cert'])
            durable=await asyncio.to_thread(checked,rc,'inbox.list',dict(limit=128,after=None));assert len(durable['records'])==1 and durable['records'][0]['payload']==payload
            assert durable['records'][0]['handle']==records[0]['handle']
            # Application storage commits first; this API consumes only the
            # opaque Inbox record and keeps the application token atomically.
            commit=dict(recordHandle=records[0]['handle'],applicationCommitToken='application-durable-message-operation')
            assert (await asyncio.to_thread(request,rc,'inbox.commitConsumption',dict(commit,applicationCommitToken='bad token')))['ok'] is False
            consumed=await asyncio.to_thread(checked,rc,'inbox.commitConsumption',commit);assert consumed['committed']
            assert await asyncio.to_thread(checked,rc,'inbox.commitConsumption',commit)==consumed
            conflict=dict(commit,applicationCommitToken='another-application-operation');assert (await asyncio.to_thread(request,rc,'inbox.commitConsumption',conflict))['ok'] is False
            assert not (await asyncio.to_thread(checked,rc,'inbox.list',dict(limit=128,after=None)))['records'];rc.close()
            rp.kill();assert await asyncio.to_thread(rp.wait)==-signal.SIGKILL;rb.close()
            rp,rb,rr,_=await asyncio.to_thread(start,recipient,'recipient',recipient_bundle,1)
            rc=connect(rr);assert recv(rc)['ok'];await asyncio.to_thread(register,rc,rm['account'],rm['cert'])
            assert await asyncio.to_thread(checked,rc,'inbox.commitConsumption',commit)==consumed
            assert not (await asyncio.to_thread(checked,rc,'inbox.list',dict(limit=128,after=None)))['records'];rc.close()
            print(json.dumps(dict(suite='native-real-job-delivery',status='PASS',admissionDifficulty=22,wireRole='NODE',checks=['Account-proof-managed-bindings','durable-ACCEPTED','policy-blocked-accept-UI-SIGKILL-then-resume','unchanged-discovery-transit-batching','recipient-durable-Inbox','transport-sent-only','identical-submit-dedupe','changed-bytes-conflict','sender-SIGKILL-before-send-retained-accepted-job','sender-restart-retained-job','recipient-packet-id-dedupe','recipient-SIGKILL-reopen-same-Inbox-record','atomic-app-commit-token-consumption','consumption-idempotent-conflict-reopen'],peerStartupDelaySeconds=delay,backendForwarded=service.runtime.stats.get('forwarded'),payloadDigest=hashlib.sha256(payload.encode()).hexdigest(),limitations=['ACK-free recipient crash window unchanged','Windows/Android runtime NOT_RUN'])),flush=True)
        except BaseException as exc:
            # Retain only private diagnostics before synthetic profile cleanup.
            # Public stdout never includes capabilities, profile rows or raw RPCs.
            failure=pathlib.Path(tempfile.mkdtemp(prefix='delivery-failure-',dir=cache));failure.chmod(0o700)
            hashes={}
            for log in logs:
                log.flush();source=pathlib.Path(log.name) if isinstance(log.name,str) else None
                if source and source.exists():
                    target=failure/source.name;shutil.copyfile(source,target);target.chmod(0o600);hashes[source.name]=hashlib.sha256(target.read_bytes()).hexdigest()
            # os.fdopen log.name is a descriptor, so copy stable fixture paths.
            for source in base.glob('*.log'):
                target=failure/source.name;shutil.copyfile(source,target);target.chmod(0o600);hashes[source.name]=hashlib.sha256(target.read_bytes()).hexdigest()
            diagnostic=dict(errorType=type(exc).__name__,rpcTimings=RPC_TIMINGS[-256:],actorLogSha256=hashes)
            note=failure/'diagnostic.json';note.write_text(json.dumps(diagnostic));note.chmod(0o600)
            raise
        finally:
            if ui and ui.poll() is None:ui.kill();ui.wait()
            for p in processes:
                if p.poll() is None:p.terminate()
            for p in processes:
                try:await asyncio.to_thread(p.wait,10)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            for b in boots:b.close()
            for log in logs:log.close()
            server.should_exit=True
            if not server.started:running.cancel()
            try:await running
            except asyncio.CancelledError:pass
            listener.close();await service.close()


if __name__=='__main__':
    if sys.argv[1:] == ['--ui-child']:child()
    else:asyncio.run(main())
