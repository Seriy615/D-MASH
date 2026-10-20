"""Fresh Root with zero Accounts enables actual foreign-transit Node through host API.
Usage: python fresh_foreign_transit_test.py CREDENTIAL_HOST NODE_HOST PRIVATE_CACHE
No profile import, Account creation/login or raw transport install is performed.
"""
import asyncio, contextlib, hashlib, json, os, pathlib, secrets, shutil, socket, subprocess, sys, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'native/tests'))
from ipc_delivery_test import mine, material
from local_ipc_test import send, recv
from fastapi import FastAPI
import uvicorn
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.recipient_payload_v4 import seal_payload, open_payload
from backend.resource_pow import activation_pow_difficulty


async def main():
    binary,node_binary,cache=sys.argv[1:];services=[];servers=[];listeners=[];tasks=[];process=log=admin=None;succeeded=False;phase='identity';timings=[]
    with contextlib.nullcontext(tempfile.mkdtemp(prefix='fresh-foreign-transit-',dir=cache)) as folder:
        base=pathlib.Path(folder);base.chmod(0o700)
        try:
            akey,bkey=await asyncio.to_thread(lambda:tuple(mine() for _ in range(2)))
            phase='Python-listeners';endpoints=[]
            for index,key in enumerate([akey,bkey]):
                service=NodeServiceV4(key,base/('python-'+str(index)));services.append(service)
                assert service.listener.difficulty is None and activation_pow_difficulty()==22
                app=FastAPI();app.state.node_v4=service;app.include_router(router)
                listener=socket.socket();listener.bind(('127.0.0.1',0));listeners.append(listener)
                server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16));servers.append(server)
                tasks.append(asyncio.create_task(server.serve(sockets=[listener])))
                while not server.started:await asyncio.sleep(.01)
                endpoints.append(dict(url=f'ws://127.0.0.1:{listener.getsockname()[1]}/mesh/v4',nodeId=key.verify_key.encode().hex()))
            phase='credential-host-start';path=base/'credential-host.log';log=os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb',buffering=0)
            profile=base/'owner';profile.mkdir(mode=0o700)
            process=subprocess.Popen([binary,'--profile',str(profile),'--node-host',node_binary],stdout=log,stderr=log)
            mapped_host_sha=hashlib.sha256(pathlib.Path(f'/proc/{process.pid}/exe').read_bytes()).hexdigest()
            async def attach():
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    try:
                        locator=json.loads((profile/'credential-endpoint.json').read_text());channel=socket.socket(socket.AF_UNIX);channel.settimeout(240);channel.connect(locator['endpoint']);return channel
                    except (OSError,ValueError):
                        if 'channel' in locals():channel.close()
                        assert process.poll() is None
                        await asyncio.sleep(.05)
                raise TimeoutError('credential host locator')
            admin=await attach();methods=[]
            async def good(method,params=None):
                methods.append(method);send(admin,dict(v=1,id='fresh-transit',method=method,params=params or {}))
                started=time.monotonic()
                try:reply=await asyncio.to_thread(recv,admin)
                finally:timings.append(dict(method=method,elapsedMs=round((time.monotonic()-started)*1000)))
                assert reply['id']=='fresh-transit' and reply['ok'],(method,reply.get('code'));return reply['result']
            async def zero_accounts():
                state=(await good('host.status'))['value'];assert state['profileExists'] and not state['rootLocked'] and not state['accountSessionActive']
                assert (await good('account.listAccounts'))['rows']==[]
                return state
            initial=(await good('host.status'))['value'];assert not initial['profileExists'] and not initial['accountSessionActive']
            phase='profile-create';creation=dict(pin=secrets.token_hex(24));private_input=base/'fresh-root-input.json';private_input.write_text(json.dumps(creation));private_input.chmod(0o600)
            created=await good('profile.create',creation);assert created['rows']==[] and created['value']['accountImportPhase']=='COMMITTED'
            await zero_accounts()
            phase='node-enable';enabled=await good('node.enable',dict(endpoints=endpoints,directEnabled=False));assert enabled['value']['nodeRunning']
            state=await zero_accounts();assert state['nodeRunning']
            # This private receipt contains public process/Node metadata only.
            receipt=json.loads((profile/'node/supervisor-child.json').read_text());middle_id=state['node']['nodeId'];assert receipt['nodeId']==middle_id
            mapped_binary_sha=hashlib.sha256(pathlib.Path('/proc/'+str(receipt['pid'])+'/exe').read_bytes()).hexdigest()
            assert mapped_binary_sha==hashlib.sha256(pathlib.Path(node_binary).read_bytes()).hexdigest()
            phase='native-authorize';deadline=time.monotonic()+180;left,right=[service.runtime for service in services]
            while time.monotonic()<deadline:
                state=await zero_accounts();status=state['node']
                if status['connectedPeers']==2 and list(left.peers)==[middle_id] and list(right.peers)==[middle_id]:break
                assert process.poll() is None
                await asyncio.sleep(.25)
            assert status['initialized'] and status['role']=='NODE' and status['connectedPeers']==2 and list(left.peers)==[middle_id] and list(right.peers)==[middle_id],'two actual authorized middle channels not reached'
            admin.close();admin=await attach() # UI/client detach preserves resident Node.
            assert (await zero_accounts())['node']['connectedPeers']==2
            source_wire=[];recipient_wire=[];received=[];delivered=asyncio.Event()
            channel=left.peers[middle_id];original_send=channel.send_operation
            async def observe_send(value):
                source_wire.extend(dict(packet) for packet in value['packets']);return await original_send(value)
            channel.send_operation=observe_send
            original_receive=right._receive
            async def observe_receive(peer,packet):
                recipient_wire.append(dict(packet));return await original_receive(peer,packet)
            right._receive=observe_receive
            recipient=material()
            async def handler(peer,packet):
                opened=open_payload([recipient['recipient']],packet['payload']);received.append(opened);delivered.set()
            right.bind_local(recipient['cert'],recipient['discovery'],recipient['box'],handler)
            phase='foreign-discovery';route=await left.discover(recipient['cert']);assert route['peer']==middle_id
            payload='opaque-Account-ciphertext-'+secrets.token_hex(32)
            blob=seal_payload(recipient['recipient'].public_key.encode(),payload)
            async def ignore_reply(peer,packet):pass
            # Two ordinary sends enter one existing500ms batch. The native
            # relay must suppress the repeat before the receiving peer sees it.
            left.send(route,blob,ignore_reply);left.send(route,blob,ignore_reply)
            phase='foreign-delivery';await asyncio.wait_for(delivered.wait(),30);await asyncio.sleep(1.2)
            incoming=[p for p in source_wire if p.get('type')=='DATA' and p.get('payload')==blob]
            outgoing=[p for p in recipient_wire if p.get('type')=='DATA' and p.get('payload')==blob]
            assert len(incoming)==2 and len(outgoing)==1 and len(received)==1
            assert received[0]['status']=='accepted' and received[0]['payload']==payload
            before,after=incoming[0],outgoing[0]
            assert set(before)==set(after)=={'type','version','label','offer','payload','expires_at'}
            assert before['label']!=after['label'] and before['offer']!=after['offer'] and before['payload']==after['payload'] and before['expires_at']==after['expires_at']
            probes_in=[p for p in source_wire if p.get('type')=='PROBE'];probes_out=[p for p in recipient_wire if p.get('type')=='PROBE']
            first=next(p for p in probes_in if any(q['box']==p['box'] for q in probes_out));last=next(p for p in probes_out if p['box']==first['box'])
            assert last['ttl']==first['ttl']-1 and last['ncrh']!=first['ncrh'] and last['return_label']!=first['return_label']
            expired=seal_payload(recipient['recipient'].public_key.encode(),payload+'expired')
            await channel.send_operation(dict(type='MESH_BATCH',version=4,packets=[dict(before,payload=expired,expires_at=int(time.time())-1)]))
            await asyncio.sleep(1.2);assert not any(p.get('payload')==expired for p in recipient_wire);assert len(received)==1
            assert (await zero_accounts())['node']['connectedPeers']==2
            assert not any(method in methods for method in ['account.create','account.login','profile.import'])
            phase='root-lock';await good('root.lock');stopped=(await good('host.status'))['value'];assert stopped['rootLocked'] and not stopped['nodeRunning'] and not stopped['accountSessionActive']
            print(json.dumps(dict(suite='fresh-zero-Account-native-foreign-transit',status='PASS',admissionDifficulty=22,wireRole='NODE',accountRows=0,accountSessionActive=False,profileImported=False,credentialApi=['profile.create','node.enable','host.status','account.listAccounts','root.lock'],uiDetachPreservesNode=True,rootLockStopsNode=True,pythonPeersConnectedOnlyToMiddle=True,sourcePackets=2,recipientWirePackets=1,recipientHandlerCalls=1,hopLabelChanged=True,replyOfferChanged=True,probeTtlBefore=first['ttl'],probeTtlAfter=last['ttl'],probeNcrhChanged=True,expiredPacketForwarded=False,mappedNodeBinarySha256=mapped_binary_sha,mappedCredentialHostSha256=mapped_host_sha,payloadDigest=hashlib.sha256(payload.encode()).hexdigest(),checks=['fresh Root with zero Account rows','normal resident host API enables Node before any Account exists','actual Node child identity and binary verified','two real default22 pinned Python channels','ordinary discovery and foreign opaque transit','unchanged500ms aggregation and per-hop rewriting','duplicate suppressed and expired packet dropped','client detach preserves autonomous transit','full Root lock stops owned Node'],limits=['Linux component; no GUI creation acceptance','configured WS loopback peers; self-organization/NAT NOT_RUN','host may retain unused owner capability; no Account owner registered','ACK-free loss window unchanged'])),flush=True);succeeded=True
        except BaseException as error:
            if log:log.flush()
            diagnostic=dict(suite='fresh-zero-Account-native-foreign-transit',status='FAIL',phase=phase,errorClass=type(error).__name__,rpcTimings=timings,privateDiagnosticDirectory=base.name)
            (base/'failure.json').write_text(json.dumps(diagnostic));(base/'failure.json').chmod(0o600)
            print(json.dumps(diagnostic),flush=True)
            raise
        finally:
            if admin:admin.close()
            if process and process.poll() is None:process.terminate()
            if process:
                try:await asyncio.to_thread(process.wait,10)
                except subprocess.TimeoutExpired:process.kill();await asyncio.to_thread(process.wait)
            if log:log.close()
            for server in servers:server.should_exit=True
            await asyncio.gather(*tasks,return_exceptions=True)
            for listener in listeners:listener.close()
            for service in services:await service.close()
            if succeeded:shutil.rmtree(base)


if __name__=='__main__':asyncio.run(main())
