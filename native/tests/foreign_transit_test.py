"""Actual native middle Node forwards between two otherwise-disconnected Python peers.
No owner capability, Account registration or local binding is installed on middle.
Usage: python foreign_transit_test.py HOST PRIVATE_CACHE
"""
import asyncio, collections, hashlib, json, os, pathlib, secrets, shutil, socket, subprocess, sys, tempfile, time
from ipc_delivery_test import mine, material, checked
from local_ipc_test import send, recv, connect
from fastapi import FastAPI
import uvicorn
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.recipient_payload_v4 import seal_payload, open_payload
from backend.resource_pow import activation_pow_difficulty


async def main():
    binary,cache=sys.argv[1:];services=[];servers=[];listeners=[];tasks=[];process=boot=log=admin=None
    with tempfile.TemporaryDirectory(prefix='foreign-transit-',dir=cache) as folder:
        base=pathlib.Path(folder);base.chmod(0o700)
        akey,bkey,middle=await asyncio.to_thread(lambda:tuple(mine() for _ in range(3)))
        try:
            endpoints=[]
            for index,key in enumerate([akey,bkey]):
                service=NodeServiceV4(key,base/('python-'+str(index)));services.append(service)
                assert service.listener.difficulty is None and activation_pow_difficulty()==22
                app=FastAPI();app.state.node_v4=service;app.include_router(router)
                listener=socket.socket();listener.bind(('127.0.0.1',0));listeners.append(listener)
                server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16));servers.append(server)
                tasks.append(asyncio.create_task(server.serve(sockets=[listener])))
                while not server.started:await asyncio.sleep(.01)
                endpoints.append(dict(url=f'ws://127.0.0.1:{listener.getsockname()[1]}/mesh/v4',nodeId=key.verify_key.encode().hex()))
            parent,child=socket.socketpair();parent.settimeout(15);boot=parent
            path=base/'middle.log';log=os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb',buffering=0)
            process=subprocess.Popen([binary,'--profile',str(base/'native-middle'),'--bootstrap-fd',str(child.fileno())],pass_fds=[child.fileno()],stdout=log,stderr=log);child.close()
            mapped_binary_sha=hashlib.sha256(pathlib.Path(f'/proc/{process.pid}/exe').read_bytes()).hexdigest()
            bundle=dict(version=1,nodeSeed=middle.encode().hex(),storageKey=secrets.token_hex(32),baseNcrh=secrets.token_hex(32),generation=1,directEnabled=False,endpoints=endpoints)
            send(boot,dict(v=1,type='InstallTransportSession',request_id='middle',generation=1,effective_policy_revision=1,transport_bundle=bundle,principals=[dict(id='supervisor',role='broker',ttl_seconds=600)]))
            ready=await asyncio.to_thread(recv,boot);assert ready['type']=='TransportSessionReady' and all(c['role']=='broker' for c in ready['capabilities'])
            admin=connect(ready,'broker');assert recv(admin)['ok']
            deadline=time.monotonic()+180
            middle_id=middle.verify_key.encode().hex();left,right=[service.runtime for service in services]
            while time.monotonic()<deadline:
                status=await asyncio.to_thread(checked,admin,'node.status',{})
                if status['connectedPeers']==2 and list(left.peers)==[middle_id] and list(right.peers)==[middle_id]:break
                assert process.poll() is None
                for line in path.read_text().splitlines():
                    try:event=json.loads(line)
                    except json.JSONDecodeError:continue
                    if event.get('event') in ['benchmark-nonce-search-error','benchmark-nonce-factory-error'] or (event.get('event')=='benchmark-port-error' and event.get('operation')=='nonceSearch'):raise RuntimeError('native nonce search: '+event.get('code','failed'))
                await asyncio.sleep(.25)
            assert status['connectedPeers']==2 and list(left.peers)==[middle_id] and list(right.peers)==[middle_id],'two actual authorized middle channels not reached'
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
            route=await left.discover(recipient['cert']);assert route['peer']==middle_id
            payload='opaque-Account-ciphertext-'+secrets.token_hex(32)
            blob=seal_payload(recipient['recipient'].public_key.encode(),payload)
            async def ignore_reply(peer,packet):pass
            # Two ordinary sends enter one existing500ms batch. The native
            # relay must suppress the repeat before the receiving peer sees it.
            left.send(route,blob,ignore_reply);left.send(route,blob,ignore_reply)
            await asyncio.wait_for(delivered.wait(),30);await asyncio.sleep(1.2)
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
            assert (await asyncio.to_thread(checked,admin,'node.status',{}))['connectedPeers']==2
            events=[json.loads(line) for line in path.read_text().splitlines()]
            startup=next(e for e in events if e.get('event')=='ready')
            nonce_bench=[{k:e[k] for k in ['attempts','crossingMs','batchMs']} for e in events if e.get('event')=='benchmark-nonce-batch']
            assert startup['accountsLoaded'] is False and startup['restored']==0
            assert not any(e.get('event')=='error' for e in events)
            print(json.dumps(dict(suite='native-foreign-transit',status='PASS',admissionDifficulty=22,wireRole='NODE',middleOwnerCapabilities=0,middleAccountRegistrations=0,middleRestoredBindings=0,pythonPeersConnectedOnlyToMiddle=True,sourcePackets=2,recipientWirePackets=1,recipientHandlerCalls=1,hopLabelChanged=True,replyOfferChanged=True,probeTtlBefore=first['ttl'],probeTtlAfter=last['ttl'],probeNcrhChanged=True,expiredPacketForwarded=False,nonceSearchBenchmarks=nonce_bench,mappedBinarySha256=mapped_binary_sha,payloadDigest=hashlib.sha256(payload.encode()).hexdigest(),checks=['two-real-authorized-pinned-channels','ordinary-discovery-cross-native-middle','unchanged500ms-aggregation','opaque-foreign-Account-box-forward','per-hop-label-offer-rewrite','probe-hop-budget-and-NCRH','duplicate-suppressed-before-recipient-wire','expired-wire-packet-dropped','no-Account-callback-or-owner-capability'],limits=['configured real WS loopback peers; self-organizing discovery/NAT NOT_RUN','ACK-free loss window unchanged','Linux executable only; Windows/Android runtime NOT_RUN'])),flush=True)
        except BaseException:
            failure=pathlib.Path(tempfile.mkdtemp(prefix='foreign-transit-failure-',dir=cache));failure.chmod(0o700)
            if log:log.flush()
            if (base/'middle.log').exists():shutil.copyfile(base/'middle.log',failure/'middle.log');(failure/'middle.log').chmod(0o600)
            raise
        finally:
            if admin:admin.close()
            if process and process.poll() is None:process.terminate()
            if process:
                try:await asyncio.to_thread(process.wait,10)
                except subprocess.TimeoutExpired:process.kill();await asyncio.to_thread(process.wait)
            if boot:boot.close()
            if log:log.close()
            for server in servers:server.should_exit=True
            await asyncio.gather(*tasks,return_exceptions=True)
            for listener in listeners:listener.close()
            for service in services:await service.close()


if __name__=='__main__':asyncio.run(main())
