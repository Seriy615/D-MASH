"""Two isolated Python Nodes; the browser is their only network path."""
import asyncio
import json
from pathlib import Path
import secrets
import socket
import uvicorn
from fastapi import FastAPI
import sys
import tempfile
import time

from nacl.public import PrivateKey
from nacl.signing import SigningKey
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.node_routing_v4 import NodeRoutingV4
from backend.route_discovery_v4 import issue_certificate
from backend.recipient_payload_v4 import seal_payload,open_payload,cover_box

async def main():
    keys=[]
    while len(keys)<2:
        key=SigningKey.generate()
        if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):keys.append(key)
    runtimes=[]
    owner,sign=SigningKey.generate(),SigningKey.generate();box,recipient=PrivateKey.generate(),PrivateKey.generate()
    now=int(time.time());cert=issue_certificate(owner,sign.verify_key,box.public_key,recipient.public_key,
        generation=1,issued_at=now,expires_at=now+3600)
    delivered=asyncio.Queue();discarded=0;accepted=0;local_cert=None
    async def receive(peer,packet):
        nonlocal discarded,accepted
        result=open_payload([recipient],packet['payload'])
        if result['status']=='discard':discarded+=1;return
        if result['status']!='accepted' or result['payload'] not in ('browser-transit-acceptance','browser-transit-after-cover','browser-local-submit'):
            raise AssertionError('Payload mismatch')
        if result['payload']=='browser-local-submit':
            reply=dict(peer=peer,label=packet['offer'],expires_at=packet['expires_at'],channel=runtimes[1].peers[peer])
            runtimes[1].send(reply,seal_payload(bytes.fromhex(local_cert['recipient_box']),'native-reply-to-browser'),discard)
        accepted+=1;await delivered.put((packet['label'],result['payload']))
    async def discard(peer,packet):pass
    servers=[];services=[];server_tasks=[];sockets=[]
    with tempfile.TemporaryDirectory() as tmp:
        try:
            for i,key in enumerate(keys):
                service=NodeServiceV4(key,Path(tmp)/str(i));services.append(service)
                service.listener.difficulty=20
                runtimes.append(service.runtime)
                app=FastAPI();app.state.node_v4=service;app.include_router(router)
                listener=socket.socket();listener.bind(('127.0.0.1',0));sockets.append(listener)
                server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16))
                servers.append(server);server_tasks.append(asyncio.create_task(server.serve(sockets=[listener])))
                async with asyncio.timeout(5):
                    while not server.started:await asyncio.sleep(.01)
            print(json.dumps({'nodes':[dict(port=s.getsockname()[1],nodeId=k.verify_key.encode().hex()) for s,k in zip(sockets,keys)]}),flush=True)
            commands=asyncio.Queue();loop=asyncio.get_running_loop()
            loop.add_reader(sys.stdin.fileno(),lambda:commands.put_nowait(sys.stdin.readline().strip()))
            try:
                command=await commands.get()
                if command!='start':raise AssertionError('Missing acceptance command')
                if any(len(runtime.peers)!=1 for runtime in runtimes):raise AssertionError('Unexpected network topology')
                if set(runtimes[0].peers)!=set(runtimes[1].peers):raise AssertionError('Browser is not shared next hop')
                discovery=asyncio.create_task(runtimes[0].discover(cert))
                async with asyncio.timeout(10):
                    while not runtimes[1].probes:await asyncio.sleep(.02)
                if runtimes[1].owned:raise AssertionError('Route bound before early Probe')
                print(json.dumps({'event':'early_probe'}),flush=True)
                if await commands.get()!='bind':raise AssertionError('Missing late binding command')
                if discovery.done() or any(len(runtime.peers)!=1 for runtime in runtimes):raise AssertionError('Early cover broke pending discovery')
                runtimes[1].bind_local(cert,sign,box,receive)
                route=await asyncio.wait_for(discovery,30)
                runtimes[0].send(route,seal_payload(recipient.public_key,'browser-transit-acceptance'),discard)
                destination_label,_=await asyncio.wait_for(delivered.get(),15)
                if destination_label==route['label']:raise AssertionError('Hop label not rewritten')
                print(json.dumps({'event':'delivered','labelRewrite':True,'onlyBrowserPath':True,'lateBinding':True}),flush=True)
                if await commands.get()!='cover':raise AssertionError('Missing cover check')
                async with asyncio.timeout(5):
                    while not discarded:await asyncio.sleep(.02)
                if accepted!=1 or any(len(runtime.peers)!=1 for runtime in runtimes):raise AssertionError('Cover changed delivery or channel state')
                runtimes[0].send(route,seal_payload(recipient.public_key,'browser-transit-after-cover'),discard)
                _,payload=await asyncio.wait_for(delivered.get(),10)
                if payload!='browser-transit-after-cover' or accepted!=2:raise AssertionError('Real payload after cover lost')
                print(json.dumps({'event':'cover','discarded':discarded,'accepted':accepted,'certificate':cert}),flush=True)
                command=await commands.get()
                if command.startswith('local:'):
                    local_cert=json.loads(command[6:])
                    local_route=await asyncio.wait_for(runtimes[0].discover(local_cert),30)
                    payload=seal_payload(bytes.fromhex(local_cert['recipient_box']),'opaque-for-locked-account')
                    runtimes[0].send(local_route,payload,discard)
                    print(json.dumps({'event':'local_sent'}),flush=True)
                    if await commands.get()!='local_keys':raise AssertionError('Missing local keys check')
                    runtimes[0].send(local_route,cover_box(1024),discard)
                    print(json.dumps({'event':'local_cover'}),flush=True)
                    if await commands.get()!='local_submit':raise AssertionError('Missing local submit check')
                    _,payload=await asyncio.wait_for(delivered.get(),15)
                    if payload!='browser-local-submit':raise AssertionError('Wrong local payload')
                    print(json.dumps({'event':'local_submitted'}),flush=True)
                    command=await commands.get()
                if command!='disconnected':raise AssertionError('Missing disconnect check')
                async with asyncio.timeout(5):
                    while any(runtime.peers for runtime in runtimes):await asyncio.sleep(.02)
                try:runtimes[0].send(route,'opaque',discard)
                except ConnectionError:pass
                else:raise AssertionError('Disconnected route remained usable')
                print(json.dumps({'event':'disconnected','unavailable':True}),flush=True)
                await commands.get()
            finally:loop.remove_reader(sys.stdin.fileno())
        finally:
            await asyncio.gather(*(service.close() for service in services))
            for server in servers:server.should_exit=True
            await asyncio.gather(*server_tasks)
            for listener in sockets:listener.close()

asyncio.run(main())
