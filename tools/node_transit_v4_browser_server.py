"""Two isolated Python Nodes; the browser is their only network path."""
import asyncio
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time

from nacl.public import PrivateKey
from nacl.signing import SigningKey
from websockets.server import serve
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.secure_socket import accept_secure
from backend.node_channel_v4 import authorize_node_v4
from backend.node_relationships_v4 import RelationshipStore
from backend.node_routing_v4 import NodeRoutingV4
from backend.route_discovery_v4 import issue_certificate,seal,open_box

async def main():
    keys=[]
    while len(keys)<2:
        key=SigningKey.generate()
        if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):keys.append(key)
    runtimes=[NodeRoutingV4(secrets.token_bytes(32)) for _ in keys]
    owner,sign=SigningKey.generate(),SigningKey.generate();box,recipient=PrivateKey.generate(),PrivateKey.generate()
    now=int(time.time());cert=issue_certificate(owner,sign.verify_key,box.public_key,recipient.public_key,
        generation=1,issued_at=now,expires_at=now+3600)
    delivered=asyncio.get_running_loop().create_future()
    async def receive(peer,packet):
        payload=open_box(recipient,packet['payload'])
        if payload!={'opaque':'browser-transit-acceptance'}:raise AssertionError('Payload mismatch')
        if not delivered.done():delivered.set_result(packet['label'])
    async def discard(peer,packet):pass
    servers=[];stores=[]
    with tempfile.TemporaryDirectory() as tmp:
        try:
            for i,key in enumerate(keys):
                store=RelationshipStore(Path(tmp)/f'{i}.db',key.verify_key.encode().hex(),secrets.token_bytes(32));stores.append(store)
                async def handle(socket,key=key,store=store,runtime=runtimes[i]):
                    secure=None;channel=None
                    try:
                        secure,_=await accept_secure(socket,key,'NODE',version=4)
                        channel=await authorize_node_v4(secure,store,difficulty=20)
                        runtime.add_peer(secure.session.peer_id,channel)
                        await socket.wait_closed()
                    except Exception:
                        if channel:await channel.close()
                        elif secure:await secure.close()
                servers.append(await serve(handle,'127.0.0.1',0,max_size=2*1024*1024))
            print(json.dumps({'nodes':[dict(port=s.sockets[0].getsockname()[1],nodeId=k.verify_key.encode().hex()) for s,k in zip(servers,keys)]}),flush=True)
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
                runtimes[1].bind_local(cert,sign,box,receive)
                route=await asyncio.wait_for(discovery,30)
                runtimes[0].send(route,seal(bytes(recipient.public_key),{'opaque':'browser-transit-acceptance'}),discard)
                destination_label=await asyncio.wait_for(delivered,15)
                if destination_label==route['label']:raise AssertionError('Hop label not rewritten')
                print(json.dumps({'event':'delivered','labelRewrite':True,'onlyBrowserPath':True,'lateBinding':True}),flush=True)
                if await commands.get()!='disconnected':raise AssertionError('Missing disconnect check')
                async with asyncio.timeout(5):
                    while any(runtime.peers for runtime in runtimes):await asyncio.sleep(.02)
                try:runtimes[0].send(route,'opaque',discard)
                except ConnectionError:pass
                else:raise AssertionError('Disconnected route remained usable')
                print(json.dumps({'event':'disconnected','unavailable':True}),flush=True)
                await commands.get()
            finally:loop.remove_reader(sys.stdin.fileno())
        finally:
            await asyncio.gather(*(runtime.close() for runtime in runtimes))
            for server in servers:server.close()
            await asyncio.gather(*(server.wait_closed() for server in servers))
            for store in stores:store.close()

asyncio.run(main())
