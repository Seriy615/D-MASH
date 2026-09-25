"""Real encrypted discovery/DATA through a pinned public v4 WSS Node."""
import asyncio
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time

from nacl.signing import SigningKey
from nacl.public import PrivateKey
from websockets.client import connect
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.secure_socket import connect_secure
from backend.node_channel_v4 import authorize_node_v4
from backend.node_relationships_v4 import RelationshipStore
from backend.node_routing_v4 import NodeRoutingV4
from backend.route_discovery_v4 import issue_certificate
from backend.recipient_payload_v4 import seal_payload,open_payload

async def main():
    url,peer=os.environ['DMASH_REMOTE_V4_URL'],os.environ['DMASH_REMOTE_NODE_ID']
    if not url.startswith('wss://') or not NodeCryptoManager.verify_node_pow(peer):
        raise ValueError('Public WSS and independently pinned NodeID required')
    def mine():
        while True:
            key=SigningKey.generate()
            if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):return key
    keys=[await asyncio.to_thread(mine) for _ in range(2)]
    runtimes=[NodeRoutingV4(secrets.token_bytes(32)) for _ in keys]
    stores=[];sockets=[]
    with tempfile.TemporaryDirectory() as tmp:
        try:
            for i,key in enumerate(keys):
                store=RelationshipStore(Path(tmp)/f'{i}.db',key.verify_key.encode().hex(),secrets.token_bytes(32));stores.append(store)
                socket=await connect(url,max_size=2*1024*1024,max_queue=16,compression=None);sockets.append(socket)
                secure,verified=await connect_secure(socket,key,'NODE',peer,version=4)
                assert verified==peer
                channel=await authorize_node_v4(secure,store,difficulty=22)
                runtimes[i].add_peer(peer,channel)
            owner,sign=SigningKey.generate(),SigningKey.generate()
            box,recipient=PrivateKey.generate(),PrivateKey.generate()
            now=int(time.time())
            certificate=issue_certificate(owner,sign.verify_key,box.public_key,recipient.public_key,generation=1,issued_at=now,expires_at=now+3600)
            delivered=asyncio.Queue()
            async def receive(_,packet):
                opened=open_payload([recipient],packet['payload'])
                if opened['status']=='accepted':await delivered.put((opened,packet['label']))
            async def discard(*_):pass
            runtimes[1].bind_local(certificate,sign,box,receive)
            route=await asyncio.wait_for(runtimes[0].discover(certificate),30)
            runtimes[0].send(route,seal_payload(recipient.public_key,'real-public-WSS-transit'),discard)
            payload,label=await asyncio.wait_for(delivered.get(),15)
            assert payload['payload']=='real-public-WSS-transit'
            assert label!=route['label']
            assert all(set(runtime.peers)=={peer} for runtime in runtimes)
            assert runtimes[0].peers[peer].secure.session.peer_id==peer
            print('PASS public WSS v4 N1 -> EMS -> N2: mutual production PoW, encrypted discovery/route proof, opaque recipient payload and rewritten labels, no direct bypass',flush=True)
        finally:
            await asyncio.gather(*(runtime.close() for runtime in runtimes))
            await asyncio.gather(*(socket.close() for socket in sockets))
            for store in stores:store.close()

asyncio.run(main())
