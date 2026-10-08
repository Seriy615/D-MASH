"""Real loopback v4 Node sender; never receives Account private material."""
import asyncio,json,sys,tempfile,socket,hashlib
from pathlib import Path
import uvicorn
from fastapi import FastAPI
from nacl.signing import SigningKey
from nacl.public import PrivateKey
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.recipient_payload_v4 import seal_payload,open_payload

async def main():
    while True:
        key=SigningKey.generate()
        if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):break
    with tempfile.TemporaryDirectory() as tmp:
        service=NodeServiceV4(key,Path(tmp));service.listener.difficulty=20
        app=FastAPI();app.state.node_v4=service;app.include_router(router)
        listener=socket.socket();listener.bind(('127.0.0.1',0))
        server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off'))
        task=asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:await asyncio.sleep(.01)
        print(json.dumps({'port':listener.getsockname()[1],'nodeId':key.verify_key.encode().hex()}),flush=True)
        commands=asyncio.Queue();loop=asyncio.get_running_loop()
        loop.add_reader(sys.stdin.fileno(),lambda:commands.put_nowait(sys.stdin.readline()))
        received=[]
        observed=[]
        recipient_keys=[]
        original_receive=service.runtime._receive
        async def observe_receive(peer,packet):
            if packet.get('type')=='DATA' and recipient_keys:
                opened=open_payload(recipient_keys,packet['payload'])
                if opened['status']=='accepted':
                    observed.append(dict(blobHash=hashlib.sha256(packet['payload'].encode()).hexdigest(),status=opened['status'],payload=opened.get('payload'),packetId=opened.get('packet_id')))
            return await original_receive(peer,packet)
        service.runtime._receive=observe_receive
        async def discard(peer,packet):pass
        try:
            while True:
                raw=await commands.get()
                if not raw:break
                command=json.loads(raw)
                if command['type']=='STOP':break
                if command['type']=='BIND':
                    recipient=bytes.fromhex(command['recipient'])
                    recipient_keys.append(recipient)
                    async def receive(peer,packet):
                        opened=open_payload([recipient],packet['payload'])
                        received.append(dict(blobHash=hashlib.sha256(packet['payload'].encode()).hexdigest(),status=opened['status'],payload=opened.get('payload'),packetId=opened.get('packet_id')))
                    service.runtime.bind_local(command['certificate'],SigningKey(bytes.fromhex(command['signSeed'])),PrivateKey(bytes.fromhex(command['boxSecret'])),receive)
                    print(json.dumps({'bound':True}),flush=True)
                if command['type']=='READ':
                    print(json.dumps({'received':received,'observed':observed}),flush=True)
                if command['type']=='SEND':
                    route=await asyncio.wait_for(service.runtime.discover(command['certificate']),40)
                    service.runtime.send(route,seal_payload(bytes.fromhex(command['certificate']['recipient_box']),command['payload']),discard)
                    print(json.dumps({'queued':True,'peers':len(service.runtime.peers)}),flush=True)
        finally:
            loop.remove_reader(sys.stdin.fileno());await service.close();server.should_exit=True;await task

asyncio.run(main())
