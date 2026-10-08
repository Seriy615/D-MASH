"""Real loopback v4 Node sender; never receives Account private material."""
import asyncio,json,sys,tempfile,socket
from pathlib import Path
import uvicorn
from fastapi import FastAPI
from nacl.signing import SigningKey
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.recipient_payload_v4 import seal_payload

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
        async def discard(peer,packet):pass
        try:
            while True:
                raw=await commands.get()
                if not raw:break
                command=json.loads(raw)
                if command['type']=='STOP':break
                if command['type']=='SEND':
                    route=await asyncio.wait_for(service.runtime.discover(command['certificate']),40)
                    service.runtime.send(route,seal_payload(bytes.fromhex(command['certificate']['recipient_box']),command['payload']),discard)
                    print(json.dumps({'queued':True,'peers':len(service.runtime.peers)}),flush=True)
        finally:
            loop.remove_reader(sys.stdin.fileno());await service.close();server.should_exit=True;await task

asyncio.run(main())
