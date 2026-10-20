"""Isolated native-host acceptance peer; existing backend protocol, default work22."""
import asyncio,json,os,secrets,socket,sys,tempfile
from pathlib import Path
from nacl.signing import SigningKey
import uvicorn
from fastapi import FastAPI
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.resource_pow import activation_pow_difficulty

def mine():
    while True:
        key=SigningKey.generate()
        if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):return key

async def main():
    base=Path(sys.argv[1]);base.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='native-interop-',dir=base) as name:
        task=Path(name);os.chmod(task,0o700)
        peer=await asyncio.to_thread(mine);local=await asyncio.to_thread(mine)
        service=NodeServiceV4(peer,task/'python-node')
        # Do not lower listener work: this is the existing production default.
        assert service.listener.difficulty is None and activation_pow_difficulty()==22
        app=FastAPI();app.state.node_v4=service;app.include_router(router)
        listener=socket.socket();listener.bind(('127.0.0.1',0))
        server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16))
        running=asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:await asyncio.sleep(.01)
        port=listener.getsockname()[1]
        bundle={'version':1,'nodeSeed':local.encode().hex(),'storageKey':secrets.token_hex(32),'baseNcrh':secrets.token_hex(32),'generation':1,'directEnabled':False,'endpoints':[{'url':f'ws://127.0.0.1:{port}/mesh/v4','nodeId':peer.verify_key.encode().hex()}]}
        path=task/'scoped-broker.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(bundle,f)
        print(json.dumps({'event':'fixture-ready','bundle':str(path),'profile':str(task/'native-node'),'nodeId':peer.verify_key.encode().hex(),'port':port,'difficulty':22}),flush=True)
        try:
            while True:
                line=(await asyncio.to_thread(sys.stdin.readline)).strip()
                if line in ('stop',''):break
                if line=='status':print(json.dumps({'event':'peer-status','peers':len(service.runtime.peers),'stats':service.runtime.stats}),flush=True)
        finally:
            server.should_exit=True;await running;await service.close()
asyncio.run(main())
