"""Synthetic v4 transit hub: no Account/recipient keys, payloads remain opaque."""
import asyncio, hashlib, json, os, socket, sys, tempfile
from pathlib import Path
import uvicorn
from fastapi import FastAPI
from nacl.signing import SigningKey
root = Path(os.environ.get('DMASH_INTEGRATION_ROOT', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(root / 'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router

async def main():
    while True:
        identity = SigningKey.generate()
        if NodeCryptoManager.verify_node_pow(identity.verify_key.encode().hex()):
            break
    with tempfile.TemporaryDirectory() as temporary:
        service = NodeServiceV4(identity, Path(temporary))
        service.listener.difficulty = 20
        app = FastAPI(); app.state.node_v4 = service; app.include_router(router)
        listener = socket.socket(); listener.bind(('127.0.0.1', 0))
        server = uvicorn.Server(uvicorn.Config(app, log_level='critical', lifespan='off'))
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:
            await asyncio.sleep(.01)
        print(json.dumps({'port': listener.getsockname()[1], 'nodeId': identity.verify_key.encode().hex()}), flush=True)
        observed = []; dropped = []; drop_next = 0
        receive = service.runtime._receive
        async def observe(peer, packet):
            nonlocal drop_next
            if packet.get('type') == 'DATA' and isinstance(packet.get('payload'), str):
                observed.append(hashlib.sha256(packet['payload'].encode()).hexdigest())
                del observed[:-1024]
                if drop_next:
                    drop_next -= 1; dropped.append(observed[-1]); return
            return await receive(peer, packet)
        service.runtime._receive = observe
        commands = asyncio.Queue(); loop = asyncio.get_running_loop()
        loop.add_reader(sys.stdin.fileno(), lambda: commands.put_nowait(sys.stdin.readline()))
        try:
            while True:
                raw = await commands.get()
                if not raw:
                    break
                command = json.loads(raw)
                if command.get('type') == 'STOP':
                    break
                if command.get('type') == 'DROP_NEXT_DATA':
                    drop_next = 1; print(json.dumps({'dropArmed': True}), flush=True)
                if command.get('type') == 'READ':
                    print(json.dumps({'peers': len(service.runtime.peers), 'ownedRoutes': len(service.runtime.owned), 'opaqueDataHashes': observed, 'droppedOpaqueHashes': dropped}), flush=True)
        finally:
            loop.remove_reader(sys.stdin.fileno())
            await service.close(); server.should_exit = True; await serving

asyncio.run(main())
