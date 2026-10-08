"""Synthetic isolated Node, real authorization/signatures; controlled health seam."""
import asyncio,json,socket,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
import uvicorn
from fastapi import FastAPI
from nacl.signing import SigningKey
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'D-MASH/client'))
from backend.crypto import NodeCryptoManager
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.node_service_descriptor_v4 import sign
async def main():
 while True:
  key=SigningKey.generate()
  if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):break
 healthy=True
 def descriptor():return {'can_s_turn':healthy}
 with tempfile.TemporaryDirectory() as tmp:
  service=NodeServiceV4(key,Path(tmp));service.listener.difficulty=20
  service.configure_service(key,SimpleNamespace(signaling_wss='wss://example.test/signal',descriptor=descriptor),SimpleNamespace(can_relay_blob=True))
  app=FastAPI();app.state.node_v4=service;app.include_router(router)
  sock=socket.socket();sock.bind(('127.0.0.1',0));server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off'))
  task=asyncio.create_task(server.serve(sockets=[sock]))
  while not server.started:await asyncio.sleep(.01)
  print(json.dumps(dict(port=sock.getsockname()[1],nodeId=key.verify_key.encode().hex())),flush=True)
  q=asyncio.Queue();loop=asyncio.get_running_loop();loop.add_reader(sys.stdin.fileno(),lambda:q.put_nowait(sys.stdin.readline().strip()))
  try:
   while True:
    cmd=await q.get()
    if cmd=='unhealthy':healthy=False;print(json.dumps({'unhealthy':True}),flush=True)
    elif cmd=='expired':
     original=service.runtime.service_provider
     async def expired(peer,channel,challenge):
      envelope=await original(peer,channel,challenge);body=envelope['body'];body['issued_at']-=60;body['expires_at']-=60;return sign(body,key)
     service.runtime.service_provider=expired;print(json.dumps({'expired':True}),flush=True)
    elif cmd=='unconfigured':service.configure_service(key,None,SimpleNamespace());print(json.dumps({'unconfigured':True}),flush=True)
    elif cmd=='stop' or not cmd:break
  finally:
   loop.remove_reader(sys.stdin.fileno());await service.close();server.should_exit=True;await task;sock.close()
asyncio.run(main())
