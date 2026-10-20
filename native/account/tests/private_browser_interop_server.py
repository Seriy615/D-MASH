"""Private test-only pipe bridge; real native owner and unmodified default22 transit.
No Account secret is provided to Node or exposed through a network test API.
"""
import asyncio,json,os,pathlib,secrets,socket,sys,tempfile,time,signal
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'native/tests'))
from ipc_delivery_test import mine
from local_ipc_test import send,recv
from fastapi import FastAPI
import uvicorn
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.resource_pow import activation_pow_difficulty

async def main():
    host,node,cache=sys.argv[1:];folder=pathlib.Path(tempfile.mkdtemp(prefix='private-browser-interop-',dir=cache));folder.chmod(0o700)
    process=channel=service=server=task=log=None
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM,asyncio.current_task().cancel)
    async def call(method,params=None):
        send(channel,dict(v=1,id='interop',method=method,params=params or {}));reply=await asyncio.to_thread(recv,channel)
        if not reply.get('ok'):raise RuntimeError(reply.get('code','RPC_FAILED'))
        return reply['result']
    try:
        peer=await asyncio.to_thread(mine);service=NodeServiceV4(peer,folder/'transit');assert activation_pow_difficulty()==22 and service.listener.difficulty is None
        app=FastAPI();app.state.node_v4=service;app.include_router(router);listener=socket.socket();listener.bind(('127.0.0.1',0))
        server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16));task=asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:await asyncio.sleep(.01)
        endpoint=dict(url=f'ws://127.0.0.1:{listener.getsockname()[1]}/mesh/v4',nodeId=peer.verify_key.encode().hex())
        profile=folder/'owner';profile.mkdir(mode=0o700);log=os.fdopen(os.open(folder/'owner.log',os.O_WRONLY|os.O_CREAT,0o600),'wb',buffering=0)
        process=await asyncio.create_subprocess_exec(host,'--profile',str(profile),'--node-host',node,stdout=log,stderr=log)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            try:
                locator=json.loads((profile/'credential-endpoint.json').read_text());channel=socket.socket(socket.AF_UNIX);channel.settimeout(240);channel.connect(locator['endpoint']);break
            except (OSError,ValueError):channel=None;await asyncio.sleep(.05)
        assert channel
        private=dict(pin=secrets.token_hex(24),identity='native-browser-'+secrets.token_hex(12),password=secrets.token_hex(32))
        (folder/'private-inputs.json').write_text(json.dumps(private));(folder/'private-inputs.json').chmod(0o600)
        assert (await call('profile.create',dict(pin=private['pin'])))['rows']==[]
        await call('account.create',dict(identity=private['identity'],password=private['password'],displayName='Synthetic native browser interop'))
        account=(await call('account.login',dict(identity=private['identity'],password=private['password'])))['value']['accountPublicId']
        assert not [r for r in (await call('account.contacts'))['rows'] if len(r['id'])==64]
        await call('node.enable',dict(endpoints=[endpoint],directEnabled=False))
        print(json.dumps(dict(type='READY',endpoint=endpoint,account=account,privateDirectory=str(folder))),flush=True)
        allowed={'account.pairingCreate','account.pairingInspect','account.pairingRequest','account.pairingOffers','account.pairingAdvance','account.sync','account.contacts','account.history','account.sendText','host.status'}
        while True:
            raw=await asyncio.to_thread(sys.stdin.readline)
            if not raw:break
            command=json.loads(raw)
            if command.get('type')=='STOP':
                print(json.dumps(dict(type='STOPPED',forwarded=service.runtime.stats.get('forwarded'),difficulty=22)),flush=True);break
            if command.get('method') not in allowed:raise ValueError('TEST_METHOD_NOT_ALLOWED')
            try:result=await call(command['method'],command.get('params'));reply=dict(id=command['id'],ok=True,result=result)
            except RuntimeError as error:reply=dict(id=command['id'],ok=False,code=str(error))
            print(json.dumps(reply),flush=True)
    except BaseException as error:
        (folder/'failure.json').write_text(json.dumps(dict(errorClass=type(error).__name__)));(folder/'failure.json').chmod(0o600)
        print(json.dumps(dict(type='FAILED',errorClass=type(error).__name__,privateDirectory=folder.name)),flush=True);raise
    finally:
        if channel:channel.close()
        if process and process.returncode is None:
            process.terminate()
            try:await asyncio.wait_for(process.wait(),15)
            except asyncio.TimeoutError:process.kill();await process.wait()
        if log:log.close()
        if server:server.should_exit=True
        if task:await task
        if service:await service.close()
if __name__=='__main__':asyncio.run(main())
