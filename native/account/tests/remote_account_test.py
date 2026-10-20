"""Two actual native Account owners exchange E2EE text through native Nodes.

Component acceptance with preselected synthetic signed pairs, not UI pairing.
Usage: python remote_account_test.py NODE_HOST ACCOUNT_PROBE PRIVATE_FIXTURE_DIR PRIVATE_CACHE
"""
import asyncio,hashlib,json,os,pathlib,secrets,shutil,socket,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'native/tests'))
from ipc_delivery_test import mine,checked
from local_ipc_test import send,recv,connect
from fastapi import FastAPI
import uvicorn
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.resource_pow import activation_pow_difficulty


async def main():
    node,probe,fixture_dir,cache=sys.argv[1:]
    actors=[];owners=[];pipes=[];logs=[];server=None;server_task=None;service=None;phase='identity'
    folder=pathlib.Path(tempfile.mkdtemp(prefix='remote-account-',dir=cache));folder.chmod(0o700)
    succeeded=False
    async def owner(index):
        directory=folder/('owner-'+str(index));directory.mkdir(mode=0o700,exist_ok=True)
        process=await asyncio.create_subprocess_exec(probe,str(pathlib.Path(fixture_dir)/('account-'+str(index)+'.json')),str(directory),str(folder/('ready-'+str(index)+'.json')),stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        owners.append(process);response=json.loads(await asyncio.wait_for(process.stdout.readline(),120));assert response.get('ok') and response['sameAccountPublicId'];return process
    async def call(process,method,**params):
        process.stdin.write(json.dumps(dict(method=method,**params)).encode()+b'\n');await process.stdin.drain()
        raw=await asyncio.wait_for(process.stdout.readline(),120)
        if not raw:raise EOFError('Account owner exited at '+method)
        result=json.loads(raw);assert result.get('ok'),(method,result.get('code'));return result
    async def sync(process):
        value=await call(process,'sync')
        for row in value['rows']:
            if row.get('code'):
                diagnostic=folder/'account-sync-failure.json';diagnostic.write_text(json.dumps(value));diagnostic.chmod(0o600)
                raise AssertionError(row.get('code'))
        return value
    async def established(a,b):
        deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            left,right=await asyncio.gather(sync(a),sync(b))
            if all(any(row.get('status',{}).get('phase')=='ESTABLISHED' for row in page['rows']) for page in [left,right]):return
            await asyncio.sleep(.5)
        raise TimeoutError('actual E2EE handshake')
    try:
        peer,*node_keys=await asyncio.to_thread(lambda:[mine() for _ in range(3)])
        service=NodeServiceV4(peer,folder/'transit');assert activation_pow_difficulty()==22 and service.listener.difficulty is None
        app=FastAPI();app.state.node_v4=service;app.include_router(router)
        listener=socket.socket();listener.bind(('127.0.0.1',0))
        server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16));server_task=asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:await asyncio.sleep(.01)
        ready=[];admins=[];phase='native-start'
        for index,key in enumerate(node_keys):
            parent,child=socket.socketpair();parent.settimeout(15);pipes.append(parent)
            log=os.fdopen(os.open(folder/('node-'+str(index)+'.log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb',buffering=0);logs.append(log)
            process=await asyncio.create_subprocess_exec(node,'--profile',str(folder/('node-'+str(index))),'--bootstrap-fd',str(child.fileno()),pass_fds=[child.fileno()],stdout=log,stderr=log);actors.append(process);child.close()
            bundle=dict(version=1,nodeSeed=key.encode().hex(),storageKey=secrets.token_hex(32),baseNcrh=secrets.token_hex(32),generation=1,directEnabled=False,endpoints=[dict(url=f'ws://127.0.0.1:{listener.getsockname()[1]}/mesh/v4',nodeId=peer.verify_key.encode().hex())])
            send(parent,dict(v=1,type='InstallTransportSession',request_id='remote',generation=1,effective_policy_revision=1,transport_bundle=bundle,principals=[dict(id='account',role='owner',ttl_seconds=1200),dict(id='broker',role='broker',ttl_seconds=1200)]))
            value=await asyncio.to_thread(recv,parent);assert value['type']=='TransportSessionReady';ready.append(value)
            path=folder/('ready-'+str(index)+'.json');path.write_text(json.dumps(value));path.chmod(0o600)
            admin=connect(value,'broker');assert recv(admin)['ok'];admins.append(admin)
        phase='native-authorize';deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            statuses=await asyncio.gather(*(asyncio.to_thread(checked,admin,'node.status',{}) for admin in admins))
            if all(value['connectedPeers']==1 for value in statuses):break
            await asyncio.sleep(.25)
        assert all(value['connectedPeers']==1 for value in statuses)
        phase='Account-import-login';a,b=await asyncio.gather(owner(0),owner(1))
        phase='Account-route-prepare';await asyncio.gather(sync(a),sync(b))
        operation=secrets.token_hex(32);plaintext='native actual encrypted remote text '+secrets.token_hex(24)
        phase='Account-initiate';first=await call(a,'send',operationId=operation,text=plaintext);assert first['value']['transportState']=='HANDSHAKE_PENDING'
        phase='Account-handshake';await established(a,b)
        # Drain handshake controls before arming an application-specific crash.
        await asyncio.gather(sync(a),sync(b));await call(b,'armCrashBeforeConsume')
        phase='Account-send';queued=await call(a,'send',operationId=operation,text=plaintext);assert queued['value']['accepted'] is True
        phase='Account-persist-before-consume';deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            try:await sync(b)
            except EOFError:break
            await sync(a);await asyncio.sleep(.5)
        assert await asyncio.wait_for(b.wait(),10)==73,'recipient Account did not reach durable application commit before consume'
        phase='Account-crash-reopen';b=await owner(1)
        before=await call(b,'history');assert len(before['rows'])==1 and before['rows'][0]['text']==plaintext,'Account durable history absent before replay drain'
        phase='Account-idempotent-drain';await sync(b)
        after=await call(b,'history');assert len(after['rows'])==1 and after['rows'][0]['operationId']==operation
        phase='Account-owner-reopen';await call(b,'reopen');await sync(b)
        again=await call(b,'history');assert again['rows']==after['rows']
        # Actual application ACKs, if received, are separate from mesh custody.
        phase='Account-sender-reopen';await call(a,'reopen');await asyncio.gather(sync(a),sync(b))
        sent=await call(a,'history');assert len(sent['rows'])==1 and sent['rows'][0]['text']==plaintext
        for index in range(2):
            for file in (folder/('node-'+str(index))).iterdir():
                if file.is_file():assert plaintext.encode() not in file.read_bytes()
        result=dict(suite='native-remote-Account-E2EE',status='PASS',admissionDifficulty=22,wireRole='NODE',accounts=2,backendForwarded=service.runtime.stats.get('forwarded'),recipientAccountExitBeforeConsumption=73,recipientHistoryBeforeReplay=1,recipientHistoryAfterReplay=1,recipientHistoryAfterReopen=1,senderHistoryAfterReopen=1,applicationPlaintextDigest=hashlib.sha256(plaintext.encode()).hexdigest(),nodeContainsApplicationPlaintext=False,checks=['actual-retained-Account-Argon2-identities','original-legacy-Kyber-WASM-compatible-E2EE-handshake','signed-bilateral-journal-replayed-with-live-Node-preparation','journal-commit-receipt-before-owner-activate','actual-destination-install-and-durable-job-submit','real-Python-transit-default22','recipient-durable-Account-history-before-Inbox-consume','actual-Account-owner-exit73-before-consume','replay-dedupe-and-token-consumption','both-Account-services-reopen-retain-history'],limits=['preselected synthetic signed contact pairs; UI pairing NOT_RUN','synthetic scoped daemon grants; resident host transport export separate','no mesh custody ACK; only actual Account protocol may report application delivery','Linux component runtime; browser/Android/Windows acceptance separate'])
        print(json.dumps(result),flush=True);succeeded=True
    except BaseException as error:
        # Preserve synthetic identities/DB/logs privately; publish phase/class only.
        (folder/'failure.json').write_text(json.dumps(dict(phase=phase,errorClass=type(error).__name__)))
        (folder/'failure.json').chmod(0o600)
        print(json.dumps(dict(suite='native-remote-Account-E2EE',status='FAIL',phase=phase,errorClass=type(error).__name__,privateDiagnosticDirectory=folder.name)),flush=True)
        raise
    finally:
        for process in owners:
            if process.returncode is None:process.terminate()
        for process in actors:
            if process.returncode is None:process.terminate()
        for process in owners+actors:
            try:await asyncio.wait_for(process.wait(),10)
            except asyncio.TimeoutError:process.kill();await process.wait()
        for pipe in pipes:pipe.close()
        for log in logs:log.close()
        if server:server.should_exit=True
        if server_task:await server_task
        if service:await service.close()
        if succeeded:shutil.rmtree(folder)


if __name__=='__main__':asyncio.run(main())
