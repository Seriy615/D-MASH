"""First send is durable before remote activation; actual host crash and automatic delivery.
Usage: python native_private_pairing_test.py CREDENTIAL_HOST NODE_HOST PRIVATE_CACHE
All setup uses normal host APIs; no injected contact, route or journal fixtures.
"""
import asyncio,hashlib,json,os,pathlib,secrets,shutil,socket,sqlite3,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'native/tests'))
from ipc_delivery_test import mine
from local_ipc_test import send,recv
from fastapi import FastAPI
import uvicorn
from backend.node_service_v4 import NodeServiceV4
from backend.gateway_v4 import router
from backend.resource_pow import activation_pow_difficulty

async def main():
    host,node,cache=sys.argv[1:];reused=os.environ.get('DMASH_REUSE_PRIVATE_PAIRING_PROFILE');folder=pathlib.Path(tempfile.mkdtemp(prefix='private-pairing-',dir=cache));folder.chmod(0o700)
    if reused:shutil.copytree(reused,folder,dirs_exist_ok=True) # Preserve original failure/identities; operate only on an owning synthetic copy.
    processes=[];clients=[];logs=[];timings=[];server=task=service=None;phase='identity';success=False
    async def call(index,method,params=None):
        started=time.monotonic();send(clients[index],dict(v=1,id='pairing',method=method,params=params or {}))
        try:reply=await asyncio.to_thread(recv,clients[index])
        finally:timings.append(dict(owner=index,method=method,elapsedMs=round((time.monotonic()-started)*1000)))
        if not reply.get('ok'):
            p=folder/'rpc-failure.json';p.write_text(json.dumps(dict(method=method,response=reply)));p.chmod(0o600)
            raise AssertionError(method+':'+reply.get('code','UNKNOWN'))
        return reply['result']
    async def sync(index):
        value=await call(index,'account.sync')
        for row in value['rows']:
            if row.get('code'):raise AssertionError('account.sync:'+row['code'])
        return value
    try:
        peer=await asyncio.to_thread(mine);service=NodeServiceV4(peer,folder/('transit-current-'+secrets.token_hex(6)));assert activation_pow_difficulty()==22 and service.listener.difficulty is None
        app=FastAPI();app.state.node_v4=service;app.include_router(router);listener=socket.socket();listener.bind(('127.0.0.1',0))
        server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',ws_max_size=2*1024*1024,ws_max_queue=16));task=asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:await asyncio.sleep(.01)
        endpoints=[dict(url=f'ws://127.0.0.1:{listener.getsockname()[1]}/mesh/v4',nodeId=peer.verify_key.encode().hex())];inputs=json.loads((folder/'private-inputs.json').read_text()) if reused else [];accounts=[];previous_nodes=[]
        phase='fresh-hosts'
        for index in range(2):
            profile=folder/('owner-'+str(index));profile.mkdir(mode=0o700,exist_ok=bool(reused));receipt=profile/'node/supervisor-child.json';previous_nodes.append(json.loads(receipt.read_text())['nodeId'] if reused and receipt.exists() else None)
            log=os.fdopen(os.open(folder/('owner-'+str(index)+'.log'),os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600),'ab',buffering=0);logs.append(log)
            process=await asyncio.create_subprocess_exec(host,'--profile',str(profile),'--node-host',node,stdout=log,stderr=log);processes.append(process)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                try:
                    locator=json.loads((profile/'credential-endpoint.json').read_text());channel=socket.socket(socket.AF_UNIX);channel.settimeout(240);channel.connect(locator['endpoint']);clients.append(channel);break
                except (OSError,ValueError):await asyncio.sleep(.05)
            assert len(clients)==index+1
            if reused:
                private=inputs[index];assert private['identity'].startswith('native-private-')
                await call(index,'root.unlock',dict(pin=private['pin']))
            else:
                private=dict(pin=secrets.token_hex(24),identity='native-private-'+str(index)+'-'+secrets.token_hex(6),password=secrets.token_hex(32));inputs.append(private)
                (folder/'private-inputs.json').write_text(json.dumps(inputs));(folder/'private-inputs.json').chmod(0o600)
                assert (await call(index,'profile.create',dict(pin=private['pin'])))['rows']==[]
                await call(index,'account.create',dict(identity=private['identity'],password=private['password'],displayName='Synthetic private peer'))
            logged=await call(index,'account.login',dict(identity=private['identity'],password=private['password']));accounts.append(logged['value']['accountPublicId'])
            assert not [row for row in (await call(index,'account.contacts'))['rows'] if len(row['id'])==64]
        phase='native-enable';await asyncio.gather(*(call(i,'node.enable',dict(endpoints=endpoints,directEnabled=False)) for i in range(2)))
        phase='native-authorize';deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            states=await asyncio.gather(*(call(i,'host.status') for i in range(2)))
            if all(state['value']['node']['connectedPeers']==1 for state in states):break
            await asyncio.sleep(.25)
        assert all(state['value']['node']['connectedPeers']==1 and state['value']['node']['bootstrapProfile']=='private-v1' for state in states)
        if reused:assert all(state['value']['node']['nodeId']==previous_nodes[i] for i,state in enumerate(states))
        phase='private-offer'
        if reused:
            prior=(await call(0,'account.pairingOffers'))['rows'];assert prior and not prior[0].get('pending');offer=prior[0]
        else:offer=(await call(0,'account.pairingCreate',dict(expectedPeer=accounts[1])))['value']
        inspected=(await call(1,'account.pairingInspect',dict(bundle=offer['bundle'],expectedPeer=accounts[0])))['value'];assert inspected['accountPublic']==accounts[0]
        phase='private-request';await call(1,'account.pairingRequest',dict(bundle=offer['bundle'],expectedPeer=accounts[0]))
        phase='bilateral-explicit-confirm';active=[False,False];deadline=time.monotonic()+150
        activation_started=time.monotonic();activation_times=[None,None];early_submissions=[None,None]
        operations=[secrets.token_hex(32) for _ in range(2)];plaintexts=['Actual private paired direction '+str(i)+' '+secrets.token_hex(24) for i in range(2)]
        first_sender=None;reopened=False
        async def reopen_owner(index):
            nonlocal reopened
            profile=folder/('owner-'+str(index));prior=json.loads((profile/'node/supervisor-child.json').read_text())
            await call(index,'account.logout');await call(index,'account.login',dict(identity=inputs[index]['identity'],password=inputs[index]['password']))
            row=(await call(index,'account.history',dict(peer=accounts[1-index])))['rows'];assert len(row)==1 and row[0]['operationId']==operations[index] and row[0]['state']=='HANDSHAKE_PENDING'
            clients[index].close();processes[index].kill();assert await processes[index].wait()!=0
            # Verify actual lease-EOF child exit, rather than infer it from timeout.
            exit_deadline=time.monotonic()+15
            while time.monotonic()<exit_deadline:
                try:state=pathlib.Path('/proc/'+str(prior['pid'])+'/stat').read_text().split(') ',1)[1].split()[0]
                except FileNotFoundError:break
                if state=='Z':break
                await asyncio.sleep(.05)
            else:raise AssertionError('owned Node did not exit after owner crash')
            log=os.fdopen(os.open(folder/('owner-'+str(index)+'-reopen.log'),os.O_WRONLY|os.O_CREAT,0o600),'wb',buffering=0);logs.append(log)
            process=await asyncio.create_subprocess_exec(host,'--profile',str(profile),'--node-host',node,stdout=log,stderr=log);processes[index]=process
            connect_deadline=time.monotonic()+15
            while time.monotonic()<connect_deadline:
                try:
                    locator=json.loads((profile/'credential-endpoint.json').read_text());channel=socket.socket(socket.AF_UNIX);channel.settimeout(240);channel.connect(locator['endpoint']);clients[index]=channel;break
                except (OSError,ValueError):await asyncio.sleep(.05)
            else:raise AssertionError('owner unavailable after crash')
            await call(index,'root.unlock',dict(pin=inputs[index]['pin']));logged=await call(index,'account.login',dict(identity=inputs[index]['identity'],password=inputs[index]['password']));assert logged['value']['accountPublicId']==accounts[index]
            row=(await call(index,'account.history',dict(peer=accounts[1-index])))['rows'];assert len(row)==1 and row[0]['operationId']==operations[index] and row[0]['state']=='HANDSHAKE_PENDING'
            await call(index,'node.enable',dict(endpoints=endpoints,directEnabled=False));after=json.loads((profile/'node/supervisor-child.json').read_text());assert after['nodeId']==prior['nodeId'] and after['generation']>prior['generation'];reopened=True
        async def advance(index):
            nonlocal first_sender
            if active[index]:return
            page=await call(index,'account.pairingOffers')
            for item in page['rows']:
                assert not item.get('pending'),item.get('code')
                for request in item['requests']:
                    if request.get('state') in ['DENIED','EXPIRED_SELECTED']:continue
                    result=(await call(index,'account.pairingAdvance',dict(id=item['id'],exchangeId=request['exchangeId'],requestDigest=request['requestDigest'],expectedPeer=accounts[1-index],deny=False,name='Actual private contact')))['value']
                    if result.get('ready'):
                        assert result['contactPublished'];active[index]=True;activation_times[index]=round((time.monotonic()-activation_started)*1000)
                        early_submissions[index]=(await call(index,'account.sendText',dict(peer=accounts[1-index],operationId=operations[index],text=plaintexts[index])))['value']
                        assert early_submissions[index]['accepted'] is True
                        if first_sender is None:
                            assert not active[1-index];first_sender=index
                            assert early_submissions[index]['transportState']=='HANDSHAKE_PENDING'
                            row=(await call(index,'account.history',dict(peer=accounts[1-index])))['rows'];assert len(row)==1 and row[0]['operationId']==operations[index] and row[0]['text']==plaintexts[index] and row[0]['state']=='HANDSHAKE_PENDING'
                            await reopen_owner(index)
                        return
        # A real user may accept one side before accepting the other. Do not
        # advance that other UI while checking first-send durability/recovery.
        while time.monotonic()<deadline and not all(active):
            for i in range(2):await advance(i)
            await asyncio.sleep(.5)
        assert all(active),'bilateral real pairing activation incomplete'
        phase='Account-handshake';deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            pages=await asyncio.gather(sync(0),sync(1))
            last=folder/'last-sync.json';last.write_text(json.dumps(pages));last.chmod(0o600)
            if all(any(row.get('status',{}).get('phase')=='ESTABLISHED' for row in page['rows']) for page in pages):break
            await asyncio.sleep(.5)
        assert all(any(row.get('status',{}).get('phase')=='ESTABLISHED' for row in page['rows']) for page in pages),'actual paired E2EE handshake not established'
        phase='automatic-first-send-bilateral-delivery';assert reopened and first_sender is not None
        # NO caller sendText retry after either original click.
        deadline=time.monotonic()+90;histories=[]
        while time.monotonic()<deadline:
            await asyncio.gather(sync(0),sync(1));histories=[(await call(i,'account.history',dict(peer=accounts[1-i])))['rows'] for i in range(2)]
            if all(len(history)==2 for history in histories):break
            await asyncio.sleep(.5)
        expected=dict(zip(operations,plaintexts))
        for history in histories:assert len(history)==2 and {row['operationId']:row['text'] for row in history}==expected
        phase='paired-reopen'
        for i in range(2):
            await call(i,'account.logout');await call(i,'account.login',dict(identity=inputs[i]['identity'],password=inputs[i]['password']))
            history=(await call(i,'account.history',dict(peer=accounts[1-i])))['rows']
            assert len(history)==2 and {row['operationId']:row['text'] for row in history}==expected
        print(json.dumps(dict(suite='actual-native-private-pending-send',status='PASS',freshRoots=0 if reused else 2,freshAccounts=0 if reused else 2,retainedRootsAccountsNodes=2 if reused else 0,preinjectedContacts=0,preinjectedRoutes=0,actualSignedRequestAcceptConfirm=True,actualNativeKyber=True,bothContactsPublished=True,backendForwarded=service.runtime.stats.get('forwarded'),recipientHistory=2,bothAccountReopenHistory=2,firstSendBeforeOtherReady=True,accountLogoutReopenPending=True,ownerSigkillReopenPending=True,sameAccountAndNodeIdentity=True,activationElapsedMs=activation_times,immediateSendStates=[v['transportState'] for v in early_submissions],callerManualRetry=False,originalSendCalls=2,plaintextDigests=[hashlib.sha256(v.encode()).hexdigest() for v in plaintexts],limits=['Linux component API simulates one send click per owner; actual platform UI NOT_RUN','configured WS loopback Python transit; NAT/self-organization NOT_RUN','ACK-free mesh baseline unchanged'])),flush=True);success=True
    except BaseException as error:
        job_states=[]
        for i in range(2):
            try:
                with sqlite3.connect('file:'+str(folder/('owner-'+str(i))/'node/node.sqlite')+'?mode=ro',uri=True) as db:job_states.append(dict(db.execute('SELECT state,count(*) FROM native_jobs GROUP BY state').fetchall()))
            except sqlite3.Error:job_states.append({})
        value=dict(suite='actual-native-private-pending-send',status='FAIL',phase=phase,errorClass=type(error).__name__,privateDiagnosticDirectory=folder.name,rpcTimings=timings,nodeJobStates=job_states)
        (folder/'failure.json').write_text(json.dumps(value));(folder/'failure.json').chmod(0o600)
        print(json.dumps({k:v for k,v in value.items() if k!='rpcTimings'}),flush=True);raise
    finally:
        for client in clients:client.close()
        for process in processes:
            if process.returncode is None:process.terminate()
            try:await asyncio.wait_for(process.wait(),15)
            except asyncio.TimeoutError:process.kill();await process.wait()
        for log in logs:log.close()
        if server:server.should_exit=True
        if task:await task
        if service:await service.close()
        if success:shutil.rmtree(folder)
if __name__=='__main__':asyncio.run(main())
