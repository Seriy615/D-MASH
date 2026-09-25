"""Unified v4 Node authorization over an already authenticated secure socket.

Both directions complete password admission and fresh resource work. The returned
channel carries no implicit route or mailbox ownership. This module is not yet
mounted as the production mesh endpoint.
"""
import asyncio
import threading
import time

from .node_admission_v4 import _context, password_proof
from .node_registration_v4 import resource, verify_registration
from .resource_pow import activation_pow_difficulty, mine_activation_pow


def _policy(value):
    if (not isinstance(value,dict) or set(value)!={'type','version','difficulty','password_challenge'}
            or value['type']!='NODE_POLICY' or type(value['version']) is not int or value['version']!=4
            or type(value['difficulty']) is not int or not 20<=value['difficulty']<=24
            or (value['password_challenge'] is not None and not isinstance(value['password_challenge'],dict))):
        raise PermissionError('invalid Node policy')
    return value


class NodeChannelV4:
    def __init__(self,secure,relationship,password_gate):
        self.secure=secure
        self.relationship=dict(relationship)
        self.password_gate=password_gate
        self.closed=False

    def require_authorized(self):
        if self.closed:raise PermissionError('Node channel closed')
        _context(self.secure.session)
        if self.password_gate:self.password_gate.require(self.secure.session)

    async def send_operation(self,operation):
        self.require_authorized()
        await self.secure.send_json(operation)

    async def receive_operation(self):
        self.require_authorized()
        value=await self.secure.receive_json()
        self.require_authorized()
        return value

    async def close(self):
        self.closed=True
        if self.password_gate:self.password_gate.forget(self.secure.session)
        await self.secure.close()


async def authorize_node_v4(secure,relationships,*,password_gate=None,peer_password_key=None,difficulty=None,require_peer_password=False):
    """Symmetric and role-independent. peer_password_key resolves a scoped Kpwd.

    Password resolvers receive only the authenticated peer ID and validated
    challenge. The caller owns credential storage/clearing and listener quotas.
    """
    session=secure.session
    stop=threading.Event()
    try:
        _context(session)
        difficulty=activation_pow_difficulty() if difficulty is None else difficulty
        local_policy=_policy({'type':'NODE_POLICY','version':4,'difficulty':difficulty,
            'password_challenge':password_gate.challenge(session) if password_gate else None})
        async with asyncio.timeout(300):
            await secure.send_json(local_policy)
            remote_policy=_policy(await secure.receive_json())
            challenge=remote_policy['password_challenge']
            if require_peer_password and challenge is None:raise PermissionError('Node password policy downgrade')
            proof=None
            if challenge is not None:
                # Validate profile/bindings/expiry before asking for credentials.
                password_proof(bytes(32),challenge,session)
                if peer_password_key is None:raise PermissionError('Node password credential missing')
                key=await peer_password_key(session.peer_id,challenge)
                proof=password_proof(key,challenge,session)
            await secure.send_json({'type':'NODE_ADMISSION','version':4,'proof':proof})
            admission=await secure.receive_json()
            if (not isinstance(admission,dict) or set(admission)!={'type','version','proof'}
                    or admission['type']!='NODE_ADMISSION' or type(admission['version']) is not int or admission['version']!=4):
                raise PermissionError('invalid Node admission')
            if password_gate:
                if not password_gate.verify(session,admission['proof']):raise PermissionError('Node admission rejected')
            elif admission['proof'] is not None:
                raise PermissionError('unexpected Node password proof')
            admitted={'type':'NODE_ADMITTED','version':4}
            await secure.send_json(admitted)
            response=await secure.receive_json()
            if response!=admitted or type(response.get('version')) is not int:raise PermissionError('Node admission incomplete')
            relationship=relationships.relationship(session.peer_id)
            own_dnss=relationship['outbound']
            work=resource(session.local_id,session.peer_id,own_dnss,session.transcript_hash)
            async def mine_and_send():
                proof=await asyncio.to_thread(mine_activation_pow,session.peer_id,'DNSS',session.local_id,
                    work,int(time.time())+180,remote_policy['difficulty'],cancelled=stop.is_set,
                    deadline=time.monotonic()+180)
                await secure.send_json({'type':'NODE_REGISTER','dnss':own_dnss,'pow':proof})
            async def receive_and_validate():
                value=await secure.receive_json()
                if not verify_registration(session,value,difficulty,expected_dnss=relationship['inbound']):
                    raise PermissionError('Node registration rejected')
                return value
            # Observe disconnect/rejection while mining, instead of burning
            # the entire work deadline after the remote socket has disappeared.
            async with asyncio.TaskGroup() as tasks:
                tasks.create_task(mine_and_send())
                incoming=tasks.create_task(receive_and_validate())
            request=incoming.result()
            if not verify_registration(session,request,difficulty,expected_dnss=relationship['inbound']):
                raise PermissionError('Node registration rejected')
            # Persist peer direction before acknowledgment. Crash/reconnect keeps
            # relationship identity but cannot reuse this socket's resource proof.
            _context(session)
            if password_gate:password_gate.require(session)
            relationship=relationships.relationship(session.peer_id,inbound=request['dnss'])
            accepted={'type':'NODE_AUTHORIZED','version':4,'dnss':request['dnss']}
            await secure.send_json(accepted)
            response=await secure.receive_json()
            if response!={'type':'NODE_AUTHORIZED','version':4,'dnss':own_dnss} or type(response.get('version')) is not int:
                raise PermissionError('Node authorization incomplete')
            channel=NodeChannelV4(secure,relationship,password_gate)
            channel.require_authorized()
            return channel
    except BaseException:
        stop.set()
        if password_gate:password_gate.forget(session)
        await secure.close(code=1008,reason='Node authorization ended')
        raise
    finally:
        stop.set()
