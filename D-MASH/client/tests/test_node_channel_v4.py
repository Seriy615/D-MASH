"""Real crypto/work channel integration. Memory wire, no mocked cryptographic success."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from nacl.signing import SigningKey
from backend.crypto import NodeCryptoManager
from backend.secure_session import Handshake
from backend.secure_socket import SecureSocket
from backend.node_admission_v4 import PasswordGate,password_credential
from backend.node_channel_v4 import authorize_node_v4
from backend.node_relationships_v4 import RelationshipStore
from backend.resource_pow import mine_activation_pow

class Wire:
    def __init__(self):self.queue=asyncio.Queue();self.closed=False;self.peer=None
    async def send(self,value):
        if self.closed:raise ConnectionError('closed')
        await self.peer.queue.put(value)
    async def recv(self):
        value=await self.queue.get()
        if value is None:raise ConnectionError('closed')
        return value
    async def close(self,code=1000,reason=''):
        self.closed=True
        await self.peer.queue.put(None)

class NodeChannelTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        def mine():
            while True:
                key=SigningKey.generate()
                if NodeCryptoManager.verify_node_pow(key.verify_key.encode().hex()):return key
        cls.a,cls.b=mine(),mine()
        cls.credential=password_credential('test-only Node password')

    def pair(self):
        i,r=Handshake(self.a,'NODE',version=4),Handshake(self.b,'NODE',version=4)
        auth,a=i.finish(r.respond(i.initiate(),'NODE'),self.b.verify_key.encode().hex())
        b=r.accept(auth)
        x,y=Wire(),Wire();x.peer=y;y.peer=x
        return SecureSocket(x,a),SecureSocket(y,b)

    async def test_two_directions_password_work_reconnect_and_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            stores=[RelationshipStore(Path(tmp)/f'{n}.db',key.verify_key.encode().hex(),bytes([n+1])*32) for n,key in enumerate((self.a,self.b))]
            self.addCleanup(lambda:[store.close() for store in stores])
            original=None
            for _ in range(2):
                sockets=self.pair();gate=PasswordGate(self.credential)
                async def resolve(peer,challenge):return self.credential['key']
                channels=await asyncio.gather(
                    authorize_node_v4(sockets[0],stores[0],peer_password_key=resolve,require_peer_password=True,difficulty=20),
                    authorize_node_v4(sockets[1],stores[1],password_gate=gate,difficulty=20))
                a,b=channels
                self.assertEqual(a.relationship['outbound'],b.relationship['inbound'])
                self.assertEqual(a.relationship['inbound'],b.relationship['outbound'])
                self.assertNotEqual(a.relationship['outbound'],a.relationship['inbound'])
                if original:self.assertEqual(a.relationship,original)
                original=dict(a.relationship)
                await a.send_operation({'type':'TEST_OPAQUE','ciphertext':'test'})
                self.assertEqual(await b.receive_operation(),{'type':'TEST_OPAQUE','ciphertext':'test'})
                gate.revoke_all()
                with self.assertRaises(PermissionError):await b.send_operation({'type':'TEST_OPAQUE'})
                await asyncio.gather(*(channel.close() for channel in channels))

    async def test_wrong_password_never_allocates_relationship(self):
        with tempfile.TemporaryDirectory() as tmp:
            stores=[RelationshipStore(Path(tmp)/f'{n}.db',key.verify_key.encode().hex(),bytes([n+1])*32) for n,key in enumerate((self.a,self.b))]
            self.addCleanup(lambda:[store.close() for store in stores])
            sockets=self.pair();gate=PasswordGate(self.credential)
            async def wrong(peer,challenge):return b'x'*32
            results=await asyncio.gather(authorize_node_v4(sockets[0],stores[0],peer_password_key=wrong,difficulty=20),
                authorize_node_v4(sockets[1],stores[1],password_gate=gate,difficulty=20),return_exceptions=True)
            self.assertTrue(all(isinstance(result,Exception) for result in results))
            self.assertFalse(gate.authorized)
            for store in stores:self.assertEqual(store.db.execute('SELECT COUNT(*) FROM node_relationship_v4').fetchone()[0],0)

    def test_work_cancellation_before_mining(self):
        with self.assertRaises(TimeoutError):mine_activation_pow('node','DNSS','applicant','resource',200,24,cancelled=lambda:True)

    async def test_disconnect_interrupts_resource_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=RelationshipStore(Path(tmp)/'one.db',self.a.verify_key.encode().hex(),b'x'*32)
            self.addCleanup(store.close)
            local,remote=self.pair()
            async def disconnect_after_admission():
                await remote.send_json({'type':'NODE_POLICY','version':4,'difficulty':24,'password_challenge':None})
                await remote.receive_json()
                await remote.send_json({'type':'NODE_ADMISSION','version':4,'proof':None})
                await remote.receive_json()
                await remote.send_json({'type':'NODE_ADMITTED','version':4})
                await remote.receive_json()
                await remote.close()
            peer=asyncio.create_task(disconnect_after_admission())
            with self.assertRaises(ExceptionGroup):
                await asyncio.wait_for(authorize_node_v4(local,store,difficulty=24),5)
            await peer
            self.assertTrue(local.session.closed)
            self.assertIsNone(store.relationship(self.b.verify_key.encode().hex())['inbound'])
