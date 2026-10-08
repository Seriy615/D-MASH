import asyncio
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from node_mailbox_v4 import MailboxStore, Grant


class TrustedVerifier:
    """Explicit test trust boundary, not a production authentication fixture."""
    def __init__(self):
        self.live = object()
        self.proof = object()
        self.migration_proof = object()
        self.route_proof = object()
        self.revoked = False
        self.binding = ('7'*64,0,900)
        self.grant = Grant('b'*64,'c'*64,'d'*64,1000,self.live)
    def bind(self, evidence):
        if evidence is not self.proof:
            raise PermissionError('Unverified evidence')
        return self.grant
    def current(self, grant):
        if self.revoked or grant.session is not self.live:
            raise PermissionError('Stale session')
    def route(self, grant, evidence):
        if evidence is not self.route_proof:
            raise PermissionError('Unverified route')
        return self.binding
    def rebind(self, grant, binding):
        if binding != self.binding:
            raise PermissionError('Binding generation/authority mismatch')
    def migration(self, old, new, evidence):
        if evidence is not self.migration_proof:
            raise PermissionError('Two-owner proof missing')


class MailboxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'mailbox.db'
        self.verifier = TrustedVerifier()
        self.now = 100
        self.store = self.open()
        self.cap = self.store.bind(self.verifier.proof)
    def open(self):
        return MailboxStore(self.path,'a'*64,b'k'*32,self.verifier,clock=lambda:self.now)
    async def asyncTearDown(self):
        self.store.close()
        self.tmp.cleanup()
    def put(self, n=1):
        self.store.put(self.cap,f'{n:064x}',b'opaque-ciphertext',500,self.verifier.route_proof)

    async def test_all_snapshot_retains_concurrent_arrival(self):
        for n in range(1,41): self.put(n)
        async def send(rows, guard):
            self.assertEqual(len(rows),40)
            self.put(99)
        self.assertEqual(await self.store.drain(self.cap,send),40)
        received=[]
        async def again(rows, guard): received.extend(rows)
        self.assertEqual(await self.store.drain(self.cap,again),1)
        self.assertEqual(received[0]['delivery'],f'{99:064x}')

    async def test_failure_and_cancellation_release_all(self):
        self.put()
        async def failed(rows, guard):
            self.put(2)
            raise ConnectionError('partial send')
        with self.assertRaises(ConnectionError): await self.store.drain(self.cap,failed)
        entered=asyncio.Event()
        async def blocked(rows, guard):
            entered.set()
            await asyncio.Future()
        task=asyncio.create_task(self.store.drain(self.cap,blocked))
        await entered.wait()
        with self.assertRaises(BlockingIOError): await self.store.drain(self.cap,blocked)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError): await task
        async def send(rows, guard): self.assertEqual(len(rows),2)
        self.assertEqual(await self.store.drain(self.cap,send),2)

    async def test_false_send_and_session_change_retain_snapshot(self):
        self.put()
        async def false(rows, guard): return False
        with self.assertRaises(ConnectionError): await self.store.drain(self.cap,false)
        async def changed(rows, guard): self.verifier.live=object()
        with self.assertRaises(PermissionError): await self.store.drain(self.cap,changed)
        self.verifier.grant=Grant('b'*64,'c'*64,'d'*64,1000,self.verifier.live)
        self.cap=self.store.bind(self.verifier.proof)
        async def send(rows, guard): self.assertEqual(len(rows),1)
        self.assertEqual(await self.store.drain(self.cap,send),1)

    async def test_reopen_fresh_bind_and_key_node_mismatch(self):
        self.put()
        self.store.close()
        for node,key in [('e'*64,b'k'*32),('a'*64,b'z'*32)]:
            with self.assertRaises(Exception): MailboxStore(self.path,node,key,self.verifier)
        self.store=self.open()
        with self.assertRaises(PermissionError): self.store.authority(self.cap)
        self.verifier.live=object()
        with self.assertRaises(PermissionError): self.store.bind(self.verifier.proof)
        self.verifier.grant=Grant('b'*64,'c'*64,'d'*64,1000,self.verifier.live)
        self.cap=self.store.bind(self.verifier.proof)
        async def send(rows, guard): self.assertEqual(len(rows),1)
        self.assertEqual(await self.store.drain(self.cap,send),1)

    async def test_caller_claims_stale_and_expiry_denied(self):
        with self.assertRaises(PermissionError): self.store.bind({'authorized':True})
        with self.assertRaises(PermissionError): self.store.authority({'authorized':True})
        self.now=1000
        with self.assertRaises(PermissionError): self.put()
        self.now=100
        self.verifier.live=object()
        with self.assertRaises(PermissionError): self.put()

    async def test_migration_atomic_idempotent_and_proof_required(self):
        self.put()
        self.verifier.grant=Grant('e'*64,'f'*64,'0'*64,1000,self.verifier.live)
        new=self.store.bind(self.verifier.proof)
        migration='9'*64
        with self.assertRaises(PermissionError): self.store.migrate(self.cap,new,migration,object())
        self.assertTrue(self.store.migrate(self.cap,new,migration,self.verifier.migration_proof))
        self.assertFalse(self.store.migrate(self.cap,new,migration,self.verifier.migration_proof))
        with self.assertRaises(PermissionError): self.put()
        async def send(rows, guard): self.assertEqual(len(rows),1)
        self.assertEqual(await self.store.drain(new,send),1)
        self.verifier.grant=Grant('1'*64,'2'*64,'3'*64,1000,self.verifier.live)
        other=self.store.bind(self.verifier.proof)
        with self.assertRaises(ValueError): self.store.migrate(self.cap,other,migration,self.verifier.migration_proof)

    async def test_migration_retry_after_restart_requires_fresh_two_owner_proof(self):
        self.put()
        old_grant=self.verifier.grant
        self.verifier.grant=Grant('e'*64,'f'*64,'0'*64,1000,self.verifier.live)
        new_grant=self.verifier.grant
        new=self.store.bind(self.verifier.proof)
        self.store.migrate(self.cap,new,'8'*64,self.verifier.migration_proof)
        self.store.close()
        self.store=self.open()
        self.verifier.live=object()
        self.verifier.grant=Grant(old_grant.recipient,old_grant.direction,old_grant.grant_id,1000,self.verifier.live)
        old=self.store.bind(self.verifier.proof)
        with self.assertRaises(PermissionError): self.store.authority(old)
        self.verifier.grant=Grant(new_grant.recipient,new_grant.direction,new_grant.grant_id,1000,self.verifier.live)
        new=self.store.bind(self.verifier.proof)
        self.assertFalse(self.store.migrate(old,new,'8'*64,self.verifier.migration_proof))
        async def send(rows, guard): self.assertEqual(len(rows),1)
        self.assertEqual(await self.store.drain(new,send),1)

    async def test_route_rebind_revocation_and_fragment_expiry(self):
        self.put()
        self.verifier.binding=('7'*64,1,900)
        async def forbidden(rows,guard): self.fail('Unbound record sent')
        self.assertEqual(await self.store.drain(self.cap,forbidden),0)
        self.assertEqual(self.store.last_blocked,1)
        self.verifier.binding=('7'*64,0,900)
        async def expires_between_fragments(rows,guard):
            guard()
            self.now=501
            guard()
            self.fail('Expired second fragment sent')
        with self.assertRaises(PermissionError): await self.store.drain(self.cap,expires_between_fragments)
        self.now=100
        self.verifier.revoked=True
        with self.assertRaises(PermissionError): await self.store.drain(self.cap,forbidden)

    async def test_blocked_binding_does_not_starve_eligible_and_tamper_fails(self):
        self.put(1)
        self.verifier.binding=('8'*64,1,900)
        self.put(2)
        async def send(rows,guard):
            guard()
            self.assertEqual([r['delivery'] for r in rows],[f'{2:064x}'])
        self.assertEqual(await self.store.drain(self.cap,send),1)
        self.assertEqual(self.store.last_blocked,1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM records').fetchone()[0],1)
        self.store.db.execute('UPDATE records SET expires=800')
        with self.assertRaises(ValueError): await self.store.drain(self.cap,send)

    async def test_direction_and_lifetime_and_metadata_quotas(self):
        original=self.verifier.current
        def current(grant):
            original(grant)
            if grant.direction != 'c'*64:
                raise PermissionError('Wrong directional grant')
        self.verifier.current=current
        self.verifier.grant=Grant('b'*64,'f'*64,'d'*64,1000,self.verifier.live)
        with self.assertRaises(PermissionError): self.store.bind(self.verifier.proof)
        self.verifier.grant=Grant('b'*64,'c'*64,'d'*64,1000,self.verifier.live)
        with self.assertRaises(PermissionError):
            self.store.put(self.cap,'1'*64,b'opaque',1001,self.verifier.route_proof)
        self.store.MAX_CAPS=1
        with self.assertRaises(BufferError): self.store.bind(self.verifier.proof)
        self.store.release(self.cap)
        self.cap=self.store.bind(self.verifier.proof)
        self.store.MAX_CAPS=256
        self.store.MAX_OWNERS=1
        self.verifier.grant=Grant('e'*64,'c'*64,'d'*64,1000,self.verifier.live)
        with self.assertRaises(BufferError): self.store.bind(self.verifier.proof)

    async def test_lookup_and_payload_are_encrypted(self):
        self.put()
        self.store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        raw=self.path.read_bytes()
        for secret in [b'a'*64,b'b'*64,b'c'*64,b'd'*64,b'opaque-ciphertext']:
            self.assertNotIn(secret,raw)
        cols=[r[1] for r in self.store.db.execute('PRAGMA table_info(records)')]
        self.assertNotIn('node',cols)
        self.assertNotIn('dnss',cols)
        self.assertNotIn('account',cols)

    async def test_expired_lease_recovered_and_expired_payload_not_sent(self):
        self.put()
        self.store.db.execute("UPDATE records SET lease='abandoned',lease_until=110")
        async def send(rows, guard): self.assertEqual(len(rows),1)
        with self.assertRaises(BlockingIOError): await self.store.drain(self.cap,send)
        self.now=111
        self.assertEqual(await self.store.drain(self.cap,send),1)
        self.put(2)
        self.now=501
        async def forbidden(rows, guard): self.fail('Expired record sent')
        self.assertEqual(await self.store.drain(self.cap,forbidden),0)

if __name__=='__main__': unittest.main()
