import concurrent.futures
import sqlite3
import tempfile
from pathlib import Path
import unittest
from backend.node_relationships_v4 import RelationshipStore

class RelationshipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'relationships.db'
        self.local, self.peer, self.key = 'aa'*32,'bb'*32,b'k'*32

    def open(self):
        return RelationshipStore(self.path,self.local,self.key)

    def test_restart_and_independent_direction(self):
        store=self.open(); first=store.relationship(self.peer); store.close()
        self.assertIsNone(first['inbound'])
        store=self.open()
        second=store.relationship(self.peer,inbound='cd'*16)
        self.assertEqual(second['outbound'],first['outbound'])
        self.assertNotEqual(second['outbound'],second['inbound'])
        with self.assertRaises(PermissionError):store.relationship(self.peer,inbound='ef'*16)
        with self.assertRaises(PermissionError):store.relationship(self.peer,inbound=first['outbound'])
        self.assertEqual(store.relationship(self.peer),second)
        store.close()
        raw=self.path.read_bytes()
        for secret in (self.local,self.peer,second['outbound'],second['inbound']):
            self.assertNotIn(secret.encode(),raw)

    def test_wrong_root_or_identity_cannot_silently_create_relationship(self):
        store=self.open(); first=store.relationship(self.peer);store.close()
        for local,key in [(self.local,b'x'*32),('cc'*32,self.key)]:
            with self.assertRaises(Exception):RelationshipStore(self.path,local,key)
        store=self.open();self.assertEqual(store.relationship(self.peer),first);store.close()

    def test_parallel_open_and_registration_have_one_durable_direction(self):
        def use(_):
            store=self.open()
            try:return store.relationship(self.peer,inbound='cd'*16)
            finally:store.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results=list(pool.map(use,range(12)))
        self.assertTrue(all(row==results[0] for row in results))

    def test_corrupt_ciphertext_is_preserved_and_rejected(self):
        store=self.open();store.relationship(self.peer);store.close()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE node_relationship_v4 SET ciphertext=?',(b'corrupt',))
        store=self.open()
        try:
            with self.assertRaisesRegex(ValueError,'recovery required'):store.relationship(self.peer)
            self.assertEqual(store.db.execute('SELECT ciphertext FROM node_relationship_v4').fetchone()[0],b'corrupt')
        finally:store.close()

    def test_quota_does_not_evict_existing_relationships(self):
        store=RelationshipStore(self.path,self.local,self.key,max_relationships=1)
        try:
            original=store.relationship(self.peer)
            with self.assertRaises(PermissionError):store.relationship('cc'*32)
            self.assertEqual(store.relationship(self.peer),original)
        finally:store.close()
