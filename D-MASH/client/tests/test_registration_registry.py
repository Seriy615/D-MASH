import os
import sqlite3
import tempfile
import unittest

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from backend.crypto import NodeCryptoManager
from backend.entry_grant import EntryGrantV1
from backend.registration_registry import RegistrationRegistry


class RegistrationRegistryTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(prefix="dmash-registration-", suffix=".sqlite")
        os.close(handle)
        self.node_key = SigningKey(b"\x11" * 32)
        self.node = NodeCryptoManager(self.node_key.encode(encoder=HexEncoder).decode("ascii"))
        self.route_key = SigningKey(b"\x22" * 32)
        self.route_public_key = self.route_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
        self.registry = RegistrationRegistry(self.path, self.node)

    def tearDown(self):
        self.registry.close()
        os.unlink(self.path)

    def grant(self, expires_at=2_000):
        return EntryGrantV1.issue(self.node_key, self.route_public_key, expires_at)

    def test_persists_only_node_scoped_blind_dnss_hash_and_survives_reopen(self):
        dnss = b"raw-dnss-value!!"  # exactly 128 bits; must never enter SQLite
        grant = self.grant()
        registered = self.registry.register(dnss, grant, now=1_000)
        self.assertEqual(registered.route_id, grant.route_id)
        self.assertEqual(self.registry.lookup(dnss, now=1_001).grant, grant)

        self.registry.close()
        self.registry = RegistrationRegistry(self.path, NodeCryptoManager(self.node_key.encode(encoder=HexEncoder).decode("ascii")))
        restored = self.registry.lookup(dnss, now=1_001)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.route_public_key, self.route_public_key)

        connection = sqlite3.connect(self.path)
        dump = " ".join(str(cell) for row in connection.iterdump() for cell in (row,))
        connection.close()
        self.assertNotIn(dnss.decode("ascii"), dump)
        self.assertIn(self.registry.blind_hash(dnss), dump)

    def test_hash_is_stable_for_node_but_node_scoped(self):
        dnss = b"raw-dnss-value!!"
        same_node = NodeCryptoManager(self.node_key.encode(encoder=HexEncoder).decode("ascii"))
        with RegistrationRegistry(self.path, same_node) as restarted_registry:
            self.assertEqual(self.registry.blind_hash(dnss), restarted_registry.blind_hash(dnss))
        # Use an independent database to avoid the intentional ownership guard.
        other_key = SigningKey(b"\x33" * 32)
        other_node = NodeCryptoManager(other_key.encode(encoder=HexEncoder).decode("ascii"))
        handle, other_path = tempfile.mkstemp(prefix="dmash-registration-other-", suffix=".sqlite")
        os.close(handle)
        try:
            with RegistrationRegistry(other_path, other_node) as other_registry:
                self.assertNotEqual(self.registry.blind_hash(dnss), other_registry.blind_hash(dnss))
        finally:
            os.unlink(other_path)

    def test_expired_registration_is_not_returned_and_can_be_purged(self):
        dnss = b"raw-dnss-value!!"
        self.registry.register(dnss, self.grant(expires_at=1_010), now=1_000)
        self.assertIsNone(self.registry.lookup(dnss, now=1_010))
        self.assertEqual(self.registry.purge_expired(now=1_010), 0)  # lookup removed it

        self.registry.register(dnss, self.grant(expires_at=1_020), now=1_011)
        self.assertEqual(self.registry.purge_expired(now=1_020), 1)
        self.assertIsNone(self.registry.lookup(dnss, now=1_020))

    def test_rejects_expired_or_other_node_grants_and_cross_node_database_open(self):
        dnss = b"raw-dnss-value!!"
        with self.assertRaises(ValueError):
            self.registry.register(dnss, self.grant(expires_at=1_000), now=1_000)

        other_signing_key = SigningKey(b"\x44" * 32)
        other_route = other_signing_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
        other_grant = EntryGrantV1.issue(other_signing_key, other_route, expires_at=2_000)
        with self.assertRaises(ValueError):
            self.registry.register(dnss, other_grant, now=1_000)

        other_node = NodeCryptoManager(other_signing_key.encode(encoder=HexEncoder).decode("ascii"))
        with self.assertRaisesRegex(ValueError, "different node"):
            RegistrationRegistry(self.path, other_node)


if __name__ == "__main__":
    unittest.main()
