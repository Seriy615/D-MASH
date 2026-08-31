import json
import os
import tempfile
import unittest

from backend.crypto import NodeCryptoManager
from backend.database import DatabaseManager


class FakeNodeCrypto:
    def get_blind_hash(self, value):
        return "blind:" + value

    def encrypt_for_self(self, value):
        return json.dumps(value, sort_keys=True)

    def decrypt_from_self(self, value):
        return json.loads(value)


class BlindRouteStorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fd, self.path = tempfile.mkstemp(prefix="dmash-route-", suffix=".db")
        os.close(fd)
        self.db = DatabaseManager(self.path)
        self.db.set_node_crypto(FakeNodeCrypto())
        await self.db.connect()

    async def asyncTearDown(self):
        await self.db.close()
        os.unlink(self.path)

    async def test_locator_is_armed_by_alias_only(self):
        raw_locator = "pairing-locator-that-must-not-be-persisted"
        alias = await self.db.arm_inbound_locator(raw_locator)
        self.assertEqual(alias, "blind:" + raw_locator)
        self.assertTrue(await self.db.is_armed_locator(raw_locator))
        async with self.db.conn.execute("SELECT binding_hash, user_blob FROM local_bindings") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["binding_hash"], alias)
        self.assertNotIn(raw_locator, row["user_blob"])

    async def test_shortest_route_replaces_longer_candidate_and_tie_uses_health(self):
        alias = "blind:route-a"
        await self.db.add_route_alias(alias, "peer-long", 5, health=0.9)
        await self.db.add_route_alias(alias, "peer-short", 3, health=0.1)
        await self.db.add_route_alias(alias, "peer-tie", 3, health=0.8)
        best = await self.db.get_best_route_alias(alias)
        self.assertEqual(best["next_hop_id"], "peer-tie")
        self.assertEqual(best["hops"], 3)
        async with self.db.conn.execute("SELECT route_in_hash, routing_blob FROM blind_routes") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["route_in_hash"], alias)
        self.assertNotIn("route-a", row["routing_blob"])

    def test_real_node_blind_alias_is_stable_but_identity_scoped(self):
        locator = "opaque-routing-locator"
        node_a = NodeCryptoManager("11" * 32)
        restarted_node_a = NodeCryptoManager("11" * 32)
        node_b = NodeCryptoManager("22" * 32)

        self.assertEqual(node_a.get_blind_hash(locator), restarted_node_a.get_blind_hash(locator))
        self.assertNotEqual(node_a.get_blind_hash(locator), node_b.get_blind_hash(locator))
        self.assertNotIn(locator, node_a.get_blind_hash(locator))


if __name__ == "__main__":
    unittest.main()
