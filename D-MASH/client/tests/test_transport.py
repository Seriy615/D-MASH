import json
import os
import hashlib
import tempfile
import unittest

from backend.database import DatabaseManager
from backend.transport import NodeTransportService


class FakeNodeCrypto:
    def get_blind_hash(self, value):
        return "blind:" + value

    def encrypt_for_self(self, value):
        return json.dumps(value, sort_keys=True)

    def decrypt_from_self(self, value):
        return json.loads(value)


class NonLeakingFakeNodeCrypto(FakeNodeCrypto):
    def get_blind_hash(self, value):
        return "blind:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class FakeNode:
    def __init__(self):
        self.calls = []

    async def enqueue_transport_packet(self, packet, *, next_hop_id=None, exclude_peer_id=None):
        self.calls.append({
            "packet": packet,
            "next_hop_id": next_hop_id,
            "exclude_peer_id": exclude_peer_id,
        })


class OpaqueTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fd, self.path = tempfile.mkstemp(prefix="dmash-transport-", suffix=".db")
        os.close(fd)
        self.db = DatabaseManager(self.path)
        self.db.set_node_crypto(NonLeakingFakeNodeCrypto())
        await self.db.connect()
        self.node = FakeNode()
        self.transport = NodeTransportService(self.db, self.node)

    async def asyncTearDown(self):
        await self.db.close()
        os.unlink(self.path)

    async def test_probe_propagation_updates_back_route_and_marks_destination_local(self):
        await self.db.add_route_alias("route-handle-b", "peer-b", 2, health=0.2)

        submission = await self.transport.start_probe(
            "route-handle-b",
            "back-route-a",
            hops=0,
            origin_peer_id="peer-a",
            probe_id="probe-1",
        )
        self.assertEqual(submission.state, "SUBMITTED_TO_ENTRY")
        self.assertEqual(self.node.calls[0]["packet"]["type"], "DMP_C_PROBE")
        self.assertEqual(self.node.calls[0]["exclude_peer_id"], "peer-a")

        await self.transport.receive_probe(self.node.calls[0]["packet"], "peer-a", is_destination=True)

        back_route = await self.db.get_best_route_alias("back-route-a")
        self.assertEqual(back_route["next_hop_id"], "peer-a")
        self.assertFalse(back_route["is_local"])

        destination_route = await self.db.get_best_route_alias("route-handle-b")
        self.assertEqual(destination_route["next_hop_id"], "LOCAL")
        self.assertTrue(destination_route["is_local"])

    async def test_submit_envelope_uses_route_alias_and_not_raw_locator(self):
        raw_locator = "pairing-locator-that-must-not-leak"
        locator_handle = await self.transport.register_inbound_locator(raw_locator)

        await self.db.add_route_alias(locator_handle, "LOCAL", 0, is_local=True)
        result = await self.transport.submit_envelope(
            locator_handle,
            {"packet_id": "packet-1", "ciphertext": "abc"},
        )

        self.assertEqual(result.state, "DELIVERED_TO_DESTINATION_NODE")
        async with self.db.conn.execute("SELECT binding_hash, user_blob FROM local_bindings") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["binding_hash"], locator_handle)
        self.assertNotIn(raw_locator, row["user_blob"])

        async with self.db.conn.execute("SELECT target_hash, packet_json FROM offline_mailbox") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["target_hash"], locator_handle)
        self.assertNotIn(raw_locator, row["packet_json"])

    async def test_pull_and_ack_keep_envelopes_opaque_until_ack(self):
        await self.db.add_route_alias("inbound-handle", "LOCAL", 0, is_local=True)
        await self.db.conn.execute(
            "INSERT INTO offline_mailbox (target_hash, packet_json, notification_id) VALUES (?, ?, ?)",
            ("inbound-handle", json.dumps({"id": "delivery-9", "route_alias": "inbound-handle", "envelope": {"ciphertext": "payload"}}), "notif-9"),
        )
        await self.db.conn.commit()

        packets = await self.transport.pull("inbound-handle")
        self.assertEqual(packets[0]["id"], "delivery-9")
        async with self.db.conn.execute("SELECT COUNT(*) AS cnt FROM offline_mailbox") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["cnt"], 1)

        self.assertTrue(await self.transport.ack("delivery-9"))
        async with self.db.conn.execute("SELECT COUNT(*) AS cnt FROM offline_mailbox") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["cnt"], 0)


if __name__ == "__main__":
    unittest.main()
