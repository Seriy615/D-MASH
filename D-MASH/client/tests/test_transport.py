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
        route_handle = self.db.node_crypto.get_blind_hash("route-handle-b")
        await self.db.add_route_alias(route_handle, "peer-b", 2, health=0.2)

        submission = await self.transport.start_probe(
            "route-handle-b",
            "back-route-a",
            hops=0,
            origin_peer_id="peer-a",
            probe_id="probe-1",
        )
        self.assertEqual(submission.state, "SUBMITTED_TO_ENTRY")
        self.assertEqual(self.node.calls[0]["packet"]["type"], "DMP_C_PROBE")
        self.assertEqual(self.node.calls[0]["packet"]["route_id"], "route-handle-b")
        self.assertEqual(self.node.calls[0]["exclude_peer_id"], "peer-a")

        await self.transport.receive_probe(self.node.calls[0]["packet"], "peer-a", is_destination=True)

        back_route = await self.db.get_best_route_alias(self.db.node_crypto.get_blind_hash("back-route-a"))
        self.assertEqual(back_route["next_hop_id"], "peer-a")
        self.assertFalse(back_route["is_local"])

        destination_route = await self.db.get_best_route_alias(route_handle)
        self.assertEqual(destination_route["next_hop_id"], "LOCAL")
        self.assertTrue(destination_route["is_local"])

    async def test_submit_envelope_uses_route_alias_and_not_raw_locator(self):
        raw_locator = "pairing-locator-that-must-not-leak"
        locator_handle = await self.transport.register_inbound_locator(raw_locator)

        await self.db.add_route_alias(locator_handle, "LOCAL", 0, is_local=True)
        result = await self.transport.submit_envelope(
            raw_locator,
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
        inbound_handle = await self.transport.register_inbound_locator("inbound-locator")
        await self.db.add_route_alias(inbound_handle, "LOCAL", 0, is_local=True)
        await self.db.conn.execute(
            "INSERT INTO offline_mailbox (target_hash, packet_json, notification_id) VALUES (?, ?, ?)",
            (inbound_handle, json.dumps({"id": "delivery-9", "envelope": {"ciphertext": "payload"}}), "notif-9"),
        )
        await self.db.conn.commit()

        packets = await self.transport.pull(inbound_handle)
        self.assertEqual(packets[0]["id"], "delivery-9")
        async with self.db.conn.execute("SELECT COUNT(*) AS cnt FROM offline_mailbox") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["cnt"], 1)

        self.assertTrue(await self.transport.ack("delivery-9"))
        async with self.db.conn.execute("SELECT COUNT(*) AS cnt FROM offline_mailbox") as cursor:
            row = await cursor.fetchone()
        self.assertEqual(row["cnt"], 0)

    async def test_disarming_locator_removes_only_its_blind_route_and_mailbox(self):
        locator = "locator-to-forget"
        keep_locator = "locator-to-keep"
        locator_handle = await self.transport.register_inbound_locator(locator)
        keep_handle = await self.transport.register_inbound_locator(keep_locator)
        await self.db.add_route_alias(locator_handle, "LOCAL", 0, is_local=True)
        await self.db.add_route_alias(keep_handle, "LOCAL", 0, is_local=True)
        await self.db.conn.execute(
            "INSERT INTO offline_mailbox (target_hash, packet_json, notification_id) VALUES (?, ?, ?)",
            (locator_handle, json.dumps({"id": "forget"}), "notification-forget"),
        )
        await self.db.conn.execute(
            "INSERT INTO offline_mailbox (target_hash, packet_json, notification_id) VALUES (?, ?, ?)",
            (keep_handle, json.dumps({"id": "keep"}), "notification-keep"),
        )
        await self.db.conn.commit()

        self.assertTrue(await self.transport.unregister_inbound_locator(locator))
        self.assertFalse(await self.db.is_armed_locator(locator))
        self.assertTrue(await self.db.is_armed_locator(keep_locator))
        self.assertIsNone(await self.db.get_best_route_alias(locator_handle))
        self.assertIsNotNone(await self.db.get_best_route_alias(keep_handle))
        self.assertEqual(await self.transport.pull(locator_handle), [])
        self.assertEqual([packet["id"] for packet in await self.transport.pull(keep_handle)], ["keep"])

    async def test_destination_probe_records_candidate_hops_plus_one(self):
        packet = {
            "type": "DMP_C_PROBE",
            "id": "probe-short",
            "route_id": "route-b",
            "back_route_id": "back-a",
            "hops": 2,
            "ttl": 10,
        }
        await self.transport.receive_probe(packet, "peer-n2", is_destination=True)
        route = await self.db.get_best_route_alias(self.db.node_crypto.get_blind_hash("route-b"))
        self.assertEqual(route["hops"], 3)
        self.assertEqual(route["next_hop_id"], "LOCAL")

    async def test_transit_packet_has_no_recipient_identity_or_plaintext(self):
        route_handle = self.db.node_crypto.get_blind_hash("route-transit")
        await self.db.add_route_alias(route_handle, "peer-next", 1)
        envelope = {"version": 1, "ciphertext": "sealed-by-pwa"}
        result = await self.transport.submit_envelope("route-transit", envelope)
        packet = self.node.calls[-1]["packet"]
        self.assertEqual(result.state, "SUBMITTED_TO_ENTRY")
        self.assertNotIn("recipient", packet)
        self.assertNotIn("recipient_id", packet)
        self.assertNotIn("plaintext", packet)
        self.assertEqual(packet["envelope"]["ciphertext"], "sealed-by-pwa")

    async def test_probe_convergence_replaces_first_long_path_with_short_path(self):
        long_probe = {
            "type": "DMP_C_PROBE", "id": "probe-graph",
            "route_id": "route-graph", "back_route_id": "back-graph",
            "hops": 4, "ttl": 10,
        }
        short_probe = {**long_probe, "hops": 2}
        self.assertTrue(await self.transport.receive_probe(long_probe, "peer-long", is_destination=True))
        self.assertTrue(await self.transport.receive_probe(short_probe, "peer-short", is_destination=True))
        route = await self.db.get_best_route_alias(self.db.node_crypto.get_blind_hash("route-graph"))
        self.assertEqual(route["hops"], 3)
        self.assertEqual(route["next_hop_id"], "LOCAL")


if __name__ == "__main__":
    unittest.main()
