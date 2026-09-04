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


class FakeDeliverySession:
    def __init__(self):
        self.messages = []

    async def send_json(self, message):
        self.messages.append(message)


class OpaqueTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fd, self.path = tempfile.mkstemp(prefix="dmash-transport-", suffix=".db")
        os.close(fd)
        self.db = DatabaseManager(self.path)
        self.db.set_node_crypto(NonLeakingFakeNodeCrypto())
        await self.db.connect()
        self.node = FakeNode()
        self.transport = NodeTransportService(self.db, self.node, can_route=True, can_accept_devices=True)

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
        self.assertEqual(self.node.calls[0]["packet"]["type"], "ROUTE_PROBE_V2")
        self.assertEqual(self.node.calls[0]["packet"]["route_id"], "route-handle-b")
        self.assertEqual(self.node.calls[0]["packet"]["hop_limit"], 15)
        self.assertGreaterEqual(self.node.calls[0]["packet"]["metric"], 1_000_000)
        self.assertNotIn("hops", self.node.calls[0]["packet"])
        self.assertNotIn("ttl", self.node.calls[0]["packet"])
        self.assertTrue(self.node.calls[0]["packet"]["ncrh"])
        self.assertEqual(self.node.calls[0]["exclude_peer_id"], "peer-a")

        await self.transport.receive_probe(self.node.calls[0]["packet"], "peer-a", is_destination=True)

        back_route = await self.db.get_best_route_alias(self.db.node_crypto.get_blind_hash("back-route-a"))
        self.assertEqual(back_route["next_hop_id"], "peer-a")
        self.assertFalse(back_route["is_local"])

        destination_route = await self.db.get_best_route_alias(route_handle)
        self.assertEqual(destination_route["next_hop_id"], "LOCAL")
        self.assertTrue(destination_route["is_local"])

    async def test_contact_submit_validates_opaque_envelope_and_keeps_reply_route_ephemeral(self):
        await self.db.add_route_alias(self.db.node_crypto.get_blind_hash("contact-route"), "peer", 1)
        envelope = {"version": 1, "type": "CONTACT_REQUEST_V1",
                    "request_id": "a" * 43, "ciphertext": "z" * 43}
        result = await self.transport.submit_contact("contact-route", envelope, reply_route="reply-route")
        self.assertEqual(result.state, "SUBMITTED_TO_ENTRY")
        self.assertEqual(self.transport.contact_reply_route("a" * 43), "reply-route")
        with self.assertRaises(ValueError):
            await self.transport.submit_contact("contact-route", {**envelope, "ciphertext": "%%%"})

    async def test_contact_receive_deduplicates_request_id(self):
        handle = await self.transport.register_inbound_locator("contact-inbox")
        await self.db.add_route_alias(handle, "LOCAL", 0, is_local=True)
        envelope = {"version": 1, "type": "CONTACT_ACCEPT_V1",
                    "request_id": "b" * 43, "ciphertext": "x" * 43}
        packet = {"type": "DMP_C_DATA", "id": "hop-1", "route_id": "contact-inbox", "envelope": envelope}
        self.assertIsNotNone(await self.transport.receive_data(packet, "peer"))
        packet["id"] = "hop-2"
        self.assertIsNone(await self.transport.receive_data(packet, "peer"))

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

    async def test_unknown_route_is_not_blindly_forwarded_and_status_is_minimal(self):
        status = await self.transport.route_status("missing-route")
        self.assertEqual(status, {"state": "ROUTE_UNKNOWN"})
        result = await self.transport.submit_envelope("missing-route", {"packet_id": "no-route", "ciphertext": "opaque"})
        self.assertEqual(result.state, "ROUTE_UNKNOWN")
        self.assertEqual(self.node.calls, [])

    async def test_route_status_reports_ready_without_next_hop_topology(self):
        await self.db.add_route_alias(self.db.node_crypto.get_blind_hash("ready-route"), "peer-private", 4)
        await self.db.add_route_alias(self.db.node_crypto.get_blind_hash("ready-route"), "peer-alternate", 6)
        status = await self.transport.route_status("ready-route")
        self.assertEqual(status["state"], "ROUTE_READY")
        self.assertEqual(status["best_metric"], 4)
        self.assertNotIn("next_hop_id", status)
        self.assertNotIn("candidate_count", status)

    async def test_candidate_ncrh_metadata_is_bounded_and_never_exposed_in_status(self):
        alias = self.db.node_crypto.get_blind_hash("bounded-route")
        for index in range(5):
            await self.db.add_route_alias(alias, "peer-a", 3, ncrh=f"{index:064x}")
        async with self.db.conn.execute("SELECT routing_blob FROM blind_routes WHERE route_in_hash=?", (alias,)) as cursor:
            stored = (await cursor.fetchone())["routing_blob"]
        candidate = json.loads(stored)["candidates"][0]
        self.assertLessEqual(len(candidate["alternate_ncrh"]), 3)
        status = await self.transport.route_status("bounded-route")
        self.assertNotIn("ncrh", status)
        self.assertNotIn("alternate_ncrh", status)

    async def test_candidate_expiry_is_independent_and_invalid_ncrh_is_not_retained(self):
        alias = self.db.node_crypto.get_blind_hash("fresh-route")
        now = __import__("time").time()
        await self.db.add_route_alias(alias, "expired-peer", 1, expires_at=now - 1, ncrh="a" * 64)
        await self.db.add_route_alias(alias, "fresh-peer", 5, expires_at=now + 60, ncrh="oversized-untrusted-label")
        route = await self.db.get_best_route_alias(alias)
        self.assertEqual(route["next_hop_id"], "fresh-peer")
        self.assertEqual(route["candidate_count"], 1)
        async with self.db.conn.execute("SELECT routing_blob FROM blind_routes WHERE route_in_hash=?", (alias,)) as cursor:
            candidate = json.loads((await cursor.fetchone())["routing_blob"])["candidates"][0]
        self.assertNotIn("oversized-untrusted-label", json.dumps(candidate))

    async def test_expired_local_candidate_does_not_capture_fresh_transit_route(self):
        alias = self.db.node_crypto.get_blind_hash("candidate-locality")
        now = __import__("time").time()
        await self.db.add_route_alias(alias, "LOCAL", 0, is_local=True, expires_at=now + 0.01)
        await self.db.add_route_alias(alias, "fresh-peer", 4, expires_at=now + 60)
        await __import__("asyncio").sleep(0.02)
        route = await self.db.get_best_route_alias(alias)
        self.assertEqual(route["next_hop_id"], "fresh-peer")
        self.assertFalse(route["is_local"])

    async def test_v2_probe_requires_separate_valid_metric_and_hop_limit(self):
        invalid = {"type": "ROUTE_PROBE_V2", "route_id": "route", "back_route_id": "back", "metric": 1}
        self.assertFalse(await self.transport.receive_probe(invalid, "peer"))
        with self.assertRaises(ValueError):
            await self.transport.start_probe("route", "back", ttl=16)

    async def test_locator_notification_binding_is_encrypted_and_removed_with_beacon(self):
        locator, beacon = "inbound-beacon-locator", "device-derived-beacon"
        locator_alias = await self.transport.register_inbound_locator(locator)
        await self.transport.register_notification_beacon(beacon)
        self.assertTrue(await self.transport.bind_locator_notification_beacon(locator, beacon))
        self.assertEqual(await self.db.notification_handle_for_locator_alias(locator_alias), beacon)
        async with self.db.conn.execute("SELECT user_blob FROM local_bindings WHERE binding_hash=?", (locator_alias,)) as cursor:
            stored = (await cursor.fetchone())["user_blob"]
        self.assertNotIn(locator, stored)
        self.assertNotIn(beacon, stored)
        self.assertTrue(await self.transport.unregister_notification_beacon(beacon))
        self.assertIsNone(await self.db.notification_handle_for_locator_alias(locator_alias))

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

    async def test_active_local_session_gets_opaque_delivery_signal_before_pull(self):
        locator = "online-pwa-locator"
        handle = await self.transport.register_inbound_locator(locator)
        await self.db.add_route_alias(handle, "LOCAL", 0, is_local=True)
        session = FakeDeliverySession()
        self.transport.attach_local_delivery_session(handle, session)

        result = await self.transport.submit_envelope(locator, {"packet_id": "online-delivery", "ciphertext": "sealed"})

        self.assertEqual(result.state, "DELIVERED_TO_DESTINATION_PWA_SESSION")
        self.assertEqual(session.messages, [{
            "type": "DELIVERY_AVAILABLE", "locator_handle": handle, "delivery_id": "online-delivery",
        }])
        self.assertEqual([packet["id"] for packet in await self.transport.pull(handle)], ["online-delivery"])

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
