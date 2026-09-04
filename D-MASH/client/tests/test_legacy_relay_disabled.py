"""Regression coverage for retirement of raw HTTP and P2P relay packets."""

import asyncio
import contextlib
import io
import json
import unittest

from fastapi import HTTPException

import backend.api as api
from backend.network import (
    LEGACY_RELAY_UNAVAILABLE_DETAIL,
    LegacyRelayUnavailableError,
    P2PNode,
)


class PersistenceTrap:
    """Fails on every persistence interaction, including blind seen tracking."""

    def __getattr__(self, name):
        raise AssertionError(f"legacy path accessed persistence via {name}")


class LegacyRelayDisabledTests(unittest.TestCase):
    def test_legacy_api_send_cannot_persist_or_echo_submitted_fields(self):
        secret_text = "plaintext-not-for-storage"
        secret_target = "recipient-identity-not-for-response"
        previous_db = api.state.db
        try:
            api.state.db = PersistenceTrap()
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(api.send_message(api.SendData(
                    target_id=secret_target,
                    text=secret_text,
                    file_data="raw-packet-material",
                )))
        finally:
            api.state.db = previous_db

        error = raised.exception
        self.assertEqual(error.status_code, 410)
        self.assertEqual(error.detail, api.LEGACY_SEND_UNAVAILABLE_DETAIL)
        self.assertIn("unavailable", error.detail.lower())
        self.assertNotIn(secret_text, error.detail)
        self.assertNotIn(secret_target, error.detail)
        self.assertNotIn("raw-packet-material", error.detail)

    def test_legacy_p2p_packet_is_rejected_before_seen_or_relay_persistence(self):
        node = P2PNode(PersistenceTrap(), can_route=True)
        secret = "raw-packet-secret-that-must-not-echo"
        raw_packet = {
            "type": "DATA",
            "id": "legacy-id",
            "route_id": "legacy-route",
            "content": secret,
            "ttl": 1,
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            asyncio.run(node._process_envelope(json.dumps({"t": "REAL", "d": json.dumps(raw_packet)}), "peer-a"))

        log = output.getvalue()
        self.assertIn("Legacy raw P2P relay is unavailable", log)
        self.assertNotIn(secret, log)
        self.assertNotIn(raw_packet["route_id"], log)

    def test_direct_legacy_readers_and_writers_raise_field_free_migration_error(self):
        node = P2PNode(PersistenceTrap(), can_route=True)
        packet = {"id": "sensitive-id", "content": "sensitive-content"}
        for call in (
            lambda: node._handle_probe(packet, "sensitive-peer", True),
            lambda: node._handle_data(packet, "sensitive-peer"),
            lambda: node._deliver_to_active_user(packet, "sensitive-peer"),
            lambda: node._send_probe_response("sensitive-peer"),
        ):
            with self.assertRaises(LegacyRelayUnavailableError) as raised:
                asyncio.run(call())
            self.assertEqual(str(raised.exception), LEGACY_RELAY_UNAVAILABLE_DETAIL)
            self.assertNotIn("sensitive-id", str(raised.exception))
            self.assertNotIn("sensitive-content", str(raised.exception))
            self.assertNotIn("sensitive-peer", str(raised.exception))

    def test_dmp_c_packet_still_uses_capability_gated_handler(self):
        class DmpCPersistenceStub:
            async def mark_packet_seen(self, packet_id):
                self.packet_id = packet_id
                return True

        db = DmpCPersistenceStub()
        node = P2PNode(db, can_route=True)
        received = []

        async def receive(packet, peer):
            received.append((packet, peer))

        node._handle_dmp_c_data = receive
        packet = {"type": "DMP_C_DATA", "id": "dmp-c-id", "envelope": {"ciphertext": "opaque"}}
        asyncio.run(node._process_envelope(json.dumps({"t": "REAL", "d": json.dumps(packet)}), "peer-dmpc"))

        self.assertEqual(db.packet_id, "dmp-c-id")
        self.assertEqual(received, [(packet, "peer-dmpc")])


if __name__ == "__main__":
    unittest.main()
