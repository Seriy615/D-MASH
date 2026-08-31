import os
import unittest
from unittest.mock import patch

from backend.capabilities import NodeCapabilities, allowed_operations
from backend.transport import NodeTransportService
from backend.network import P2PNode


class NodeCapabilitiesTests(unittest.TestCase):
    def test_defaults_are_python_node_route_policy_only(self):
        capabilities = NodeCapabilities()
        self.assertEqual(capabilities.visibility, "public")
        self.assertTrue(capabilities.can_route)
        self.assertFalse(capabilities.can_accept_devices)
        self.assertFalse(capabilities.can_fallback_store)
        self.assertNotIn("FALLBACK", capabilities.advertised_operations())
        self.assertNotIn("SIGNAL", capabilities.advertised_operations())
        self.assertNotIn("TURN", capabilities.advertised_operations())
        self.assertNotIn("BLOB", capabilities.advertised_operations())

    def test_route_disabled_fails_closed_for_legacy_delivery_operations(self):
        capabilities = NodeCapabilities(can_route=False)
        self.assertEqual(capabilities.advertised_operations(), frozenset({"PING", "STATUS"}))
        self.assertFalse(capabilities.is_operation_allowed("PULL"))
        self.assertTrue(capabilities.is_operation_allowed("STATUS"))

    def test_environment_parses_explicit_boolean_policy(self):
        environment = {
            "DMASH_NODE_VISIBILITY": "private",
            "DMASH_CAN_ROUTE": "off",
            "DMASH_CAN_ACCEPT_DEVICES": "true",
            "DMASH_CAN_FALLBACK_STORE": "1",
            "DMASH_CAN_SIGNAL": "yes",
            "DMASH_CAN_BE_TURN": "0",
            "DMASH_CAN_RELAY_BLOB": "false",
        }
        with patch.dict(os.environ, environment, clear=False):
            capabilities = NodeCapabilities.from_env()
        self.assertEqual(capabilities.visibility, "private")
        self.assertFalse(capabilities.can_route)
        self.assertTrue(capabilities.can_accept_devices)
        self.assertTrue(capabilities.can_fallback_store)
        self.assertTrue(capabilities.can_signal)
        self.assertFalse(capabilities.can_be_turn)
        self.assertFalse(capabilities.can_relay_blob)

    def test_invalid_environment_value_is_rejected(self):
        with patch.dict(os.environ, {"DMASH_CAN_ROUTE": "sometimes"}, clear=False):
            with self.assertRaises(ValueError):
                NodeCapabilities.from_env()

    def test_gateway_uses_capability_policy_not_account_information(self):
        class State:
            capabilities = NodeCapabilities(can_route=False)

        self.assertEqual(allowed_operations(State()), frozenset({"PING", "STATUS"}))

    def test_missing_runtime_policy_fails_closed(self):
        class State:
            pass

        self.assertEqual(allowed_operations(State()), frozenset({"PING", "STATUS"}))

    def test_transport_rejects_submission_when_routing_disabled(self):
        service = NodeTransportService(system_db=object(), can_route=False)
        import asyncio

        with self.assertRaises(PermissionError):
            asyncio.run(service.start_probe("route", "back-route"))
        with self.assertRaises(PermissionError):
            asyncio.run(service.submit_envelope("route", {"ciphertext": "opaque"}))

    def test_constructor_defaults_fail_closed(self):
        self.assertFalse(P2PNode(object()).can_route)
        self.assertFalse(NodeTransportService(system_db=object()).can_route)

    def test_device_operations_require_explicit_device_acceptance(self):
        capabilities = NodeCapabilities(can_route=True, can_accept_devices=False)
        self.assertEqual(capabilities.advertised_operations(), frozenset({"PING", "STATUS"}))
        self.assertIn("REGISTER_INBOUND_LOCATOR", NodeCapabilities(can_route=True, can_accept_devices=True).advertised_operations())

    def test_transport_rejects_device_api_when_device_acceptance_disabled(self):
        import asyncio
        service = NodeTransportService(system_db=object(), can_route=True, can_accept_devices=False)
        with self.assertRaises(PermissionError):
            asyncio.run(service.register_inbound_locator("opaque-locator"))
        with self.assertRaises(PermissionError):
            asyncio.run(service.pull("opaque-handle"))
        with self.assertRaises(PermissionError):
            asyncio.run(service.ack("delivery"))

    def test_node_rejects_direct_enqueue_when_routing_disabled(self):
        class Database:
            pass

        node = P2PNode(Database(), can_route=False)
        import asyncio

        with self.assertRaises(PermissionError):
            asyncio.run(node.enqueue_transport_packet({"id": "packet"}))

    def test_disabled_node_drops_legacy_p2p_before_storage_or_routing(self):
        class Database:
            def __init__(self):
                self.marked = False

            async def mark_packet_seen(self, _packet_id):
                self.marked = True
                return True

        database = Database()
        node = P2PNode(database, can_route=False)
        import asyncio
        import json

        asyncio.run(node._process_envelope(json.dumps({
            "t": "REAL", "d": json.dumps({"type": "PROBE", "id": "packet"})
        }), "peer"))
        self.assertFalse(database.marked)

    def test_disabled_node_rejects_inbound_before_handshake_or_neighbor_write(self):
        class Database:
            node_crypto = None
            neighbor_written = False

            async def add_neighbor(self, *_args):
                self.neighbor_written = True

        class WebSocket:
            closed = None

            async def close(self, *, code, reason):
                self.closed = (code, reason)

        database = Database()
        websocket = WebSocket()
        node = P2PNode(database, can_route=False)
        import asyncio

        asyncio.run(node._handle_incoming(websocket))
        self.assertEqual(websocket.closed, (1008, "routing disabled"))
        self.assertFalse(database.neighbor_written)


if __name__ == "__main__":
    unittest.main()
