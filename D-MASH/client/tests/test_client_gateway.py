import base64
import asyncio
from dataclasses import dataclass
import json
import os
import tempfile
import time
import unittest

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from starlette.websockets import WebSocketDisconnect

import backend.client_gateway as gateway
from backend.client_gateway import (
    auth_transcript,
    device_auth_transcript,
    verify_auth,
    verify_device_auth,
    router,
)
from backend.registration_registry import RegistrationRegistry


class ClientGatewayAuthTests(unittest.TestCase):
    class GatewaySocket:
        """Minimal ASGI WebSocket surface used by the real gateway coroutine."""
        def __init__(self, inbound):
            self.inbound = list(inbound)
            self.sent = []
            self.closed = None

        async def accept(self):
            return None

        async def send_json(self, payload):
            self.sent.append(payload)

        async def receive_text(self):
            if not self.inbound:
                raise RuntimeError("test socket has no more frames")
            frame = self.inbound.pop(0)
            if frame == "__DISCONNECT__":
                raise WebSocketDisconnect()
            return frame(self.sent) if callable(frame) else frame

        async def close(self, code=1000, reason=""):
            self.closed = (code, reason)

    def setUp(self):
        self.node_key = SigningKey.generate()
        self.previous_runtime_state = gateway.runtime_state
        self.previous_registry_factory = gateway.registration_registry_factory
        handle, self.registry_path = tempfile.mkstemp(prefix="dmash-gateway-registration-", suffix=".sqlite")
        os.close(handle)
        gateway.registration_registry_factory = lambda node_crypto: RegistrationRegistry(self.registry_path, node_crypto)
        # Gateway auth needs only NodeID and a capability policy. The test
        # never requests a transport operation, so no routing/session state is
        # fabricated or persisted.
        gateway.runtime_state = lambda: type("State", (), {
            "node_crypto": type("NodeCrypto", (), {
                "node_id": self.node_key.verify_key.encode().hex(),
                "secret_salt": b"g" * 32,
            })(),
            "capabilities": None,
            "node": None,
        })()

    def tearDown(self):
        gateway.runtime_state = self.previous_runtime_state
        gateway.registration_registry_factory = self.previous_registry_factory
        if os.path.exists(self.registry_path):
            os.unlink(self.registry_path)

    def _authenticated_frames(self, client_key, *requests):
        """Build a DEVICE_AUTH_V1 exchange followed by public DMP-C frames."""
        def valid_auth(sent):
            challenge = sent[0]
            client_nonce = "client-nonce-gateway-tests-01"
            transcript = device_auth_transcript(
                challenge["node_id"], challenge["session_id"], challenge["nonce"],
                client_nonce, challenge["expires_at"],
            )
            return json.dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(),
                "client_nonce": client_nonce,
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        return [valid_auth, *(json.dumps(request) for request in requests), "__DISCONNECT__"]

    def _install_routing_state(self, transport):
        """Install an in-memory, routing-capable Node facade for the gateway."""
        capabilities = type("Capabilities", (), {
            "advertised_operations": lambda self: frozenset({"STATUS", "START_PROBE", "ROUTE_STATUS"}),
        })()
        gateway.runtime_state = lambda: type("State", (), {
            "node_crypto": type("NodeCrypto", (), {
                "node_id": self.node_key.verify_key.encode().hex(),
                "secret_salt": b"g" * 32,
            })(),
            "capabilities": capabilities,
            "node": type("Node", (), {"active_connections": [], "transport": transport})(),
        })()

    def test_v2_websocket_authenticates_only_valid_device_transcript(self):
        client_key = SigningKey.generate()
        def valid_auth(sent):
            challenge = sent[0]
            client_nonce = "client-nonce-0123456789"
            transcript = device_auth_transcript(
                challenge["node_id"], challenge["session_id"], challenge["nonce"],
                client_nonce, challenge["expires_at"],
            )
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": client_nonce,
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        websocket = self.GatewaySocket([valid_auth, "__DISCONNECT__"])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.sent[0]["auth_mode"], "DEVICE_AUTH_V1")
        self.assertEqual(websocket.sent[0]["version"], 2)
        self.assertEqual(websocket.sent[0]["node_id"], self.node_key.verify_key.encode().hex())
        self.assertEqual(websocket.sent[1]["type"], "AUTH_OK")
        self.assertEqual(websocket.sent[1]["auth_mode"], "DEVICE_AUTH_V1")

    def test_v2_websocket_keeps_runtime_state_for_post_auth_status(self):
        client_key = SigningKey.generate()

        def valid_auth(sent):
            challenge = sent[0]
            client_nonce = "client-nonce-status-012345"
            transcript = device_auth_transcript(
                challenge["node_id"], challenge["session_id"], challenge["nonce"],
                client_nonce, challenge["expires_at"],
            )
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": client_nonce,
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })

        websocket = self.GatewaySocket([valid_auth, __import__("json").dumps({"type": "STATUS", "request_id": "status-1"}), "__DISCONNECT__"])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.sent[1]["type"], "AUTH_OK")
        self.assertEqual(websocket.sent[2], {
            "type": "STATUS", "request_id": "status-1",
            "node_id": self.node_key.verify_key.encode().hex(), "mesh_peers": 0,
        })

    def test_authenticated_route_status_reports_unknown_and_ready_minimal_topology(self):
        class Transport:
            async def route_status(self, locator):
                if locator == "unknown-route":
                    return {"state": "ROUTE_UNKNOWN"}
                return {
                    "state": "ROUTE_READY", "best_metric": 4,
                    "expires_at": 1_900_000_000,
                }

            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "ROUTE_STATUS", "request_id": "route-unknown", "route_locator": "unknown-route"},
            {"type": "ROUTE_STATUS", "request_id": "route-ready", "route_locator": "ready-route"},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "ROUTE_STATUS_RESULT", "request_id": "route-unknown",
            "state": "ROUTE_UNKNOWN",
        })
        self.assertEqual(websocket.sent[3], {
            "type": "ROUTE_STATUS_RESULT", "request_id": "route-ready",
            "state": "ROUTE_READY", "best_metric": 4, "expires_at": 1_900_000_000,
        })

    def test_registration_operations_are_advertised_only_for_routing_capable_state(self):
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "not-route-capable", "dnss": "00" * 16},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertNotIn("REGISTER_DNSS", websocket.sent[1]["capabilities"])
        self.assertNotIn("REGISTER_ENTRY_GRANT", websocket.sent[1]["capabilities"])
        self.assertEqual(websocket.sent[2], {
            "type": "ERROR", "request_id": "not-route-capable",
            "code": "UNSUPPORTED_OPERATION",
        })

    def test_authenticated_dnss_registration_accepts_128_bit_values_and_returns_blind_handle(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        dnss_hex = "0123456789abcdef" * 2
        dnss_b64 = base64.urlsafe_b64encode(bytes.fromhex(dnss_hex)).decode("ascii").rstrip("=")
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "dnss-hex", "dnss": dnss_hex},
            {"type": "REGISTER_DNSS", "request_id": "dnss-b64", "dnss": dnss_b64},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertIn("REGISTER_DNSS", websocket.sent[1]["capabilities"])
        for result in websocket.sent[2:]:
            self.assertEqual(result["type"], "REGISTER_DNSS_RESULT")
            self.assertRegex(result["dnss_handle"], r"^[0-9a-f]{64}$")
            self.assertNotIn(dnss_hex, json.dumps(result))
            self.assertNotIn(dnss_b64, json.dumps(result))

    def test_authenticated_dnss_registration_rejects_malformed_values(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "empty", "dnss": ""},
            {"type": "REGISTER_DNSS", "request_id": "short", "dnss": "00" * 15},
            {"type": "REGISTER_DNSS", "request_id": "bad-hex", "dnss": "gg" * 16},
            {"type": "REGISTER_DNSS", "request_id": "bad-b64", "dnss": "not-base64!"},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2:], [
            {"type": "ERROR", "request_id": "empty", "code": "INVALID_DNSS"},
            {"type": "ERROR", "request_id": "short", "code": "INVALID_DNSS"},
            {"type": "ERROR", "request_id": "bad-hex", "code": "INVALID_DNSS"},
            {"type": "ERROR", "request_id": "bad-b64", "code": "INVALID_DNSS"},
        ])

    def test_authenticated_entry_grant_accepts_node_bound_grant_and_rejects_wrong_node(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        route_key = SigningKey.generate()
        route_public_key = route_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
        valid_grant = gateway.EntryGrantV1.issue(self.node_key, route_public_key, int(time.time()) + 60)
        wrong_node = SigningKey.generate()
        wrong_grant = gateway.EntryGrantV1.issue(wrong_node, route_public_key, int(time.time()) + 60)
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_ENTRY_GRANT", "request_id": "grant-valid", "entry_grant": valid_grant.to_dict()},
            {"type": "REGISTER_ENTRY_GRANT", "request_id": "grant-wrong-node", "entry_grant": wrong_grant.to_dict()},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2], {
            "type": "REGISTER_ENTRY_GRANT_RESULT", "request_id": "grant-valid",
            "route_id": valid_grant.route_id, "expires_at": valid_grant.expires_at,
        })
        self.assertEqual(websocket.sent[3], {
            "type": "ERROR", "request_id": "grant-wrong-node", "code": "INVALID_ENTRY_GRANT",
        })

    def test_registration_persists_only_when_dnss_and_verified_grant_are_both_present(self):
        class Transport:
            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        route_key = SigningKey.generate()
        route_public_key = route_key.verify_key.encode(encoder=HexEncoder).decode("ascii")
        grant = gateway.EntryGrantV1.issue(self.node_key, route_public_key, int(time.time()) + 60)
        dnss = "ab" * 16
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "REGISTER_DNSS", "request_id": "dnss", "dnss": dnss},
            {"type": "REGISTER_ENTRY_GRANT", "request_id": "grant", "entry_grant": grant.to_dict()},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2]["type"], "REGISTER_DNSS_RESULT")
        self.assertEqual(websocket.sent[3]["type"], "REGISTER_ENTRY_GRANT_RESULT")
        registry = RegistrationRegistry(self.registry_path, type("Node", (), {
            "node_id": self.node_key.verify_key.encode().hex(), "secret_salt": b"g" * 32,
        })())
        try:
            record = registry.lookup(bytes.fromhex(dnss))
            self.assertIsNotNone(record)
            self.assertEqual(record.grant.to_dict(), grant.to_dict())
            with open(self.registry_path, "rb") as database:
                self.assertNotIn(bytes.fromhex(dnss), database.read())
        finally:
            registry.close()

    def test_authenticated_start_probe_propagates_metric_and_clamps_hop_limit(self):
        @dataclass
        class Submission:
            delivery_id: str
            state: str
            packet: dict

        class Transport:
            def __init__(self):
                self.calls = []

            async def start_probe(self, route_locator, back_route_locator, *, hops, ttl):
                self.calls.append((route_locator, back_route_locator, hops, ttl))
                return Submission("probe-id", "SUBMITTED_TO_ENTRY", {
                    "type": "ROUTE_PROBE_V2", "metric": hops, "hop_limit": ttl,
                })

            def detach_local_delivery_session(self, session):
                pass

        transport = Transport()
        self._install_routing_state(transport)
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "START_PROBE", "request_id": "probe-high", "route_locator": "out", "back_route_locator": "back", "metric": 7, "hop_limit": 99},
            {"type": "START_PROBE", "request_id": "probe-low", "route_locator": "out-2", "back_route_locator": "back-2", "metric": 8, "hop_limit": -3},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(transport.calls, [("out", "back", 7, 15), ("out-2", "back-2", 8, 1)])
        self.assertEqual(websocket.sent[2], {
            "type": "START_PROBE_RESULT", "request_id": "probe-high",
            "delivery_id": "probe-id", "state": "SUBMITTED_TO_ENTRY",
            "packet": {"type": "ROUTE_PROBE_V2", "metric": 7, "hop_limit": 15},
        })
        self.assertEqual(websocket.sent[3]["request_id"], "probe-low")
        self.assertEqual(websocket.sent[3]["packet"]["hop_limit"], 1)

    def test_authenticated_probe_and_route_status_reject_invalid_v2_values(self):
        class Transport:
            async def start_probe(self, *args, **kwargs):
                # The gateway coerces/clamps hop_limit while the transport owns
                # metric validation; both invalid V2 fields surface uniformly.
                raise ValueError("invalid probe metric or hop limit")

            async def route_status(self, *args):
                raise AssertionError("invalid route frame reached transport")

            def detach_local_delivery_session(self, session):
                pass

        self._install_routing_state(Transport())
        client_key = SigningKey.generate()
        websocket = self.GatewaySocket(self._authenticated_frames(
            client_key,
            {"type": "ROUTE_STATUS", "request_id": "bad-route", "route_locator": ""},
            {"type": "START_PROBE", "request_id": "bad-back-route", "route_locator": "route", "back_route_locator": None},
            {"type": "START_PROBE", "request_id": "bad-limit", "route_locator": "route", "back_route_locator": "back", "metric": 3, "hop_limit": "not-an-int"},
            {"type": "START_PROBE", "request_id": "bad-metric", "route_locator": "route", "back_route_locator": "back", "metric": "not-an-int", "hop_limit": 4},
        ))

        asyncio.run(gateway.dmp_client(websocket))

        self.assertEqual(websocket.sent[2:], [
            {"type": "ERROR", "request_id": "bad-route", "code": "INVALID_ROUTE_HANDLE"},
            {"type": "ERROR", "request_id": "bad-back-route", "code": "INVALID_ROUTE_HANDLE"},
            {"type": "ERROR", "request_id": "bad-limit", "code": "NODE_OPERATION_FAILED"},
            {"type": "ERROR", "request_id": "bad-metric", "code": "NODE_OPERATION_FAILED"},
        ])

    def test_v2_rejects_legacy_or_replayed_challenge_signature(self):
        client_key = SigningKey.generate()
        def replayed_auth(sent):
            challenge = sent[0]
            # Signing a captured transcript with a changed fresh client nonce
            # must be rejected by the session rather than falling back.
            captured_nonce = "client-nonce-captured-1"
            transcript = device_auth_transcript(challenge["node_id"], challenge["session_id"], challenge["nonce"], captured_nonce, challenge["expires_at"])
            return __import__("json").dumps({
                "type": "AUTH", "auth_mode": "DEVICE_AUTH_V1",
                "public_key": client_key.verify_key.encode().hex(), "client_nonce": "client-nonce-fresh-222",
                "signature": base64.b64encode(client_key.sign(transcript).signature).decode("ascii"),
            })
        websocket = self.GatewaySocket([replayed_auth])
        asyncio.run(gateway.dmp_client(websocket))
        self.assertEqual(websocket.closed, (1008, "authentication failed"))

    def test_legacy_compatibility_is_explicit_not_a_v2_fallback(self):
        paths = {route.path for route in router.routes}
        self.assertIn("/dmp-c/v1", paths)
        self.assertIn("/dmp-c/legacy-v1", paths)

    def test_legacy_transcript_helper_remains_verifiable_but_is_not_device_auth(self):
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode().hex()
        signature = base64.b64encode(signing_key.sign(auth_transcript("session-test", "nonce-test")).signature).decode("ascii")
        self.assertTrue(verify_auth(public_key, signature, "session-test", "nonce-test"))

    def test_device_auth_binds_challenge_node_and_client_nonce(self):
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode().hex()
        fields = dict(node_id="ab" * 32, session_id="session-test", server_nonce="server-nonce", client_nonce="client-nonce-012345", expires_at=1_900_000_000)
        signature = base64.b64encode(signing_key.sign(device_auth_transcript(**fields)).signature).decode("ascii")
        self.assertTrue(verify_device_auth(public_key, signature, **fields))
        # Capture/replay cannot authenticate a fresh challenge/session.
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "server_nonce": "fresh-nonce"}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "session_id": "fresh-session"}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "node_id": "cd" * 32}))
        self.assertFalse(verify_device_auth(public_key, signature, **{**fields, "expires_at": fields["expires_at"] + 1}))
        self.assertFalse(verify_device_auth("cd" * 32, signature, **fields))


if __name__ == "__main__":
    unittest.main()
