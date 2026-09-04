import base64
import asyncio
from dataclasses import dataclass
import json
import unittest

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
        # Gateway auth needs only NodeID and a capability policy. The test
        # never requests a transport operation, so no routing/session state is
        # fabricated or persisted.
        gateway.runtime_state = lambda: type("State", (), {
            "node_crypto": type("NodeCrypto", (), {"node_id": self.node_key.verify_key.encode().hex()})(),
            "capabilities": None,
            "node": None,
        })()

    def tearDown(self):
        gateway.runtime_state = self.previous_runtime_state

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
            "node_crypto": type("NodeCrypto", (), {"node_id": self.node_key.verify_key.encode().hex()})(),
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
